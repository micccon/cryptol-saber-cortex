#!/usr/bin/env python3
"""
Expand NIST PQC KAT seeds using AES-256 CTR DRBG (from rng.c)
and generate a Cryptol test file with concrete values.
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# AES-256 CTR DRBG implementation mimicking that of rng.c in the SABER Round 3 reference implementation. 
# This is a simplified version that only supports the necessary operations for seed expansion.
class AES256_CTR_DRBG:
    def __init__(self, entropy_input: bytes, personalization_string: bytes = None):
        seed_material = bytearray(entropy_input)
        if personalization_string:
            for i in range(48):
                seed_material[i] ^= personalization_string[i]
        
        self.key = bytearray(32)  # Initial key is all zeros
        self.V   = bytearray(16)  # Initial V is all zeros
        self._update(bytes(seed_material))
        self.reseed_counter = 1

    def _aes256_ecb(self, key: bytes, ctr: bytes) -> bytes:
        cipher = Cipher(
            algorithms.AES(key),
            modes.ECB(),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        return encryptor.update(ctr) + encryptor.finalize()
    
    def _increment_V(self):
        for j in range(15, -1, -1):
            if self.V[j] == 0xFF:
                self.V[j] = 0x00
            else:
                self.V[j] += 1
                break

    def _update(self, provided_data: bytes = None):
        temp = bytearray()
        for _ in range(3):
            self._increment_V()
            temp += self._aes256_ecb(bytes(self.key), bytes(self.V))

        if provided_data is not None:
            for i in range(48):
                temp[i] ^= provided_data[i]
        
        self.key = bytearray(temp[:32])
        self.V   = bytearray(temp[32:48])

    def randombytes(self, xlen: int) -> bytes:
        output = bytearray()
        remaining = xlen

        while remaining > 0:
            self._increment_V()
            block = self._aes256_ecb(bytes(self.key), bytes(self.V))
            if remaining >= 16:
                output += block
                remaining -= 16
            else:
                output += block[:remaining]
                remaining = 0
        
        self._update(None)
        self.reseed_counter += 1
        return bytes(output)
    

def parse_kat_file(filename:str):
    """
    Parse a NIST KAT .req or .rsp file into a list of dicts. 
    Each dict corresponds to a test case and contains the relevant fields.
    """
    vectors = []
    current = {}

    with open(filename, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '=' in line:
                key, val = line.split('=', 1)
                key = key.strip()
                val = val.strip()
                if key == 'count':
                    if current:
                        vectors.append(current)
                    current = {'count': int(val)}
                else:
                    current[key] = bytes.fromhex(val)
    
    if current:
        vectors.append(current)

    return vectors

def bytes_to_cryptol(b: bytes) -> str:
    """Convert bytes to Cryptol byte array literal."""
    hex_bytes = ', '.join(f'0x{byte:02x}' for byte in b)
    return f'[{hex_bytes}]'

def expand_kat_vector(seed: bytes):
    """
    Expand a 48-byte KAT seed using the NIST AES-256 CTR DRBG
    to produce the actual random bytes used in KEM operations.
    
    The KAT generation calls randombytes three times:
    1. 32 bytes for seedA (entropy for matrix generation)
    2. 32 bytes for seedS (entropy for secret key)  
    3. 32 bytes for z (rejection value)
    Then for encapsulation:
    4. 32 bytes for m (message randomness)
    """
    drbg = AES256_CTR_DRBG(seed)

    seedA = drbg.randombytes(32)
    seedS = drbg.randombytes(32)
    z     = drbg.randombytes(32)
    m     = drbg.randombytes(32)

    return seedA, seedS, z, m

def generate_cryptol_tests(kat_file: str, output_file: str, num_vectors: int = 5):
    """Generate a Cryptol test file from KAT vectors."""
    
    vectors = parse_kat_file(kat_file)
    
    lines = []
    lines.append('module SaberKATTests where')
    lines.append('')
    lines.append('import SaberKEM')
    lines.append('import SaberPKE')
    lines.append('import SaberConstants')
    lines.append('import SaberHelpers')
    lines.append('import SaberTypes')
    lines.append('import Primitive::Keyless::Hash::SHA3::Instantiations::SHA3_256 as SHA3_256')
    lines.append('import Primitive::Keyless::Hash::SHA3::Instantiations::SHA3_512 as SHA3_512')
    lines.append('import Primitive::Keyless::Hash::SHA3::Instantiations::SHAKE128 as SHAKE128')
    lines.append('')
    lines.append('/**')
    lines.append(' * KAT test vectors generated from PQCkemKAT_2304.req')
    lines.append(' * using the NIST AES-256 CTR DRBG (rng.c)')
    lines.append(' */')
    lines.append('')
    
    for vec in vectors[:num_vectors]:
        count = vec['count']
        seed  = vec['seed']
        
        # Expand seed through DRBG
        seedA, seedS, z, m = expand_kat_vector(seed)
        
        # Expected values from KAT file
        expected_pk = vec.get('pk', b'')
        expected_sk = vec.get('sk', b'')
        expected_ct = vec.get('ct', b'')
        expected_ss = vec.get('ss', b'')
        
        lines.append(f'// KAT vector {count}')
        lines.append(f'// Seed: {seed.hex()}')
        lines.append('')
        
        lines.append(f'kat{count}_seedA : ByteString seedBytes')
        lines.append(f'kat{count}_seedA = {bytes_to_cryptol(seedA)}')
        lines.append('')
        
        lines.append(f'kat{count}_seedS : ByteString noiseSeedBytes')
        lines.append(f'kat{count}_seedS = {bytes_to_cryptol(seedS)}')
        lines.append('')
        
        lines.append(f'kat{count}_z : ByteString keyBytes')
        lines.append(f'kat{count}_z = {bytes_to_cryptol(z)}')
        lines.append('')
        
        lines.append(f'kat{count}_m : ByteString (N / 8)')
        lines.append(f'kat{count}_m = {bytes_to_cryptol(m)}')
        lines.append('')
        
        if expected_pk:
            lines.append(f'kat{count}_expected_pk : ByteString publicKeyBytes')
            lines.append(f'kat{count}_expected_pk = {bytes_to_cryptol(expected_pk)}')
            lines.append('')
        
        if expected_sk:
            lines.append(f'kat{count}_expected_sk : ByteString secretKeyBytes')
            lines.append(f'kat{count}_expected_sk = {bytes_to_cryptol(expected_sk)}')
            lines.append('')
        
        if expected_ct:
            lines.append(f'kat{count}_expected_ct : ByteString bytesCCADec')
            lines.append(f'kat{count}_expected_ct = {bytes_to_cryptol(expected_ct)}')
            lines.append('')
        
        if expected_ss:
            lines.append(f'kat{count}_expected_ss : ByteString keyBytes')
            lines.append(f'kat{count}_expected_ss = {bytes_to_cryptol(expected_ss)}')
            lines.append('')
        
        # Key generation check
        lines.append(f'(kat{count}_pk, kat{count}_sk) = KEM_KeyGenDet kat{count}_seedA kat{count}_seedS kat{count}_z')
        lines.append('')
        
        # Encapsulation check  
        lines.append(f'(kat{count}_ct, kat{count}_ss_enc) = KEM_EncapsDet kat{count}_m kat{count}_pk')
        lines.append('')
        
        # Decapsulation
        lines.append(f'kat{count}_ss_dec : ByteString keyBytes')
        lines.append(f'kat{count}_ss_dec = KEM_Decaps kat{count}_ct kat{count}_sk')
        lines.append('')
        
        # Properties
        if expected_pk:
            lines.append(f'property check_kat{count}_pk = kat{count}_pk == kat{count}_expected_pk')
        if expected_sk:
            lines.append(f'property check_kat{count}_sk = kat{count}_sk == kat{count}_expected_sk')
        if expected_ct:
            lines.append(f'property check_kat{count}_ct = kat{count}_ct == kat{count}_expected_ct')
        if expected_ss:
            lines.append(f'property check_kat{count}_ss = kat{count}_ss_enc == kat{count}_expected_ss')
        lines.append(f'property check_kat{count}_roundtrip = kat{count}_ss_enc == kat{count}_ss_dec')
        lines.append('')
    
    with open(output_file, 'w') as f:
        f.write('\n'.join(lines))
    
    print(f'Generated {min(num_vectors, len(vectors))} KAT vectors in {output_file}')


if __name__ == '__main__':
    generate_cryptol_tests(
        kat_file='KATs/PQCkemKAT_2304.rsp',
        output_file='cryptol/SaberKATTests.cry',
        num_vectors=5
    )

    seed = bytes.fromhex("061550234d158c5ec95595fe04ef7a25767f2e24cc2bc479d09d86dc9abcfde7056a8c266f9ef97ed08541dbd2e1ffa1")
    drbg = AES256_CTR_DRBG(seed)
    seedA = drbg.randombytes(32)

    # Simulate what the reference does: SHAKE128(seedA)
    from cryptography.hazmat.primitives.hashes import Hash, SHAKE128
    digest = Hash(SHAKE128(32))
    digest.update(seedA)
    shaken = digest.finalize()
    print(f"raw seedA:        {seedA.hex()}")
    print(f"SHAKE128(seedA):  {shaken.hex()}")
    print(f"expected pk[:32]: 29157c69a067dd1c151115a9bbeb2d6e627f4e747716efa1569c7b7858cb2e71")