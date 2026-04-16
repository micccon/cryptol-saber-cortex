// Implementation of declarations in 'kem.h'
#include "kem.h"

#include <string.h>

#include "helpers.h"
#include "randombytes.h"

static void serialize_pk(uint8_t out[SABER_INDCPA_PUBLICKEYBYTES], const pk_t *pk) {
    memcpy(out, pk->seed_a, SABER_SEEDBYTES);
    memcpy(out + SABER_SEEDBYTES,
           pk->pk,
           SABER_INDCPA_PUBLICKEYBYTES - SABER_SEEDBYTES);
}

void KEM_KeyGen_Deterministic(pk_t *pk,
                              kem_sk_t *sk,
                              uint8_t seed_a[SABER_SEEDBYTES],
                              uint8_t seed_s[SABER_NOISE_SEEDBYTES],
                              uint8_t z[SABER_KEYBYTES]) {
    uint8_t pk_bytes[SABER_INDCPA_PUBLICKEYBYTES];

    PKE_KeyGen_Deterministic(pk, &sk->indcpa_sk, seed_a, seed_s);

    sk->pk = *pk;

    serialize_pk(pk_bytes, pk);
    sha3_256(sk->hash_pk, pk_bytes, SABER_INDCPA_PUBLICKEYBYTES);
    memcpy(sk->z, z, SABER_KEYBYTES);
}

void KEM_KeyGen(pk_t *pk, kem_sk_t *sk) {
    uint8_t seed_a[SABER_SEEDBYTES];
    uint8_t seed_s[SABER_NOISE_SEEDBYTES];
    uint8_t z[SABER_KEYBYTES];

    randombytes(seed_a, SABER_SEEDBYTES);
    shake128(seed_a, SABER_SEEDBYTES, seed_a, SABER_SEEDBYTES);
    randombytes(seed_s, SABER_NOISE_SEEDBYTES);
    randombytes(z, SABER_KEYBYTES);

    KEM_KeyGen_Deterministic(pk, sk, seed_a, seed_s, z);
}

void KEM_Encaps(pk_t *pk, uint8_t key[SABER_KEYBYTES], ct_t *ct) {
    
    // Setup random m
    uint8_t m[SABER_KEYBYTES];
    randombytes(m, SABER_KEYBYTES);
    sha3_256(m, m, SABER_KEYBYTES);

    // Generate hash of pk
    uint8_t hash_pk[SABER_HASHBYTES];
    uint8_t pk_bytes[SABER_INDCPA_PUBLICKEYBYTES];
    serialize_pk(pk_bytes, pk);
    sha3_256(hash_pk, pk_bytes, SABER_INDCPA_PUBLICKEYBYTES);

    // Store in buf hash_pk | m
    uint8_t buf[SABER_HASHBYTES + SABER_KEYBYTES];
    memcpy(buf, hash_pk, SABER_HASHBYTES);
    memcpy(buf + SABER_HASHBYTES, m, SABER_KEYBYTES);

    // Make rk = H(hash_pk | m)
    uint8_t rk[SABER_KEYBYTES + SABER_HASHBYTES];
    sha3_512(rk, buf, SABER_HASHBYTES + SABER_KEYBYTES);

    // Split rk in half
    uint8_t r[SABER_KEYBYTES];
    uint8_t k[SABER_HASHBYTES];
    memcpy(r, rk, SABER_KEYBYTES);
    memcpy(k, rk + SABER_KEYBYTES, SABER_HASHBYTES);

    // Ciphertext encryption
    PKE_Enc(m, r, pk, ct);

    // Make r'
    uint8_t r1[SABER_HASHBYTES];
    sha3_256(r1, ct->bytes, SABER_BYTES_CCA_DEC);

    // Create rk' = H(r' || k)
    uint8_t r1k[SABER_HASHBYTES * 2];
    memcpy(r1k, r1, SABER_HASHBYTES);
    memcpy(r1k + SABER_HASHBYTES, k, SABER_HASHBYTES);

    // Input session key
    sha3_256(key, r1k, SABER_HASHBYTES * 2);
}

void KEM_Decaps(ct_t *ct, kem_sk_t *sk, uint8_t key[SABER_KEYBYTES]) {

    // Decrypt ciphertext to recover m'
    uint8_t m[SABER_KEYBYTES];
    PKE_Dec(ct, &sk->indcpa_sk, m);

    // Recompute rk = G(H(pk) | m')
    uint8_t buf[SABER_HASHBYTES + SABER_KEYBYTES];
    memcpy(buf, sk->hash_pk, SABER_HASHBYTES);
    memcpy(buf + SABER_HASHBYTES, m, SABER_KEYBYTES);

    uint8_t rk[SABER_HASHBYTES + SABER_KEYBYTES];
    sha3_512(rk, buf, SABER_HASHBYTES + SABER_KEYBYTES);

    // Split rk in half
    uint8_t r[SABER_KEYBYTES];
    uint8_t k[SABER_HASHBYTES];
    memcpy(r, rk, SABER_KEYBYTES);
    memcpy(k, rk + SABER_KEYBYTES, SABER_HASHBYTES);

    // Re-encrypt m' and compare against input ciphertext
    ct_t ct_cmp;
    PKE_Enc(m, r, &sk->pk, &ct_cmp);

    // Hash input ciphertext
    uint8_t hash_ct[SABER_HASHBYTES];
    sha3_256(hash_ct, ct->bytes, SABER_BYTES_CCA_DEC);

    // Create rk' = H(c) || k, then conditionally replace k with z on failure
    uint8_t r1k[SABER_HASHBYTES * 2];
    uint8_t fail = (uint8_t)verify(ct->bytes, ct_cmp.bytes, SABER_BYTES_CCA_DEC);
    memcpy(r1k, hash_ct, SABER_HASHBYTES);
    memcpy(r1k + SABER_HASHBYTES, k, SABER_HASHBYTES);
    cmov(r1k + SABER_HASHBYTES, sk->z, SABER_KEYBYTES, fail);

    // Output session key
    sha3_256(key, r1k, SABER_HASHBYTES * 2);
}
