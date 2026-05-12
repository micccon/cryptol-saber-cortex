// Implementation of declarations in 'kem.h'
#include "kem.h"

#include <string.h>

#include "helpers.h"
#include "randombytes.h"

static void serialize_pk(uint8_t out[SABER_INDCPA_PUBLICKEYBYTES], const pk_t *pk) {
    memcpy(out, pk->pk, SABER_INDCPA_PUBLICKEYBYTES - SABER_SEEDBYTES);
    memcpy(out + SABER_INDCPA_PUBLICKEYBYTES - SABER_SEEDBYTES,
           pk->seed_a,
           SABER_SEEDBYTES);
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

    // Store in buf m | hash_pk
    uint8_t buf[SABER_HASHBYTES + SABER_KEYBYTES];
    memcpy(buf, m, SABER_KEYBYTES);
    memcpy(buf + SABER_KEYBYTES, hash_pk, SABER_HASHBYTES);

    // Make rk = H(m | hash_pk)
    uint8_t rk[SABER_KEYBYTES + SABER_HASHBYTES];
    sha3_512(rk, buf, SABER_HASHBYTES + SABER_KEYBYTES);

    // Split rk in half as pre-key | coins
    uint8_t k[SABER_KEYBYTES];
    uint8_t r[SABER_HASHBYTES];
    memcpy(k, rk, SABER_KEYBYTES);
    memcpy(r, rk + SABER_KEYBYTES, SABER_HASHBYTES);

    // Ciphertext encryption
    PKE_Enc(m, r, pk, ct);

    // Overwrite the coin half with H(c)
    sha3_256(rk + SABER_KEYBYTES, ct->bytes, SABER_BYTES_CCA_DEC);

    // Input session key
    sha3_256(key, rk, SABER_HASHBYTES * 2);
}

void KEM_Decaps(ct_t *ct, kem_sk_t *sk, uint8_t key[SABER_KEYBYTES]) {

    // Decrypt ciphertext to recover m'
    uint8_t m[SABER_KEYBYTES];
    PKE_Dec(ct, &sk->indcpa_sk, m);

    // Recompute rk = G(m' | H(pk))
    uint8_t buf[SABER_HASHBYTES + SABER_KEYBYTES];
    memcpy(buf, m, SABER_KEYBYTES);
    memcpy(buf + SABER_KEYBYTES, sk->hash_pk, SABER_HASHBYTES);

    uint8_t rk[SABER_HASHBYTES + SABER_KEYBYTES];
    sha3_512(rk, buf, SABER_HASHBYTES + SABER_KEYBYTES);

    // Split rk in half as pre-key | coins
    uint8_t k[SABER_KEYBYTES];
    uint8_t r[SABER_HASHBYTES];
    memcpy(k, rk, SABER_KEYBYTES);
    memcpy(r, rk + SABER_KEYBYTES, SABER_HASHBYTES);

    // Re-encrypt m' and compare against input ciphertext
    ct_t ct_cmp;
    PKE_Enc(m, r, &sk->pk, &ct_cmp);

    uint8_t fail = (uint8_t)verify(ct->bytes, ct_cmp.bytes, SABER_BYTES_CCA_DEC);
    sha3_256(rk + SABER_KEYBYTES, ct->bytes, SABER_BYTES_CCA_DEC);
    cmov(rk, sk->z, SABER_KEYBYTES, fail);

    // Output session key
    sha3_256(key, rk, SABER_HASHBYTES * 2);
}
