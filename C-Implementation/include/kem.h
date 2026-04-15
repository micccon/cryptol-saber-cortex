/*
 * The Saber IND-CCA2 key encapsulation mechanism (KEM).
 *
 * Declares the three KEM functions corresponding to Section 8.5
 * of the Round 3 Saber specification:
 *   - KEM_KeyGen:  generates a public/secret key pair (Algorithm 20)
 *   - KEM_Encaps:  encapsulates a session key (Algorithm 21)
 *   - KEM_Decaps:  decapsulates a ciphertext to recover the session key
 * (Algorithm 22)
 *
 * Depends on: params.h, types.h, indcpa.h, third_party/fips202.h
 */

#ifndef KEM_H
#define KEM_H

#include <stdint.h>

#include "params.h"
#include "indcpa.h"

/*
 * Public key wrapper for the KEM.
 *
 * The IND-CCA public key has the same serialized layout as the IND-CPA
 * public key, so we keep the same shape here.
 */
typedef struct {
    uint8_t seed_a[SABER_SEEDBYTES];
    uint8_t pk[SABER_PUBLICKEYBYTES - SABER_SEEDBYTES];
} kem_pk_t;

/*
 * Secret key wrapper for the KEM.
 *
 * The secret key stores the IND-CPA secret key, the public key, H(pk),
 * and the fallback secret value z.
 */
typedef struct {
    uint8_t indcpa_sk[SABER_INDCPA_SECRETKEYBYTES];
    kem_pk_t pk;
    uint8_t hash_pk[SABER_HASHBYTES];
    uint8_t z[SABER_KEYBYTES];
} kem_sk_t;

/*
 * Ciphertext wrapper for the KEM.
 */
typedef struct {
    uint8_t bytes[SABER_BYTES_CCA_DEC];
} kem_ct_t;

/*
 * Generates a KEM public/secret key pair (Algorithm 20).
 */
void KEM_KeyGen(kem_pk_t *pk, kem_sk_t *sk);

/*
 * Encapsulates a shared secret under the given public key (Algorithm 21).
 */
void KEM_Encaps(const kem_pk_t *pk,
                kem_ct_t *ct,
                uint8_t key[SABER_KEYBYTES]);

/*
 * Decapsulates a ciphertext to recover the shared secret (Algorithm 22).
 */
void KEM_Decaps(const kem_ct_t *ct,
                const kem_sk_t *sk,
                uint8_t key[SABER_KEYBYTES]);

#endif
