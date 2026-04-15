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
#include "types.h"
#include "../third_party/fips202.h"

/*
 * Secret key wrapper for the KEM.
 *
 * Algorithm 20 stores the secret key as:
 *   z || H(pk) || PublicKeycpa || SecretKeycpa
 */
typedef struct {
    uint8_t z[SABER_KEYBYTES];
    uint8_t hash_pk[SABER_HASHBYTES];
    pk_t pk;
    uint8_t indcpa_sk[SABER_INDCPA_SECRETKEYBYTES];
} kem_sk_t;

/*
 * Ciphertext wrapper for the KEM.
 */
typedef struct {
    uint8_t bytes[SABER_BYTES_CCA_DEC];
} ct_t;

/*
 * Generates a KEM public/secret key pair (Algorithm 20).
 */
void KEM_KeyGen(pk_t *pk, kem_sk_t *sk);

/*
 * Encapsulates a shared secret under the given public key (Algorithm 21).
 */
void KEM_Encaps(pk_t *pk,
                uint8_t key[SABER_KEYBYTES],
                ct_t *ct);

/*
 * Decapsulates a ciphertext to recover the shared secret (Algorithm 22).
 */
void KEM_Decaps(ct_t *ct,
                kem_sk_t *sk,
                uint8_t key[SABER_KEYBYTES]);

#endif
