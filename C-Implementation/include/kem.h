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
 * Algorithm 20 stores the secret key byte string as:
 *   SecretKeycpa || PublicKeycpa || H(pk) || z
 */
typedef struct {
    pke_sk_t indcpa_sk;
    pk_t pk;
    uint8_t hash_pk[SABER_HASHBYTES];
    uint8_t z[SABER_KEYBYTES];
} kem_sk_t;

/*
 * Generates a KEM public/secret key pair (Algorithm 20).
 */
void KEM_KeyGen(pk_t *pk, kem_sk_t *sk);

/*
 * Deterministic variant of KEM_KeyGen used for tests/KATs.
 *
 * @param pk empty pk struct storing the IND-CPA public key as b || seed_A
 * @param sk empty kem_sk_t struct to hold the generated secret key
 * @param seed_a random byte string of SABER_SEEDBYTES to use for public
 *              matrix generation
 * @param seed_s random byte string of SABER_NOISE_SEEDBYTES to use
 *             for secret vector generation
 * @param z random byte string of SABER_KEYBYTES to use for the 'z' value in
 *         the secret key
 */
void KEM_KeyGen_Deterministic(pk_t *pk,
                              kem_sk_t *sk,
                              uint8_t seed_a[SABER_SEEDBYTES],
                              uint8_t seed_s[SABER_NOISE_SEEDBYTES],
                              uint8_t z[SABER_KEYBYTES]);

/*
 * Encapsulates a shared secret under the given public key (Algorithm 21)
 *
 * @param pk public key struct to encapsulate under
 * @param key output buffer for the shared secret (byte string of SABER_KEYBYTES
 *       bytes)
 * @param ct output ciphertext struct to hold the encapsulated ciphertext
 */
void KEM_Encaps(pk_t *pk,
                uint8_t key[SABER_KEYBYTES],
                ct_t *ct);

/*
 * Decapsulates a ciphertext to recover the shared secret (Algorithm 22)
 *
 * @param ct input ciphertext struct to decapsulate
 * @param sk secret key struct to use for decapsulation
 * @param key output buffer for the shared secret (byte string of SABER_KEYBYTES
 *      bytes)
 */
void KEM_Decaps(ct_t *ct,
                kem_sk_t *sk,
                uint8_t key[SABER_KEYBYTES]);

#endif
