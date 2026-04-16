/*
 * The Saber IND-CPA public-key encryption scheme.
 *
 * Declares the three PKE functions corresponding to Section 8.4
 * of the Round 3 Saber specification:
 *   - PKE_KeyGen: generates a public/secret key pair (Algorithm 17)
 *   - PKE_Enc:    encrypts a 256-bit message (Algorithm 18)
 *   - PKE_Dec:    decrypts a ciphertext (Algorithm 19)
 *
 * This scheme is not directly used by callers — it serves as the
 * underlying primitive for the IND-CCA KEM declared in kem.h.
 *
 * Depends on: params.h, types.h, arithmetic.h, pack_unpack.h,
 * third_party/fips202.h
 */

#ifndef INDCPA_H
#define INDCPA_H

#include "params.h"
#include "types.h"
#include "arithmetic.h"
#include "helpers.h"
#include "pack_unpack.h"
#include "randombytes.h"
#include <stdint.h>

#define H1 (1U << (SABER_EQ - SABER_EP - 1))
#define H2 ((1U << (SABER_EP - 2)) - (1U << (SABER_EP - SABER_ET - 1)) + H1)
#define H3 (1U << (SABER_EP - SABER_ET - 1))

/*
 * IND-CPA public key stored as seedA || b'.
 */
typedef struct {
    uint8_t seed_a[SABER_SEEDBYTES];
    uint8_t pk[SABER_PUBLICKEYBYTES - SABER_SEEDBYTES];
} pk_t;

/*
 * IND-CPA secret key stored as the packed secret vector s.
 */
typedef struct {
    uint8_t sk[SABER_INDCPA_SECRETKEYBYTES];
} pke_sk_t;

/*
 * IND-CPA / KEM ciphertext stored in its packed byte-string form.
 */
typedef struct {
    uint8_t bytes[SABER_BYTES_CCA_DEC];
} ct_t;

/**
 * Generates a random public/secret keypair (Algorithm 17)
 *
 * @param pk empty pk struct (byte string array of SABER_INDCPA_PUBKEYBYTES)
 * @param sk empty byte string array of SABER_INDCPA_SECRETKEYBYTES
 */
void PKE_KeyGen(pk_t *pk, pke_sk_t *sk);

/**
 * Deterministic variant of PKE_KeyGen used for tests/KATs.
 *
 * @param pk output public key
 * @param sk output secret key
 * @param seed_a seed used to derive the public matrix
 * @param seed_s seed used to derive the secret vector
 */
void PKE_KeyGen_Deterministic(pk_t *pk,
                              pke_sk_t *sk,
                              uint8_t seed_a[SABER_SEEDBYTES],
                              uint8_t seed_s[SABER_NOISE_SEEDBYTES]);

/**
 * Encrypt a message m with a public key (Algorithm 18)
 *
 * @param m message to encrypt - 256 bit string
 * @param seed_s random byte string of SABER_NOISE_SEEDBYTES
 * @param pk public key byte string to use to encrypt
 * @param ct empty ct struct to hold the ciphertext
 */
void PKE_Enc(uint8_t m[SABER_KEYBYTES],
                uint8_t seed_s[SABER_NOISE_SEEDBYTES],
                pk_t *pk,
                ct_t *ct);

/**
 * Decrypt a ciphertext ct with a secret key sk
 *
 * @param ct ciphertext to decrypt - byte string
 * @param sk secret key to use to encrypt
 * @param m empty byte string array of SABER_KEYBYTES to hold the decrypted message
 */
void PKE_Dec(ct_t *ct, pke_sk_t *sk, uint8_t m[SABER_KEYBYTES]);

#endif
