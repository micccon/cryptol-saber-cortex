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
#include <stdint.h>

typedef struct {
    uint8_t seed_a[SABER_SEEDBYTES];
    uint8_t pk[SABER_PUBLICKEYBYTES - SABER_SEEDBYTES];
} pk_t;

/**
 * Generates a random public/secret keypair (Algorithm 17)
 *
 * @param pk empty pk struct (byte string array of SABER_INDCPA_PUBKEYBYTES)
 * @param sk empty byte string array of SABER_INDCPA_SECRETKEYBYTES
 */
void PKE_KeyGen(pk_t *pk, uint8_t *sk);

/**
 * Encrypt a message m with a public key (Algorithm 18)
 *
 * @param m message to encrypt - 256 bit string
 * @param seed_s randome byte string of SABER_SEEDBYTES
 * @param pk public key byte string to use to encrypt
 *
 * @return ciphertext byte string
 */
uint8_t *PKE_Enc(uint8_t *m, uint8_t *seed_s, pk_t *pk);

/**
 * Decrypt a ciphertext ct with a secret key sk
 *
 * @param ct ciphertext to decrypt - byte string
 * @param sk secret key to use to encrypt
 *
 * @return 256 bit string message
 */
uint8_t *PKE_DEC(uint8_t *ct, uint8_t *sk);

#endif
