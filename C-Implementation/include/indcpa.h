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

#endif