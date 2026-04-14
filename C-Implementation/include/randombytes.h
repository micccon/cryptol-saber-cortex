/*
 * Interface for the random byte generation required by Saber key generation and
 * encapsulation.
 *
 * Declares randombytes(), which fills a buffer with cryptographically
 * secure random bytes. The underlying implementation uses an AES-256
 * counter-mode DRBG (as specified by NIST) for PQC KAT generation,
 * but tbh any cryptographically secure source may be substituted in
 * practice.
 *
 * Depends on: params.h (for key and seed sizes)
 */

#ifndef RANDOMBYTES_H
#define RANDOMBYTES_H

#include <stdint.h>

void randombytes_init(uint8_t entropy_input[48],
                      uint8_t personalization_string[48],
                      int security_strength);

int randombytes(uint8_t *x, unsigned long long xlen);

#endif
