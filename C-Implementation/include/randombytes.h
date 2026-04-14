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

#endif