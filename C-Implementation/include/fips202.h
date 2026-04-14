/**
 * Interfaces for the hash and XOF functions used throughout Saber.
 *
 * Declares the following functions, as standardized in FIPS 202:
 *   - SHAKE-128: used as an XOF in GenMatrix and GenSecret
 *   - SHA3-256:  used in KEM key generation, encapsulation, and decapsulation
 *   - SHA3-512:  used in KEM encapsulation and decapsulation
 *
 * See Sections 8.3.1 thru 8.3.3 of the Round 3 Saber specification
 * for the specific contexts in which each function is used.
 *
 * Depends on: nothing (standalone primitive)
 */

#ifndef FIPS202_H
#define FIPS202_H

#endif