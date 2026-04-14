/*
 * The serialization and deserialization of polynomial and vector types.
 *
 * Declares functions for converting between in-memory polynomial
 * representations and packed byte strings, only for the moduli actually
 * used in Saber (i.e., only the useful conversions). These functions define
 * this implementation's byte-level wire format for public keys, secret keys,
 * and ciphertexts.
 *
 * See Sections 8.2.4 and 8.2.7 of the Round 3 Saber specification
 * for the data conversion algorithms (BS2POL, POL2BS, etc.) that
 * these functions implement.
 *
 * Depends on: params.h, types.h
 */

#ifndef PACK_UNPACK_H
#define PACK_UNPACK_H

#include "params.h"
#include "types.h"

#endif