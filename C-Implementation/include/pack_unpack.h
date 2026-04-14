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

#include <stdint.h>

#include "params.h"
#include "types.h"

/*
 * Conversions for going from Zt Polynomials to ByteStrings, and vice versa.
 *
 * Used in PKE.Enc and PKE.Dec, see Sections 8.4.2 & 8.4.3 of the Round 3 Saber
 * specification
 */
void POLT2BS(const Poly_Zt input_poly,
             uint8_t output_bytes[SABER_SCALEBYTES_KEM]);
void BS2POLT(Poly_Zt output_poly,
             const uint8_t input_bytes[SABER_SCALEBYTES_KEM]);

/*
 * Conversions for going from vectors of Zq Polynomials to ByteStrings, and vice
 * versa.
 *
 * Used in PKE.KeyGen and PKE.Dec, see Sections 8.4.1 & 8.4.3 of the Round 3
 * Saber specification
 */
void POLVECq2BS(const PolyVec_Zq input_vec,
                uint8_t output_bytes[SABER_POLYVECBYTES]);
void BS2POLVECq(PolyVec_Zq output_vec,
                const uint8_t input_bytes[SABER_POLYVECBYTES]);

/*
 * Conversions for going from vectors of Zp Polynomials to ByteStrings, and vice
 * versa.
 *
 * Used in PKE.KeyGen, PKE.Enc and PKE.Dec, see Sections 8.4.1 thru 8.4.3 of the
 * Round 3 Saber specification
 */
void POLVECp2BS(const PolyVec_Zp input_vec,
                uint8_t output_bytes[SABER_POLYVECCOMPRESSEDBYTES]);
void BS2POLVECp(PolyVec_Zp output_vec,
                const uint8_t input_bytes[SABER_POLYVECCOMPRESSEDBYTES]);

/*
 * Conversions for going from Z2 Polynomials to ByteStrings, and vice versa.
 *
 * Used in PKE.Enc and PKE.Dec, see Sections 8.4.2 & 8.4.3 of the Round 3 Saber
 * specification
 */
void POLmsg2BS(const Poly_Z2 input_poly, uint8_t output_bytes[SABER_KEYBYTES]);
void BS2POLmsg(Poly_Z2 output_poly, const uint8_t input_bytes[SABER_KEYBYTES]);

#endif