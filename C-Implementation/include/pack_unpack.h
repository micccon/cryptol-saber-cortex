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

/**
 * Packs a Poly_Zt into a byte string, two SABER_ET-bit coefficients per byte.
 * Used in PKE.Enc (Section 8.4.2).
 *
 * @param input_poly   polynomial to pack
 * @param output_bytes output buffer of SABER_SCALEBYTES_KEM bytes
 */
void POLT2BS(Poly_Zt input_poly, uint8_t output_bytes[SABER_SCALEBYTES_KEM]);

/**
 * Unpacks a byte string into a Poly_Zt. Inverse of POLT2BS.
 * Used in PKE.Dec (Section 8.4.3).
 *
 * @param output_poly recovered polynomial
 * @param input_bytes input buffer of SABER_SCALEBYTES_KEM bytes
 */
void BS2POLT(Poly_Zt output_poly, const uint8_t input_bytes[SABER_SCALEBYTES_KEM]);

/**
 * Unpacks a byte string into a Poly_Zq (13-bit coefficients).
 * Used in GenMatrix.
 *
 * @param output_poly recovered polynomial
 * @param input_bytes input buffer of SABER_POLYBYTES bytes
 */
void BS2POLq(Poly_Zq output_poly, const uint8_t input_bytes[SABER_POLYBYTES]);

/**
 * Packs a PolyVec_Zq into a byte string.
 * Used in PKE.KeyGen (Section 8.4.1).
 *
 * @param input_vec    vector to pack
 * @param output_bytes output buffer of SABER_POLYVECBYTES bytes
 */
void POLVECq2BS(PolyVec_Zq input_vec, uint8_t output_bytes[SABER_POLYVECBYTES]);

/**
 * Unpacks a byte string into a PolyVec_Zq. Inverse of POLVECq2BS.
 * Used in PKE.Dec (Section 8.4.3).
 *
 * @param output_vec  recovered vector
 * @param input_bytes input buffer of SABER_POLYVECBYTES bytes
 */
void BS2POLVECq(PolyVec_Zq output_vec, const uint8_t input_bytes[SABER_POLYVECBYTES]);

/**
 * Packs a PolyVec_Zp into a byte string, four 10-bit coefficients per 5 bytes.
 * Used in PKE.KeyGen, PKE.Enc, PKE.Dec (Sections 8.4.1-8.4.3).
 *
 * @param input_vec    vector to pack
 * @param output_bytes output buffer of SABER_POLYVECCOMPRESSEDBYTES bytes
 */
void POLVECp2BS(PolyVec_Zp input_vec, uint8_t output_bytes[SABER_POLYVECCOMPRESSEDBYTES]);

/**
 * Unpacks a byte string into a PolyVec_Zp. Inverse of POLVECp2BS.
 * Used in PKE.KeyGen, PKE.Enc, PKE.Dec (Sections 8.4.1-8.4.3).
 *
 * @param output_vec  recovered vector
 * @param input_bytes input buffer of SABER_POLYVECCOMPRESSEDBYTES bytes
 */
void BS2POLVECp(PolyVec_Zp output_vec, const uint8_t input_bytes[SABER_POLYVECCOMPRESSEDBYTES]);

/**
 * Packs a Poly_Z2 (256 single-bit message coefficients) into 32 bytes, LSB first.
 * Used in PKE.Enc (Section 8.4.2).
 *
 * @param input_poly   polynomial to pack
 * @param output_bytes output buffer of SABER_KEYBYTES bytes
 */
void POLmsg2BS(Poly_Z2 input_poly, uint8_t output_bytes[SABER_KEYBYTES]);

/**
 * Unpacks 32 bytes into a Poly_Z2. Inverse of POLmsg2BS.
 * Used in PKE.Dec (Section 8.4.3).
 *
 * @param output_poly recovered polynomial
 * @param input_bytes input buffer of SABER_KEYBYTES bytes
 */
void BS2POLmsg(Poly_Z2 output_poly, const uint8_t input_bytes[SABER_KEYBYTES]);

#endif
