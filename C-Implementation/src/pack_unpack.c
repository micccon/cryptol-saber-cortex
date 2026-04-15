/*
 * Implementations of BS<-->Poly serialization and deserialization routines.
 *
 * All functions currently assume the Saber parameter set (SABER_ET = 4,
 * SABER_EP = 10, SABER_EQ = 13, SABER_L = 3). See params.h.
 *
 * Packing conventions follow Sections 8.2.4 and 8.2.7 of the Round 3 Saber
 * specification (BS2POL / POL2BS families), using little-endian bit ordering
 * within each coefficient.
 */

#include <stdint.h>
#include <stddef.h> // for 'size_t'

#include "pack_unpack.h"
#include "params.h"
#include "types.h"

/* ---------------------------------------------------------------------------
 * Zt  <-->  ByteString   (SABER_ET bits per coefficient)
 *
 * For Saber: SABER_ET = 4, so two coefficients pack into one byte.
 * Output buffer length: SABER_SCALEBYTES_KEM = (4 * 256) / 8 = 128 bytes.
 * ---------------------------------------------------------------------------
 */

/*
 * POLT2BS — pack a Poly_Zt into a byte string.
 *
 * Each coefficient is SABER_ET bits wide (4 bits for Saber), so pairs of
 * coefficients are packed into a single byte, low coefficient in the low
 * nibble.
 */
void POLT2BS(const Poly_Zt input_poly,
             uint8_t output_bytes[SABER_SCALEBYTES_KEM]) {
    for (size_t i = 0; i < SABER_N / 2; ++i) {
        // Get first and second coefficients of the current pair
        uint8_t a = input_poly[2 * i] & MASK_Zt;
        uint8_t b = input_poly[2 * i + 1] & MASK_Zt;

        // Put 'a' in the low nibble, 'b' in the high nibble (matching the spec)
        output_bytes[i] = a | (b << 4);
    }
}

/*
 * BS2POLT — unpack a byte string into a Poly_Zt.
 *
 * Inverse of POLT2BS. Masks each extracted coefficient to SABER_ET bits.
 */
void BS2POLT(Poly_Zt output_poly,
             const uint8_t input_bytes[SABER_SCALEBYTES_KEM]) {
    for (size_t i = 0; i < SABER_SCALEBYTES_KEM; ++i) {
        // Extract first and second coefficients from packed byte
        Zt a = input_bytes[i] & MASK_Zt;        // 'a' from low nibble
        Zt b = (input_bytes[i] >> 4) & MASK_Zt; // 'b' from high nibble

        // Write unpacked coefficients to polynomial
        output_poly[2 * i] = a;
        output_poly[2 * i + 1] = b;
    }
}

/* ---------------------------------------------------------------------------
 * Z2  <-->  ByteString   (1 bit per coefficient)
 *
 * Output buffer length: SABER_KEYBYTES = 32 bytes (256 bits).
 * ---------------------------------------------------------------------------
 */

/*
 * POLmsg2BS — pack a Poly_Z2 (256 single-bit coefficients) into 32 bytes.
 *
 * Bit i of coefficient i is placed in bit (i % 8) of byte (i / 8),
 * LSB first.
 */
void POLmsg2BS(const Poly_Z2 input_poly, uint8_t output_bytes[SABER_KEYBYTES]) {
    for (size_t i = 0; i < SABER_N / 8; ++i) {
        // First coefficient in LSB, second in next LSB, third in next LSB, etc.
        output_bytes[i] =
            (input_poly[8 * i + 0] << 0) | (input_poly[8 * i + 1] << 1) |
            (input_poly[8 * i + 2] << 2) | (input_poly[8 * i + 3] << 3) |
            (input_poly[8 * i + 4] << 4) | (input_poly[8 * i + 5] << 5) |
            (input_poly[8 * i + 6] << 6) | (input_poly[8 * i + 7] << 7);
    }
}

/*
 * BS2POLmsg — unpack 32 bytes into a Poly_Z2.
 *
 * Inverse of POLmsg2BS. Each coefficient is masked to 1 bit.
 */
void BS2POLmsg(Poly_Z2 output_poly, const uint8_t input_bytes[SABER_KEYBYTES]) {
    for (size_t i = 0; i < SABER_KEYBYTES; ++i) {
        // Extract eight coefficients from packed byte
        Z2 a = (input_bytes[i] >> 0) & MASK_Z2; // LSB
        Z2 b = (input_bytes[i] >> 1) & MASK_Z2;
        Z2 c = (input_bytes[i] >> 2) & MASK_Z2;
        Z2 d = (input_bytes[i] >> 3) & MASK_Z2;
        Z2 e = (input_bytes[i] >> 4) & MASK_Z2;
        Z2 f = (input_bytes[i] >> 5) & MASK_Z2;
        Z2 g = (input_bytes[i] >> 6) & MASK_Z2;
        Z2 h = (input_bytes[i] >> 7) & MASK_Z2; // MSB

        // Write unpacked coefficients to polynomial
        output_poly[8 * i + 0] = a;
        output_poly[8 * i + 1] = b;
        output_poly[8 * i + 2] = c;
        output_poly[8 * i + 3] = d;
        output_poly[8 * i + 4] = e;
        output_poly[8 * i + 5] = f;
        output_poly[8 * i + 6] = g;
        output_poly[8 * i + 7] = h;
    }
}

/* ---------------------------------------------------------------------------
 * Zq vector  <-->  ByteString   (SABER_EQ = 13 bits per coefficient)
 *
 * Output buffer length: SABER_POLYVECBYTES = L * (13 * 256 / 8) = 1248 bytes.
 *
 * 13 bits does not divide evenly into bytes, so every 8 coefficients span
 * exactly 13 bytes (8 * 13 = 104 bits = 13 bytes). The inner loop therefore
 * processes SABER_N / 8 = 32 such groups per polynomial.
 * ---------------------------------------------------------------------------
 */

/*
 * POLVECq2BS — pack a PolyVec_Zq into a byte string.
 *
 * Iterates over the L polynomials and, within each, packs groups of 8
 * coefficients (13 bits each) into 13 bytes, LSB first.
 */
void POLVECq2BS(const PolyVec_Zq input_vec,
                uint8_t output_bytes[SABER_POLYVECBYTES]) {
    /* TODO */
}

/*
 * BS2POLVECq — unpack a byte string into a PolyVec_Zq.
 *
 * Inverse of POLVECq2BS. Each coefficient is masked to SABER_EQ bits.
 */
void BS2POLVECq(PolyVec_Zq output_vec,
                const uint8_t input_bytes[SABER_POLYVECBYTES]) {
    /* TODO */
}

/* ---------------------------------------------------------------------------
 * Zp vector  <-->  ByteString   (SABER_EP = 10 bits per coefficient)
 *
 * Output buffer length: SABER_POLYVECCOMPRESSEDBYTES =
 *     L * (10 * 256 / 8) = 960 bytes.
 *
 * 10 bits: every 4 coefficients span exactly 5 bytes (4 * 10 = 40 bits).
 * The inner loop therefore processes SABER_N / 4 = 64 groups per polynomial.
 * ---------------------------------------------------------------------------
 */

/*
 * POLVECp2BS — pack a PolyVec_Zp into a byte string.
 *
 * Iterates over the L polynomials and, within each, packs groups of 4
 * coefficients (10 bits each) into 5 bytes, LSB first.
 */
void POLVECp2BS(const PolyVec_Zp input_vec,
                uint8_t output_bytes[SABER_POLYVECCOMPRESSEDBYTES]) {
    /* TODO */
}

/*
 * BS2POLVECp — unpack a byte string into a PolyVec_Zp.
 *
 * Inverse of POLVECp2BS. Each coefficient is masked to SABER_EP bits.
 */
void BS2POLVECp(PolyVec_Zp output_vec,
                const uint8_t input_bytes[SABER_POLYVECCOMPRESSEDBYTES]) {
    /* TODO */
}