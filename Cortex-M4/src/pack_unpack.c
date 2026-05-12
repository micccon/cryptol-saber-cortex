// Implementation of bit packing/unpacking from `pack_unpack.h`
#include <stdint.h>
#include <stddef.h> // for 'size_t'

#include "pack_unpack.h"
#include "params.h"
#include "types.h"

/* ---------------------------------------------------------------------------
 * Zt  <-->  ByteString   (SABER_ET bits per coefficient)
 * ---------------------------------------------------------------------------
 */

void POLT2BS(Poly_Zt input_poly, uint8_t output_bytes[SABER_SCALEBYTES_KEM]) {
    for (size_t i = 0; i < SABER_N / 2; ++i) {
        // Get first and second coefficients of the current pair
        uint8_t a = input_poly[2 * i] & MASK_Zt;
        uint8_t b = input_poly[2 * i + 1] & MASK_Zt;

        // Put 'a' in the low nibble, 'b' in the high nibble (matching the spec)
        output_bytes[i] = a | (b << 4);
    }
}

void BS2POLT(Poly_Zt output_poly, const uint8_t input_bytes[SABER_SCALEBYTES_KEM]) {
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
 * ---------------------------------------------------------------------------
 */

void POLmsg2BS(Poly_Z2 input_poly, uint8_t output_bytes[SABER_KEYBYTES]) {
    for (size_t i = 0; i < SABER_N / 8; ++i) {
        // First coefficient in LSB, second in next LSB, third in next LSB, etc.
        output_bytes[i] = (input_poly[8 * i + 0] << 0) | (input_poly[8 * i + 1] << 1) | (input_poly[8 * i + 2] << 2) |
                          (input_poly[8 * i + 3] << 3) | (input_poly[8 * i + 4] << 4) | (input_poly[8 * i + 5] << 5) |
                          (input_poly[8 * i + 6] << 6) | (input_poly[8 * i + 7] << 7);
    }
}

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
 * ---------------------------------------------------------------------------
 */

static void POLq2BS(Poly_Zq input_poly, uint8_t output_bytes[SABER_POLYBYTES]) {
    // Work thru poly in batches of 8 coefficients, to pack 13 bytes at a time
    for (size_t i = 0; i < SABER_N / 8; ++i) {
        // Gather eight coefficients (for readability)
        Zq coeff1 = input_poly[8 * i + 0];
        Zq coeff2 = input_poly[8 * i + 1];
        Zq coeff3 = input_poly[8 * i + 2];
        Zq coeff4 = input_poly[8 * i + 3];
        Zq coeff5 = input_poly[8 * i + 4];
        Zq coeff6 = input_poly[8 * i + 5];
        Zq coeff7 = input_poly[8 * i + 6];
        Zq coeff8 = input_poly[8 * i + 7];

        // Pack the eight coefficients into their respective 13 bytes
        output_bytes[13 * i + 0] = ((coeff1 >> 0) & 0xFF);    // Lower 8 bits of first coeff
        output_bytes[13 * i + 1] = ((coeff1 >> 8) & 0x1F) |   // Remaining 5 bits of first coeff
                                   ((coeff2 << 5) & 0xE0);    // Lower 3 bits of second coeff
        output_bytes[13 * i + 2] = ((coeff2 >> 3) & 0xFF);    // Next 8 bits of second coeff
        output_bytes[13 * i + 3] = ((coeff2 >> 11) & 0x03) |  // Remaining 2 bits of second coeff
                                   ((coeff3 << 2) & 0xFC);    // Lower 6 bits of third coeff
        output_bytes[13 * i + 4] = ((coeff3 >> 6) & 0x7F) |   // Remaining 7 bits of third coeff
                                   ((coeff4 << 7) & 0x80);    // Lower 1 bit of fourth coeff
        output_bytes[13 * i + 5] = ((coeff4 >> 1) & 0xFF);    // Next 8 bits of fourth coeff
        output_bytes[13 * i + 6] = ((coeff4 >> 9) & 0x0F) |   // Remaining 4 bits of fourth coeff
                                   ((coeff5 << 4) & 0xF0);    // Lower 4 bits of fifth coeff
        output_bytes[13 * i + 7] = ((coeff5 >> 4) & 0xFF);    // Next 8 bits of fifth coeff
        output_bytes[13 * i + 8] = ((coeff5 >> 12) & 0x01) |  // Remaining 1 bit of fifth coeff
                                   ((coeff6 << 1) & 0xFE);    // Lower 7 bits of sixth coeff
        output_bytes[13 * i + 9] = ((coeff6 >> 7) & 0x3F) |   // Remaining 6 bits of sixth coeff
                                   ((coeff7 << 6) & 0xC0);    // Lower 2 bits of seventh coeff
        output_bytes[13 * i + 10] = ((coeff7 >> 2) & 0xFF);   // Next 8 bits of seventh coeff
        output_bytes[13 * i + 11] = ((coeff7 >> 10) & 0x07) | // Remaining 3 bits of seventh coeff
                                    ((coeff8 << 3) & 0xF8);   // Lower 5 bits of eighth coeff
        output_bytes[13 * i + 12] = ((coeff8 >> 5) & 0xFF);   // Remaining 8 bits of eighth coeff
    }
}

void BS2POLq(Poly_Zq output_poly, const uint8_t input_bytes[SABER_POLYBYTES]) {
    // Extract eight coefficients from 13 bytes at a time
    for (size_t i = 0; i < SABER_N / 8; ++i) {
        // Extract the eight Zq coefficients
        Zq a = ((input_bytes[13 * i + 0] & 0xFF) >> 0) |  // Lower 8 bits of first coeff
               ((input_bytes[13 * i + 1] & 0x1F) << 8);   // Remaining 5 bits of first coeff
        Zq b = ((input_bytes[13 * i + 1] & 0xE0) >> 5) |  // Lower 3 bits of second coeff
               ((input_bytes[13 * i + 2] & 0xFF) << 3) |  // Next 8 bits of second coeff
               ((input_bytes[13 * i + 3] & 0x03) << 11);  // Remaining 2 bits of second coeff
        Zq c = ((input_bytes[13 * i + 3] & 0xFC) >> 2) |  // Lower 6 bits of third coeff
               ((input_bytes[13 * i + 4] & 0x7F) << 6);   // Remaining 7 bits of third coeff
        Zq d = ((input_bytes[13 * i + 4] & 0x80) >> 7) |  // Lower 1 bit of fourth coeff
               ((input_bytes[13 * i + 5] & 0xFF) << 1) |  // Next 8 bits of fourth coeff
               ((input_bytes[13 * i + 6] & 0x0F) << 9);   // Remaining 4 bits of fourth coeff
        Zq e = ((input_bytes[13 * i + 6] & 0xF0) >> 4) |  // Lower 4 bits of fifth coeff
               ((input_bytes[13 * i + 7] & 0xFF) << 4) |  // Next 8 bits of fifth coeff
               ((input_bytes[13 * i + 8] & 0x01) << 12);  // Remaining 1 bit of fifth coeff
        Zq f = ((input_bytes[13 * i + 8] & 0xFE) >> 1) |  // Lower 7 bits of sixth coeff
               ((input_bytes[13 * i + 9] & 0x3F) << 7);   // Remaining 6 bits of sixth coeff
        Zq g = ((input_bytes[13 * i + 9] & 0xC0) >> 6) |  // Lower 2 bits of seventh coeff
               ((input_bytes[13 * i + 10] & 0xFF) << 2) | // Next 8 bits of seventh coeff
               ((input_bytes[13 * i + 11] & 0x07) << 10); // Remaining 3 bits of seventh coeff
        Zq h = ((input_bytes[13 * i + 11] & 0xF8) >> 3) | // Lower 5 bits of eigth coeff
               ((input_bytes[13 * i + 12] & 0xFF) << 5);  // Remaining 8 bits of eigth coeff

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

void POLVECq2BS(PolyVec_Zq input_vec, uint8_t output_bytes[SABER_POLYVECBYTES]) {
    // Pack in a poly-by-poly fashion thru the entire vector
    for (size_t i = 0; i < SABER_L; ++i)
        POLq2BS(input_vec[i], output_bytes + i * SABER_POLYBYTES);
}

void BS2POLVECq(PolyVec_Zq output_vec, const uint8_t input_bytes[SABER_POLYVECBYTES]) {
    // Unpack in a poly-by-poly fashion thru the byte string
    for (size_t i = 0; i < SABER_L; ++i) {
        BS2POLq(output_vec[i], input_bytes + i * SABER_POLYBYTES);
    }
}

/* ---------------------------------------------------------------------------
 * Zp vector  <-->  ByteString   (SABER_EP = 10 bits per coefficient)
 * ---------------------------------------------------------------------------
 */

static void POLp2BS(Poly_Zp input_poly, uint8_t output_bytes[SABER_POLYCOMPRESSEDBYTES]) {
    // Work thru poly in batches of 4 coefficients, to pack 5 bytes at a time
    for (size_t i = 0; i < SABER_N / 4; ++i) {
        // Gather four coefficients (for readability)
        Zp coeff1 = input_poly[4 * i + 0];
        Zp coeff2 = input_poly[4 * i + 1];
        Zp coeff3 = input_poly[4 * i + 2];
        Zp coeff4 = input_poly[4 * i + 3];

        // Pack the four coefficients into their respective five bytes
        output_bytes[5 * i + 0] = ((coeff1 >> 0) & 0xFF);  // Lower 8 bits of first coeff
        output_bytes[5 * i + 1] = ((coeff1 >> 8) & 0x03) | // 2 remaining bits of first coeff in LSB
                                  ((coeff2 << 2) & 0xFC);  // Lower 6 bits of second coeff in MSB
        output_bytes[5 * i + 2] = ((coeff2 >> 6) & 0x0F) | // 4 remaining bits of second coeff in LSB
                                  ((coeff3 << 4) & 0xF0);  // Lower 4 bits of third coeff in MSB
        output_bytes[5 * i + 3] = ((coeff3 >> 4) & 0x3F) | // 6 remaining bits of third coeff in LSB
                                  ((coeff4 << 6) & 0xC0);  // 2 lower bits of fourth coeff in MSB
        output_bytes[5 * i + 4] = ((coeff4 >> 2) & 0xFF);  // Remaining 8 bits of fourth coeff
    }
}

static void BS2POLp(Poly_Zp output_poly, const uint8_t input_bytes[SABER_POLYCOMPRESSEDBYTES]) {
    // Extract 4 coefficients from 5 bytes at a time
    for (size_t i = 0; i < SABER_N / 4; ++i) {
        // Extract the four Zp coefficients
        Zp a = ((input_bytes[5 * i + 0] & 0xFF) >> 0) | // Lower 8 bits of first coeff
               ((input_bytes[5 * i + 1] & 0x03) << 8);  // Remaining 2 bits of first coeff
        Zp b = ((input_bytes[5 * i + 1] & 0xFC) >> 2) | // Lower 6 bits of second coeff
               ((input_bytes[5 * i + 2] & 0x0F) << 6);  // 4 remaining bits of second coeff
        Zp c = ((input_bytes[5 * i + 2] & 0xF0) >> 4) | // Lower 4 bits of third coeff
               ((input_bytes[5 * i + 3] & 0x3F) << 4);  // Remaining 6 bits of third coeff
        Zp d = ((input_bytes[5 * i + 3] & 0xC0) >> 6) | // Lower 2 bits of fourth coeff
               ((input_bytes[5 * i + 4] & 0xFF) << 2);  // Remaining 8 bits of fourth coeff

        // Write unpacked coefficients to polynomial
        output_poly[4 * i + 0] = a;
        output_poly[4 * i + 1] = b;
        output_poly[4 * i + 2] = c;
        output_poly[4 * i + 3] = d;
    }
}

void POLVECp2BS(PolyVec_Zp input_vec, uint8_t output_bytes[SABER_POLYVECCOMPRESSEDBYTES]) {
    // Pack in a poly-by-poly fashion thru the entire vector
    for (size_t i = 0; i < SABER_L; ++i)
        POLp2BS(input_vec[i], output_bytes + i * SABER_POLYCOMPRESSEDBYTES);
}

void BS2POLVECp(PolyVec_Zp output_vec, const uint8_t input_bytes[SABER_POLYVECCOMPRESSEDBYTES]) {
    // Unpack in a poly-by-poly fashion thru the byte string
    for (size_t i = 0; i < SABER_L; ++i) {
        BS2POLp(output_vec[i], input_bytes + i * SABER_POLYCOMPRESSEDBYTES);
    }
}
