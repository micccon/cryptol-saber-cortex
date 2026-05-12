/*
 * Type definitions for Saber polynomial and vector types.
 *
 * Defines typedefs for the core algebraic objects used throughout
 * the Saber scheme — individual polynomials over Zq, Zp, Zt, and Z2,
 * as well as vectors and matrices of these polynomials. These map directly
 * onto the mathematical objects described in Section 8.2 of the Round 3
 * Saber specification.
 *
 * Depends on: params.h (for SABER_N, SABER_L, and modulus sizes)
 */

// TURN OFF clang-format for this file for readability purposes
// clang-format off

#ifndef TYPES_H
#define TYPES_H

#include <stdint.h>
#include "params.h"

/*
 * All coefficient types will use uint16_t regardless of the actual modulus
 * size. This is because we regularly need to convert polynomials with
 * coefficients in one domain into polynomials with coefficients in another
 * domain.
 *
 *      Zq --> 13 bits
 *      Zp --> 10 bits
 *      Zt --> et bits
 *      Z2 --> 1  bit
 *
 * The upper bits are unused, and should be masked off.
 */
typedef uint16_t Zq;
typedef uint16_t Zp;
typedef uint16_t Zt;
typedef uint16_t Z2;

/*
 * Bit masks for each coefficient type. Since all coefficients are stored
 * as uint16_t regardless of their actual modulus size, these masks MUST
 * be applied explicitly wherever the modulus matters.
 *
 * Usage: coeff & MASK_Zq, coeff & MASK_Zp, etc.
 */
#define MASK_Zq ((1U << SABER_EQ) - 1) // 0x1FFF - 13 bits
#define MASK_Zp ((1U << SABER_EP) - 1) // 0x03FF - 10 bits
#define MASK_Zt ((1U << SABER_ET) - 1) // Varies based on et (security level)
#define MASK_Z2 0x1U                   // 1 bit

// Various polynomial types, per coefficient type
typedef Zq Poly_Zq[SABER_N];
typedef Zp Poly_Zp[SABER_N];
typedef Zt Poly_Zt[SABER_N];
typedef Z2 Poly_Z2[SABER_N];

// Various vector types, per polynomial type (SABER only uses vectors of Zp and
// Zq)
typedef Poly_Zq PolyVec_Zq[SABER_L];
typedef Poly_Zp PolyVec_Zp[SABER_L];

// Only matrix type that SABER uses.
typedef Poly_Zq PolyMatrix_Zq[SABER_L][SABER_L];

#endif
