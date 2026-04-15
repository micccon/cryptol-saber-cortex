/*
 * Polynomial arithmetic over the ring R_q = Z_q[x] / (x^256 + 1).
 *
 * Declares functions for polynomial multiplication (PolyMul) and
 * accumulation, which are the core arithmetic operations in Saber.
 * The implementation uses schoolbook multiplication; we may shoot for
 * more efficient approaches (e.g. Toom-Cook, Karatsuba, NTTs) later,
 * particularly for the optimized Cortex-M4 target.
 *
 * See Section 8.3.7 of the Round 3 Saber specification for the
 * definition of PolyMul.
 *
 * Depends on: params.h, types.h
 */

#ifndef POLY_H
#define POLY_H

#include "params.h"
#include "types.h"

/*
 * Negacyclic polynomial multiplication in R_q = Z_q[x] / (x^N + 1).
 *
 * Computes:
 *     result = a * b mod (x^SABER_N + 1)
 *
 * Coefficients are represented as Zq values, with the caller responsible
 * for applying any required masking/reduction policy after multiplication.
 */
void poly_mul_negacyclic_zq(const Poly_Zq a,
                            const Poly_Zq b,
                            Poly_Zq result);

/*
 * Negacyclic polynomial multiplication in R_p = Z_p[x] / (x^N + 1).
 *
 * Computes:
 *     result = a * b mod (x^SABER_N + 1)
 */
void poly_mul_negacyclic_zp(const Poly_Zp a,
                            const Poly_Zp b,
                            Poly_Zp result);

#endif
