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

#endif