/*
 * Higher-level arithmetic operations over polynomial vectors and matrices.
 *
 * Declares the following functions, corresponding to algorithms in
 * Section 8.3 of the Round 3 Saber specification:
 *   - GenMatrix:       generates the public matrix A from a seed (Algorithm 15)
 *   - GenSecret:       samples a secret vector from a noise seed (Algorithm 16)
 *   - MatrixVectorMul: multiplies a matrix by a vector in R_q (Algorithm 13)
 *   - InnerProd:       computes the inner product of two vectors in R_p
 * (Algorithm 14)
 *
 * Depends on: params.h, types.h, poly.h, third_party/fips202.h
 */

#ifndef ARITHMETIC_H
#define ARITHMETIC_H

#include "params.h"
#include "types.h"
#include "poly.h"
#include "../third_party/fips202.h"

/**
 * High-level arithmetic operations over polynomial vectors and matrices.
 *
 * @param seed Input seed for generation functions (GenMatrix, GenSecret)
 * @param result Output buffer for results of each function
 */
void gen_matrix(const uint8_t seed[SABER_SEEDBYTES], PolyMatrix_Zq result);

/**
 * Generates a secret vector of polynomials in R_q from a noise seed.
 *
 * @param seed Input noise seed (SABER_NOISE_SEEDBYTES bytes)
 * @param result Output buffer for the generated secret vector (PolyVec_Zq)
 */
void gen_secret(const uint8_t seed[SABER_NOISE_SEEDBYTES], PolyVec_Zq result);

/**
 * Multiplies a matrix by a vector in R_q, producing a vector in R_q.
 *
 * @param M Input matrix (PolyMatrix_Zq)
 * @param v Input vector (PolyVec_Zq)
 * @param result Output buffer for the resulting vector (PolyVec_Zq)
 */
void matrix_vector_mul(const PolyMatrix_Zq M, const PolyVec_Zq v, PolyVec_Zq result);

/**
 * Computes the inner product of two vectors in R_p, producing a polynomial in R_p.
 *
 * @param a Input vector (PolyVec_Zp)
 * @param b Input vector (PolyVec_Zp)
 * @param result Output buffer for the resulting polynomial (Poly_Zp)
 */
void inner_prod(const PolyVec_Zp a, const PolyVec_Zp b, Poly_Zp result);

#endif
