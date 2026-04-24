/*
 * Interface for NTT helper methods, including Montgomery Multiplication/Reduction
 *
 * A goal of this project is to optimize the speed of our SABER implementation. One of
 * the known bottlenecks of our original, working C implementation lies in the MatrixVectorMul
 * and InnerProd functions, which require calls to `poly_mul` in order to compute negatively-wrapped
 * convolutions (NWC's) of polynomials. These functions use the naive schoolbook method, which takes
 * O(n^2) time.
 *
 * The SABER reference implementation uses Toom-Cook and Karatsuba to optimize this, but research
 * suggests that lifting polynomial arithmetic to a Number Theoretic Transform (NTT)-friendly ring
 * and performing operations there yields similar (often better) performances.
 *
 * Depends on: nothing :)
 */

// TURN OFF clang-format for this file for readability purposes
// clang-format off

#ifndef NTT_HELPERS_H
#define NTT_HELPERS_H

#include <stdint.h>

/*
 * This is the NTT prime modulus (i.e., the ring we're lifting SABER's polynomial multiplication into).
 * Note that it has ~nothing~ to do with SABER's own modulus (q = 2^{13}). Rather, we choose this q' because:
 * 
 *    1) q' is prime, where q (2^{13}) is not. As a result, Z_{q'} is a field with a cyclic multiplicative group.
 *    2) q' has the form 2^k * p' + 1, and thus has primitive roots of unity of high-enough order for NTTs to work.
 *    3) q' is large enough that intermediate results (products) don't overflow and wrap around incorrectly before
 *         we reduce back to Z_q
 */
#define NTT_Q      25166081     // NTT prime for Saber/Firesaber

/*
 * This is the negated inverse of q' in Z_{2^{32}}. It's necessary for Montgomery Reduction to work, and is the value
 * such that:
 *            q' * q'_inv ≡ -1 (mod R)
 */
#define NTT_Q_INV  41877759     // -q'^{-1} mod 2^32

/*
 * R^2 mod q', where R = 2^32. We use this value to convert values into Montgomery form via
 * Montgomery multiplication:
 *
 *    montgomery_mul(a, NTT_R2) = a * R^2 * R^{-1} mod q' = a * R mod q'
 *
 * which is the definition of a being in Montgomery form.
 * 
 * A note on R (not R^2): we choose R = 2^{32} for ~computational~ reasons, not mathematical reasons. If we choose
 * R such that R is a power of 2 that is greater than q', then we gain two advantages:
 *    
 *    1) 'x mod R' is free: we just truncate a value to its lower 32 bits.
 *    2) 'x / R' is free: we just bit shift right by 32 (>> 32).
 */
#define NTT_R2     13990637     // R^2 mod q'

/**
 * Computes T * R^{-1} mod q' for a 64-bit input T.
 *
 * @param  a    64-bit value to reduce
 * @return      32-bit r ∈ [0, q') such that r ≡ T * R^{-1} (mod q')
 */
int32_t montgomery_reduce(int64_t a);

/**
 * Computes the Montgomery product of two values already in Montgomery form.
 * 
 * @param  a    First 32-bit Montgomery-form multiplicand
 * @param  b    Second 32-bit Montgomery-form multiplicand
 * @return      Montgomery Product r such that r ≡ â * b̂ * R (mod q')
 */
int32_t montgomery_multiply(int32_t a, int32_t b);

/**
 * Converts an integer into its Montgomery representative.
 * 
 * @param  a    Arbitrary 32-bit integer such that a ∈ [0, q')
 * @return      â, the Montgomery representation of a, such that â ≡ a * R (mod q')
 */
int32_t to_montgomery(int32_t a);

/**
 * Recovers an integer from its Montgomery representative.
 * 
 * @param  a    â, the 32-bit Montgomery-form value such that â ≡ a * R (mod q')
 * @return      Recovered value r such that r ≡ a (mod q')
 */
int32_t from_montgomery(int32_t a);

#endif
