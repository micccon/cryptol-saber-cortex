// Implementation of declarations in ntt_helpers.h
#include <stdint.h>

#include "ntt_helpers.h"

/*
 * To reduce some 64-bit product T of a 32-bit x 32-bit multiplication,
 * we need to compute T * R^{-1} (mod q'). We can achieve this algebraically by:
 *
 *    m  =  T * q'_inv (mod R)           --- chosen so that (T + m * q') ≡ 0 (mod R)
 *    t  =  (T + m * q') / R             --- exact division, free since R = 2^{32}
 *
 * To see why t ≡ T * R^{-1} (mod q'), we can note that:
 *
 *        t  =  (T + m * q') / R
 *    t * R  =  T + m * q'               --- multiply both sides by R
 *           ≡  T (mod q')               --- since m * q' ≡ 0 (mod q')
 *        t  ≡  T * R^{-1} (mod q')      --- multiply both sides by R^{-1}
 */
uint32_t montgomery_reduce(uint64_t a) {
    uint32_t m = (uint32_t)a * NTT_Q_INV;
    uint32_t t = (uint32_t)((a + ((uint64_t)m * NTT_Q)) >> 32);

    if (t >= NTT_Q)
        t -= NTT_Q;
    return t;
}

/*
 * To compute the Montgomery product T of two numbers â * b̂ (both already in Montgomery form),
 * we need to compute T = â * b̂ * R^{-1} (mod q'). We can achieve this by:
 *
 *    montgomery_reduce(â * b̂ )  =  (â * b̂) * R^{-1} (mod q')
 *                               =  (a * R) * (b * R) * R^{-1} (mod q')
 *                               =  a * b * R (mod q')            --- precisely the Montgomery representative of a * b
 */
uint32_t montgomery_multiply(uint32_t a, uint32_t b) { return montgomery_reduce((uint64_t)a * (uint64_t)b); }

/*
 * To convert some integer a ∈ [0, q') into Montgomery space, we need to
 * compute â ≡ a * R (mod q'). We can achieve this by leveraging montgomery_multiply
 * with R^2 (mod q') as the second argument:
 *
 *   montgomery_multiply(a, R^2)  =  a * R^2 * R^{-1} (mod q')
 *                                =  a * R (mod q')
 *                                =  â
 */
uint32_t to_montgomery(uint32_t a) { return montgomery_multiply(a, NTT_R2); }

/*
 * To recover some integer a ∈ [0, q') from its Montgomery representative â ∈ [0, q'),
 * observe that â = a * R (mod q'). Passing this directly to montgomery_reduce, we get:
 *
 *   montgomery_reduce(â)  =  â * R^{-1} (mod q')
 *                         =  (a * R) * R^{-1} (mod q')
 *                         =  a (mod q')
 */
uint32_t from_montgomery(uint32_t a) { return montgomery_reduce((uint64_t)a); }
