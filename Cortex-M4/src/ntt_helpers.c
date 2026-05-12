// Implementation of declarations in ntt_helpers.h
#include <stdint.h>

#include "../include/ntt_helpers.h"
#include "params.h"

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

/*
 * Performs a Cooley-Tukey NTT on a 256-coefficient polynomial over Z_{q'}, leaving
 * 128 degree-1 sub-polynomials rather than reducing all the way to scalars.
 */
void ntt(uint32_t a[SABER_N]) {
    int k = 1; // index into precomputed table of twiddle factors

    for (int len = 128; len >= 2; len >>= 1) { // 7 levels: 128, 64, 32, 16, 8, 4, 2
        for (int start = 0; start < SABER_N; start += 2 * len) {
            uint32_t zeta = zetas[k++]; // the twiddle factor for this group

            // Apply the Cooley-Tukey butterfly to each coefficient pair (a[j], a[j+len])
            // in this group. Each pair holds one coefficient from the low half and the
            // corresponding coefficient from the high half of the current sub-polynomial.
            // The butterfly computes the two CRT projections in-place:
            //   a[j]     <- a[j] + zeta * a[j+len]   (mod x^len - zeta)
            //   a[j+len] <- a[j] - zeta * a[j+len]   (mod x^len + zeta)
            for (int j = start; j < start + len; ++j) {
                uint32_t t = montgomery_multiply(zeta, a[j + len]);

                // High-half coefficient, a[j] - zeta * a[j+len] (mod x^len + zeta)
                a[j + len] = a[j] + NTT_Q - t;
                if (a[j + len] >= NTT_Q) {
                    a[j + len] -= NTT_Q;
                }

                // Low-half coefficient, a[j] + zeta * a[j+len] (mod x^len - zeta)
                a[j] = a[j] + t;
                if (a[j] >= NTT_Q) {
                    a[j] -= NTT_Q;
                }
            }
        }
    }
}

/*
 * Completes the incomplete NTT multiply: 128 independent degree-1 multiplications
 * in Z_{q'}[x]/(x^2 - zeta_i), one per residue sub-polynomial left by ntt().
 */
void ntt_base_mul(const uint32_t *a, const uint32_t *b, uint32_t *result) {
    for (int i = 0; i < 128; ++i) {
        // Second pair in each group uses ~negated~ twiddle factor
        uint32_t zeta = (i % 2 == 0) ? zetas[64 + i / 2] : NTT_Q - zetas[64 + i / 2];

        // Constant term: a0*b0 + zeta*a1*b1
        result[2 * i] = montgomery_multiply(a[2 * i], b[2 * i]) +
                        montgomery_multiply(montgomery_multiply(a[2 * i + 1], b[2 * i + 1]), zeta);
        if (result[2 * i] >= NTT_Q) {
            result[2 * i] -= NTT_Q;
        }

        // Linear term: a0*b1 + a1*b0
        result[2 * i + 1] = montgomery_multiply(a[2 * i], b[2 * i + 1]) + montgomery_multiply(a[2 * i + 1], b[2 * i]);
        if (result[2 * i + 1] >= NTT_Q) {
            result[2 * i + 1] -= NTT_Q;
        }
    }
}

/*
 * Inverts ntt() via the Gentleman-Sande butterfly (len 2→128, fine-to-coarse),
 * then normalizes by 128^{-1} to cancel the per-level scaling factor.
 */
void inv_ntt(uint32_t a[SABER_N]) {
    int k = 1; // index into precomputed table of ~inverse~ twiddle factors

    for (int len = 2; len <= 128; len <<= 1) {
        for (int start = 0; start < SABER_N; start += 2 * len) {
            uint32_t inv_zeta = inv_zetas[k++]; // the inverse twiddle factor for this group

            // Apply the Gentleman-Sande butterfly to each pair (a[j], a[j+len]).
            // Each pair holds two CRT residues left by the forward NTT's CT split:
            //   a[j]     ≡ f (mod x^len - zeta)
            //   a[j+len] ≡ f (mod x^len + zeta)
            // The butterfly recombines them into coefficients of the merged degree-2*len polynomial
            // (without the 1/2 normalization factor, which is batched into NTT_INV128 at the end):
            //   a[j]     <- a[j] + a[j+len]
            //   a[j+len] <- inv_zeta * (a[j] - a[j+len])
            for (int j = start; j < start + len; ++j) {
                uint32_t t = a[j + len];

                a[j + len] = montgomery_multiply(inv_zeta, a[j] + NTT_Q - t);
                if (a[j + len] >= NTT_Q) {
                    a[j + len] -= NTT_Q;
                }

                a[j] = a[j] + t;
                if (a[j] >= NTT_Q) {
                    a[j] -= NTT_Q;
                }
            }
        }
    }

    // Normalize: multiply every coefficient by 128^{-1} in Montgomery form
    for (int i = 0; i < SABER_N; ++i)
        a[i] = montgomery_multiply(a[i], NTT_INV128);
}
