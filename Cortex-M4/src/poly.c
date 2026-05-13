// Implementation of declarations in 'poly.h'
#include "poly.h"
#include "ntt_helpers.h"
#include "types.h"
#include <stddef.h>

void poly_mul_negacyclic_zq(const Poly_Zq aPoly, const Poly_Zq bPoly, Poly_Zq result) {
    for (size_t i = 0; i < SABER_N; i++) {
        uint32_t acc = 0;

        for (size_t j = 0; j < SABER_N; j++) {
            uint32_t product;

            if (j <= i) {
                product = (uint32_t)aPoly[j] * bPoly[i - j];
                acc += product;
            } else {
                product = (uint32_t)aPoly[j] * bPoly[SABER_N + i - j];
                acc -= product;
            }
        }

        result[i] = (Zq)(acc & MASK_Zq);
    }
}

void poly_mul_negacyclic_zp(const Poly_Zp aPoly, const Poly_Zp bPoly, Poly_Zp result) {
    for (size_t i = 0; i < SABER_N; i++) {
        uint32_t acc = 0;

        for (size_t j = 0; j < SABER_N; j++) {
            uint32_t product;

            if (j <= i) {
                product = (uint32_t)aPoly[j] * bPoly[i - j];
                acc += product;
            } else {
                product = (uint32_t)aPoly[j] * bPoly[SABER_N + i - j];
                acc -= product;
            }
        }

        result[i] = (Zp)(acc & MASK_Zp);
    }
}

void poly_mul_ntt_zq(const Poly_Zq a, const Poly_Zq b, Poly_Zq result) {
    uint32_t a_ntt[SABER_N], b_ntt[SABER_N], r_ntt[SABER_N];

    // Lift Z_q coefficients into Z_{q'} using a centered representative.
    // Coefficients > q/2 represent negative values in Z_q; encode them as
    // q' - q + c so the true convolution stays within (-q'/2, q'/2),
    // which is required for the centered reduction below to be unambiguous.
    for (int i = 0; i < SABER_N; ++i) {
        uint32_t ai = (a[i] > (MASK_Zq >> 1)) ? (NTT_Q - (MASK_Zq + 1) + a[i]) : (uint32_t)a[i];
        uint32_t bi = (b[i] > (MASK_Zq >> 1)) ? (NTT_Q - (MASK_Zq + 1) + b[i]) : (uint32_t)b[i];
        a_ntt[i] = to_montgomery(ai);
        b_ntt[i] = to_montgomery(bi);
    }

    // Apply 7-layer incomplete, in-place NTT transformation to a and b
    ntt(a_ntt);
    ntt(b_ntt);

    // Handle base-case multiplication of 128 degree-1 sub-polynomials
    ntt_base_mul(a_ntt, b_ntt, r_ntt);

    // Apply INTT to get back to 256 Montgomery-form coefficients
    inv_ntt(r_ntt);

    // Centered reduction: NTT result in [0, q'). Values > q'/2 represent
    // negative coefficients; subtract q' to recover the signed integer, then
    // mask to Z_q. Two's complement makes & MASK_Zq correct for both signs.
    for (int i = 0; i < SABER_N; ++i) {
        uint32_t v = from_montgomery(r_ntt[i]);
        if (v > (uint32_t)(NTT_Q / 2))
            v = (uint32_t)((int32_t)v - (int32_t)NTT_Q);
        result[i] = (Zq)(v & MASK_Zq);
    }
}

void poly_mul_ntt_zp(const Poly_Zp a, const Poly_Zp b, Poly_Zp result) {
    uint32_t a_ntt[SABER_N], b_ntt[SABER_N], r_ntt[SABER_N];

    for (int i = 0; i < SABER_N; ++i) {
        uint32_t ai = (a[i] > (MASK_Zp >> 1)) ? (NTT_Q - (MASK_Zp + 1) + a[i]) : (uint32_t)a[i];
        uint32_t bi = (b[i] > (MASK_Zp >> 1)) ? (NTT_Q - (MASK_Zp + 1) + b[i]) : (uint32_t)b[i];
        a_ntt[i] = to_montgomery(ai);
        b_ntt[i] = to_montgomery(bi);
    }

    ntt(a_ntt);
    ntt(b_ntt);
    ntt_base_mul(a_ntt, b_ntt, r_ntt);
    inv_ntt(r_ntt);

    for (int i = 0; i < SABER_N; ++i) {
        uint32_t v = from_montgomery(r_ntt[i]);
        if (v > (uint32_t)(NTT_Q / 2))
            v = (uint32_t)((int32_t)v - (int32_t)NTT_Q);
        result[i] = (Zp)(v & MASK_Zp);
    }
}
