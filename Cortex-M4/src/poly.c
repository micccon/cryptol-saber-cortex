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
    // To leverage the NTT, need to represent coefficients in 32-bit integers
    // instead of 16-bit integers
    uint32_t a_ntt[SABER_N], b_ntt[SABER_N], r_ntt[SABER_N];

    for (int i = 0; i < SABER_N; ++i) {
        a_ntt[i] = to_montgomery((uint32_t)a[i]);
        b_ntt[i] = to_montgomery((uint32_t)b[i]);
    }

    // Apply 7-layer incomplete, in-place NTT transformation to a and b
    ntt(a_ntt);
    ntt(b_ntt);

    // Handle base-case multiplication of 128 degree-1 sub-polynomials
    ntt_base_mul(a_ntt, b_ntt, r_ntt);

    // Apply INTT to get back to 256 Montgomery-form coefficients
    inv_ntt(r_ntt);

    // Convert back from Montgomery to normal coefficient representation
    for (int i = 0; i < SABER_N; ++i) {
        result[i] = from_montgomery(r_ntt[i]) & MASK_Zq;
    }
}

void poly_mul_ntt_zp(const Poly_Zp a, const Poly_Zp b, Poly_Zp result) {
    // To leverage the NTT, need to represent coefficients in 32-bit integers
    // instead of 16-bit integers
    uint32_t a_ntt[SABER_N], b_ntt[SABER_N], r_ntt[SABER_N];

    for (int i = 0; i < SABER_N; ++i) {
        a_ntt[i] = to_montgomery((uint32_t)a[i]);
        b_ntt[i] = to_montgomery((uint32_t)b[i]);
    }

    // Apply 7-layer incomplete, in-place NTT transformation to a and b
    ntt(a_ntt);
    ntt(b_ntt);

    // Handle base-case multiplication of 128 degree-1 sub-polynomials
    ntt_base_mul(a_ntt, b_ntt, r_ntt);

    // Apply INTT to get back to 256 Montgomery-form coefficients
    inv_ntt(r_ntt);

    // Convert back from Montgomery to normal coefficient representation
    for (int i = 0; i < SABER_N; ++i) {
        result[i] = from_montgomery(r_ntt[i]) & MASK_Zp;
    }
}
