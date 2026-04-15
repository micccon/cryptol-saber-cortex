// Implementation of declarations in 'poly.h'
#include <stddef.h>
#include "poly.h"

void poly_mul_negacyclic_zq(const Poly_Zq aPoly,
                            const Poly_Zq bPoly,
                            Poly_Zq result) {
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

void poly_mul_negacyclic_zp(const Poly_Zp aPoly,
                            const Poly_Zp bPoly,
                            Poly_Zp result) {
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
