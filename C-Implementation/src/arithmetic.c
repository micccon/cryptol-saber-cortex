// Implementation of declarations in 'arithmetic.h'
#include "arithmetic.h"
#include <stddef.h>
#include <string.h>

void gen_matrix(const uint8_t seed[SABER_SEEDBYTES], PolyMatrix_Zq result) {
    // Generate buffer
    uint8_t buf[SABER_L * SABER_L * SABER_N * SABER_EQ / 8];
    shake128(buf, sizeof(buf), seed, SABER_SEEDBYTES);

    // Convert into split buffer where each row corresponds to one polynomial, for easier unpacking
    uint8_t buf_matrix[SABER_L * SABER_L][SABER_EQ * SABER_N / 8];
    memcpy(buf_matrix, buf, sizeof(buf_matrix));

    // For each vector
    for (int i1 = 0; i1 < SABER_L; i1++)
    {
        // For each polynomial
        for (int i2 = 0; i2 < SABER_L; i2++)
            BS2POLq(result[i1][i2], buf_matrix[i1 * SABER_L + i2]);
    }
}

void gen_secret(const uint8_t seed[SABER_NOISE_SEEDBYTES], PolyVec_Zq result) {
    uint8_t buf[] = malloc(SABER_L * SABER_N * (SABER_MU / 8));
    result = malloc(sizeof(PolyVec_Zq));

    shake128(buf, sizeof(buf), seed, SABER_NOISE_SEEDBYTES);

    int k = 0;
    for (int i = 0; i < SABER_L; i++) {
        for (int j = 0; j < SABER_N; j++) {
            // hamming weight
            k += 2;
        }
    }
    return;
}

void inner_prod(PolyVec_Zp a, PolyVec_Zp b, Poly_Zp result) {
    Poly_Zp product;

    for (size_t k = 0; k < SABER_N; ++k) {
        result[k] = 0;
    }

    for (size_t i = 0; i < SABER_L; ++i) {
        poly_mul_negacyclic_zp(a[i], b[i], product);

        for (size_t k = 0; k < SABER_N; ++k) {
            result[k] = (Zp)((result[k] + product[k]) & MASK_Zp);
        }
    }
}

void matrix_vector_mul(PolyMatrix_Zq M, PolyVec_Zq v, PolyVec_Zq result)
{
    // For each vector in M
    for (int i = 0; i < SABER_L; i++) {
        Poly_Zq product;
        memset(result[i], 0, sizeof(Poly_Zq));

        // For each poly in M and v
        for (int j = 0; j < SABER_L; j++)
        {
            poly_mul_negacyclic_zq(M[i][j], v[j], product);
            
            for (int k = 0; k < SABER_N; k++)
                result[i][k] = (Zq)((result[i][k] + product[k]) & MASK_Zq);
        }
    }
}
