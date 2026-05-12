// Implementation of declarations in 'arithmetic.h'
#include "arithmetic.h"
#include "helpers.h"
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
    uint8_t buf[SABER_L * SABER_N * SABER_MU / 8];
    shake128(buf, sizeof(buf), seed, SABER_NOISE_SEEDBYTES);
    /* "Split buf into 2 × l × n bit strings of length μ/2 bits"
     * So thats (2 * l * n) / 8 byte strings of length (μ/2) / 8 bytes
     * Since saber mu = 8 means each is a 4 bit half, so we can combine the halves of mu
     * Then we'll have (l * n) bit strings each of length mu
     * Converting to bytes, we'll have (l * n) / 8 byte strings of length mu / 8 bytes (1 byte)
     * Sooooo we can just use the original buffer
     */
    int k = 0;
    for (int i = 0; i < SABER_L; i++) {
        for (int j = 0; j < SABER_N; j++) {
            uint8_t low = buf[k] & 0x0F;
            uint8_t high = (buf[k] >> 4) & 0x0F;
            // Calculate the hamming weight of the low and high halves, subtract, and store in result
            result[i][j] =
                (Zq)((hamming_weight(&low, SABER_MU / 2) -
                    hamming_weight(&high, SABER_MU / 2)) & MASK_Zq);
            ++k;
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
