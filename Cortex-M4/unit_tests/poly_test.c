#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "poly.h"
#include "types.h"

#define NUM_ITERS 10000

static void random_poly_zq(Poly_Zq poly) {
    for (int i = 0; i < SABER_N; ++i)
        poly[i] = rand() & MASK_Zq;
}

static void random_small_poly_zq(Poly_Zq poly) {
    for (int i = 0; i < SABER_N; ++i) {
        poly[i] = rand() % (SABER_MU + 1); // 0..8, reminiscent of the actual values generated via gen_secret
    }
}

static int check_zero_poly_schoolbook(void) {
    Poly_Zq zeroes = {0};
    Poly_Zq poly;
    random_poly_zq(poly);

    Poly_Zq res;
    poly_mul_negacyclic_zq(zeroes, poly, res);

    for (int i = 0; i < SABER_N; ++i) {
        if (res[i] != 0) {
            printf("[FAIL] check_zero_poly_schoolbook: coefficient %d nonzero (got %u)\n", i, (unsigned)res[i]);
            return 1;
        }
    }
    printf("[PASS] check_zero_poly_schoolbook\n");
    return 0;
}

static int check_zero_poly_ntt(void) {
    Poly_Zq zeroes = {0};
    Poly_Zq poly;
    random_poly_zq(poly);

    Poly_Zq res;
    poly_mul_ntt_zq(zeroes, poly, res);

    for (int i = 0; i < SABER_N; ++i) {
        if (res[i] != 0) {
            printf("[FAIL] check_zero_poly_ntt: coefficient %d nonzero (got %u)\n", i, (unsigned)res[i]);
            return 1;
        }
    }
    printf("[PASS] check_zero_poly_ntt\n");
    return 0;
}

static int check_identity_poly_schoolbook(void) {
    Poly_Zq ones = {1};
    Poly_Zq poly;
    random_poly_zq(poly);

    Poly_Zq res;
    poly_mul_negacyclic_zq(ones, poly, res);

    for (int i = 0; i < SABER_N; ++i) {
        if (res[i] != poly[i]) {
            printf("[FAIL] check_identity_poly_schoolbook: coefficient %d mismatch"
                   " (got %u, expected %u)\n",
                   i, (unsigned)res[i], (unsigned)poly[i]);
            return 1;
        }
    }
    printf("[PASS] check_identity_poly_schoolbook\n");
    return 0;
}

static int check_identity_poly_ntt(void) {
    Poly_Zq ones = {1};
    Poly_Zq poly;
    random_poly_zq(poly);

    Poly_Zq res;
    poly_mul_ntt_zq(ones, poly, res);

    for (int i = 0; i < SABER_N; ++i) {
        if (res[i] != poly[i]) {
            printf("[FAIL] check_identity_poly_ntt: coefficient %d mismatch"
                   " (got %u, expected %u)\n",
                   i, (unsigned)res[i], (unsigned)poly[i]);
            return 1;
        }
    }
    printf("[PASS] check_identity_poly_ntt\n");
    return 0;
}

// Tests x^255 * x = x^256 ≡ -1 (mod x^256+1), so result[0] = q-1 and all other coefficients zero.
static int check_negacyclic_wrap_schoolbook(void) {
    Poly_Zq a = {0};
    a[255] = 1;

    Poly_Zq b = {0};
    b[1] = 1;

    Poly_Zq res;
    poly_mul_negacyclic_zq(a, b, res);

    for (int i = 0; i < SABER_N; ++i) {
        Zq expected = (i == 0) ? (Zq)8191 : (Zq)0;
        if (res[i] != expected) {
            printf("[FAIL] check_negacyclic_wrap_schoolbook: coefficient %d"
                   " (got %u, expected %u)\n",
                   i, (unsigned)res[i], (unsigned)expected);
            return 1;
        }
    }
    printf("[PASS] check_negacyclic_wrap_schoolbook\n");
    return 0;
}

static int check_random_inputs(void) {
    Poly_Zq a;                       // Polynomial buffer for uniformly distributed coefficients in Zq
    Poly_Zq s;                       // Polynomial buffer for small (near-zero) coefficients in Zq
    Poly_Zq res_schoolbook, res_ntt; // Result buffers

    for (int i = 0; i < NUM_ITERS; ++i) {
        random_poly_zq(a);
        random_small_poly_zq(s);

        poly_mul_negacyclic_zq(a, s, res_schoolbook);
        poly_mul_ntt_zq(a, s, res_ntt);

        // Check that both versions match
        for (int j = 0; j < SABER_N; ++j) {
            if (res_schoolbook[j] != res_ntt[j]) {
                printf("[FAIL] check_random_inputs: iteration %d, coefficient %d"
                       " (schoolbook=%u, ntt=%u)\n",
                       i, j, (unsigned)res_schoolbook[j], (unsigned)res_ntt[j]);
                return 1;
            }
        }
    }

    printf("[PASS] check_random_inputs\n");
    return 0;
}

int main(void) {
    srand((unsigned)time(NULL));
    int passed = 0, total = 0;

    total++;
    if (check_zero_poly_schoolbook() == 0)
        passed++;
    total++;
    if (check_zero_poly_ntt() == 0)
        passed++;
    total++;
    if (check_identity_poly_schoolbook() == 0)
        passed++;
    total++;
    if (check_identity_poly_ntt() == 0)
        passed++;
    total++;
    if (check_negacyclic_wrap_schoolbook() == 0)
        passed++;
    total++;
    if (check_random_inputs() == 0)
        passed++;

    printf("poly_test: %d/%d passed\n", passed, total);
    return (passed == total) ? 0 : 1;
}
