#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "poly.h"

static void random_poly_zq(Poly_Zq poly) {
    for (int i = 0; i < SABER_N; ++i) {
        poly[i] = rand() & MASK_Zq;
    }
}

static void random_poly_zp(Poly_Zp poly) {
    for (int i = 0; i < SABER_N; ++i) {
        poly[i] = rand() & MASK_Zp;
    }
}

static int check_zero_poly_schoolbook() {
    Poly_Zq zeroes = {0};
    Poly_Zq poly;
    random_poly_zq(poly);

    Poly_Zq res;
    poly_mul_negacyclic_zq(zeroes, poly, res);

    for (int i = 0; i < SABER_N; ++i) {
        if (res[i] != 0)
            return 1;
    }

    return 0;
}

static int check_identity_poly_schoolbook() {
    Poly_Zq ones = {1};
    Poly_Zq poly;
    random_poly_zq(poly);

    Poly_Zq res;
    poly_mul_negacyclic_zq(ones, poly, res);

    for (int i = 0; i < SABER_N; ++i) {
        if (res[i] != poly[i])
            return 1;
    }

    return 0;
}

// This is testing multiplying x^{255} * x, which is x^{256}. This should reduce to -1, which is
// q - 1 in SABER's ring.
static int check_negacyclic_wrap_schoolbook() {
    Poly_Zq a = {0};
    a[255] = 1;

    Poly_Zq b = {0};
    b[1] = 1;

    Poly_Zq res;
    poly_mul_negacyclic_zq(a, b, res);

    for (int i = 0; i < SABER_N; ++i) {
        Zq expected = (i == 0) ? 8191 : 0;
        if (res[i] != expected)
            return 1;
    }

    return 0;
}

int main(void) {
    int res = 0;
    if ((res |= check_zero_poly_schoolbook()))
        printf("check_zero_poly_schoolbook        FAILED\n");
    if ((res |= check_identity_poly_schoolbook()))
        printf("check_identity_poly_schoolbook    FAILED\n");
    if ((res |= check_negacyclic_wrap_schoolbook()))
        printf("check_negacyclic_wrap_schoolbook  FAILED\n");

    if (res == 0)
        printf("ALL CHECKS PASSED\n");

    return (res | 0);
}
