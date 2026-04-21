#include <stdio.h>
#include <string.h>

#include "poly.h"

static int check_zq_case(void) {
    static const Poly_Zq a = {
        [0] = 1,
        [2] = 2,
        [SABER_N - 1] = 3
    };
    static const Poly_Zq b = {
        [0] = 4,
        [1] = 5,
        [SABER_N - 1] = 6
    };
    static const Poly_Zq expected = {
        [0] = 8181,
        [1] = 8185,
        [2] = 8,
        [3] = 10,
        [SABER_N - 2] = 8174,
        [SABER_N - 1] = 18
    };
    Poly_Zq actual = {0};
    size_t i;

    poly_mul_negacyclic_zq(a, b, actual);

    if (memcmp(actual, expected, sizeof(expected)) != 0) {
        for (i = 0; i < SABER_N; ++i) {
            if (actual[i] != expected[i]) {
                printf("zq test failed at coefficient %zu: got %u, expected %u\n",
                       i,
                       (unsigned)actual[i],
                       (unsigned)expected[i]);
                break;
            }
        }
        return 1;
    }

    return 0;
}

static int check_zp_case(void) {
    static const Poly_Zp a = {
        [0] = 1,
        [2] = 2,
        [SABER_N - 1] = 3
    };
    static const Poly_Zp b = {
        [0] = 4,
        [1] = 5,
        [SABER_N - 1] = 6
    };
    static const Poly_Zp expected = {
        [0] = 1013,
        [1] = 1017,
        [2] = 8,
        [3] = 10,
        [SABER_N - 2] = 1006,
        [SABER_N - 1] = 18
    };
    Poly_Zp actual = {0};
    size_t i;

    poly_mul_negacyclic_zp(a, b, actual);

    if (memcmp(actual, expected, sizeof(expected)) != 0) {
        for (i = 0; i < SABER_N; ++i) {
            if (actual[i] != expected[i]) {
                printf("zp test failed at coefficient %zu: got %u, expected %u\n",
                       i,
                       (unsigned)actual[i],
                       (unsigned)expected[i]);
                break;
            }
        }
        return 1;
    }

    return 0;
}

int main(void) {
    if (check_zq_case() != 0) {
        return 1;
    }

    if (check_zp_case() != 0) {
        return 1;
    }

    puts("poly negacyclic multiplication tests passed");
    return 0;
}
