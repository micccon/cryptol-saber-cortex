#include <stdio.h>
#include <stdint.h>

#include "arithmetic.h"

typedef struct {
    size_t row;
    size_t col;
    size_t coeff;
    Zq expected;
} matrix_check_t;

static int check_gen_matrix(void) {
    static const uint8_t seed[SABER_SEEDBYTES] = {
        0, 1, 2, 3, 4, 5, 6, 7,
        8, 9, 10, 11, 12, 13, 14, 15,
        16, 17, 18, 19, 20, 21, 22, 23,
        24, 25, 26, 27, 28, 29, 30, 31
    };
    static const matrix_check_t checks[] = {
        {0, 0, 0, 2566}, {0, 0, 1, 2483}, {0, 0, 2, 4487}, {0, 0, 3, 4331},
        {0, 0, 4, 1391}, {0, 0, 5, 1767}, {0, 0, 6, 3843}, {0, 0, 7, 1189},
        {0, 0, 254, 7555}, {0, 0, 255, 2720},
        {0, 1, 0, 2785}, {0, 1, 1, 590}, {0, 1, 2, 116}, {0, 1, 3, 3268},
        {0, 1, 4, 6129}, {0, 1, 5, 5806}, {0, 1, 6, 7550}, {0, 1, 7, 1647},
        {0, 1, 254, 1008}, {0, 1, 255, 8114},
        {0, 2, 0, 3675}, {0, 2, 1, 6654}, {0, 2, 2, 3154}, {0, 2, 3, 1945},
        {0, 2, 4, 7540}, {0, 2, 5, 2557}, {0, 2, 6, 861}, {0, 2, 7, 2900},
        {0, 2, 254, 6088}, {0, 2, 255, 5035},
        {1, 0, 0, 3830}, {1, 0, 1, 7533}, {1, 0, 2, 1622}, {1, 0, 3, 4345},
        {1, 0, 4, 7178}, {1, 0, 5, 1716}, {1, 0, 6, 6495}, {1, 0, 7, 2388},
        {1, 0, 254, 213}, {1, 0, 255, 1953},
        {1, 1, 0, 2928}, {1, 1, 1, 6345}, {1, 1, 2, 554}, {1, 1, 3, 4883},
        {1, 1, 4, 5518}, {1, 1, 5, 6663}, {1, 1, 6, 173}, {1, 1, 7, 5591},
        {1, 1, 254, 7857}, {1, 1, 255, 1089},
        {1, 2, 0, 8026}, {1, 2, 1, 2757}, {1, 2, 2, 3571}, {1, 2, 3, 4895},
        {1, 2, 4, 3041}, {1, 2, 5, 949}, {1, 2, 6, 870}, {1, 2, 7, 6184},
        {1, 2, 254, 7672}, {1, 2, 255, 6224},
        {2, 0, 0, 1641}, {2, 0, 1, 7923}, {2, 0, 2, 6496}, {2, 0, 3, 6025},
        {2, 0, 4, 7514}, {2, 0, 5, 2195}, {2, 0, 6, 6776}, {2, 0, 7, 1625},
        {2, 0, 254, 7608}, {2, 0, 255, 4461},
        {2, 1, 0, 4298}, {2, 1, 1, 1680}, {2, 1, 2, 5590}, {2, 1, 3, 7630},
        {2, 1, 4, 4423}, {2, 1, 5, 2700}, {2, 1, 6, 6970}, {2, 1, 7, 3677},
        {2, 1, 254, 3731}, {2, 1, 255, 886},
        {2, 2, 0, 1856}, {2, 2, 1, 3224}, {2, 2, 2, 6861}, {2, 2, 3, 4701},
        {2, 2, 4, 850}, {2, 2, 5, 7364}, {2, 2, 6, 5439}, {2, 2, 7, 2803},
        {2, 2, 254, 6389}, {2, 2, 255, 2061}
    };
    PolyMatrix_Zq result;
    size_t i;

    gen_matrix(seed, result);

    for (i = 0; i < sizeof(checks) / sizeof(checks[0]); ++i) {
        const matrix_check_t check = checks[i];

        if (result[check.row][check.col][check.coeff] != check.expected) {
            printf("gen_matrix failed at [%zu][%zu][%zu]: got %u, expected %u\n",
                   check.row,
                   check.col,
                   check.coeff,
                   (unsigned)result[check.row][check.col][check.coeff],
                   (unsigned)check.expected);
            return 1;
        }
    }

    return 0;
}

static int check_inner_prod(void) {
    PolyVec_Zp a = {0};
    PolyVec_Zp b = {0};
    Poly_Zp result;
    size_t i;
    static const Poly_Zp expected = {
        [0] = 1001,
        [1] = 63,
        [2] = 1000,
        [3] = 188,
        [4] = 22,
        [5] = 312,
        [7] = 350,
        [8] = 60,
        [9] = 231,
        [10] = 126,
        [11] = 84,
        [12] = 219,
        [14] = 162,
        [16] = 90,
        [254] = 988,
        [255] = 42
    };

    a[0][0] = 1;
    a[0][3] = 2;
    a[0][SABER_N - 1] = 3;
    a[1][1] = 4;
    a[1][5] = 5;
    a[1][9] = 6;
    a[2][2] = 7;
    a[2][4] = 8;
    a[2][6] = 9;

    b[0][0] = 10;
    b[0][1] = 11;
    b[0][SABER_N - 1] = 12;
    b[1][0] = 13;
    b[1][2] = 14;
    b[1][7] = 15;
    b[2][1] = 16;
    b[2][3] = 17;
    b[2][8] = 18;

    inner_prod(a, b, result);

    for (i = 0; i < SABER_N; ++i) {
        if (result[i] != expected[i]) {
            printf("inner_prod failed at coefficient %zu: got %u, expected %u\n",
                   i,
                   (unsigned)result[i],
                   (unsigned)expected[i]);
            return 1;
        }
    }

    return 0;
}

int main(void) {
    if (check_gen_matrix() != 0) {
        return 1;
    }

    if (check_inner_prod() != 0) {
        return 1;
    }

    puts("arithmetic tests passed");
    return 0;
}
