/*
 * Correctness tests for the Montgomery arithmetic helpers.
 *
 *  1. check_montgomery_roundtrip  — to_montgomery / from_montgomery are inverses.
 *  2. check_two_way_product       — montgomery_multiply agrees with naive a*b mod q'.
 *  3. check_four_way_product      — four chained montgomery_multiplys agree with naive.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "ntt_helpers.h"

#define NUM_ITERS 10000

static int check_montgomery_roundtrip(void) {
    for (int i = 0; i < NUM_ITERS; ++i) {
        uint32_t a = (uint32_t)rand() % NTT_Q;
        uint32_t mont = to_montgomery(a);

        if (from_montgomery(mont) != a) {
            printf("[FAIL] check_montgomery_roundtrip: iteration %d:"
                   " a=%u, to_mont=%u, from_mont(to_mont)=%u\n",
                   i, a, mont, from_montgomery(mont));
            return 1;
        }
    }
    printf("[PASS] check_montgomery_roundtrip\n");
    return 0;
}

static int check_two_way_product(void) {
    for (int i = 0; i < NUM_ITERS; ++i) {
        uint32_t a = (uint32_t)rand() % NTT_Q;
        uint32_t b = (uint32_t)rand() % NTT_Q;
        uint32_t expected = (uint32_t)(((uint64_t)a * b) % NTT_Q);
        uint32_t got = from_montgomery(montgomery_multiply(to_montgomery(a), to_montgomery(b)));

        if (got != expected) {
            printf("[FAIL] check_two_way_product: iteration %d:"
                   " a*b=%u, from_mont(mont_mul)=%u\n",
                   i, expected, got);
            return 1;
        }
    }
    printf("[PASS] check_two_way_product\n");
    return 0;
}

static int check_four_way_product(void) {
    for (int i = 0; i < NUM_ITERS; ++i) {
        uint32_t a = (uint32_t)rand() % NTT_Q;
        uint32_t b = (uint32_t)rand() % NTT_Q;
        uint32_t c = (uint32_t)rand() % NTT_Q;
        uint32_t d = (uint32_t)rand() % NTT_Q;

        uint32_t expected = (uint32_t)(((uint64_t)a * b) % NTT_Q);
        expected = (uint32_t)(((uint64_t)expected * c) % NTT_Q);
        expected = (uint32_t)(((uint64_t)expected * d) % NTT_Q);

        uint32_t got = from_montgomery(montgomery_multiply(
            montgomery_multiply(montgomery_multiply(to_montgomery(a), to_montgomery(b)), to_montgomery(c)),
            to_montgomery(d)));

        if (got != expected) {
            printf("[FAIL] check_four_way_product: iteration %d:"
                   " a=%u b=%u c=%u d=%u, expected=%u, got=%u\n",
                   i, a, b, c, d, expected, got);
            return 1;
        }
    }
    printf("[PASS] check_four_way_product\n");
    return 0;
}

int main(void) {
    srand((unsigned)time(NULL));
    int passed = 0, total = 0;

    total++;
    if (check_montgomery_roundtrip() == 0)
        passed++;
    total++;
    if (check_two_way_product() == 0)
        passed++;
    total++;
    if (check_four_way_product() == 0)
        passed++;

    printf("montgomery_test: %d/%d passed\n", passed, total);
    return (passed == total) ? 0 : 1;
}
