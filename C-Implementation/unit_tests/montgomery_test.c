/*
 * This is a test script for ensuring the correctness of the Montgomery multiplication, reduction,
 * and conversion functions. Three main things are checked:
 *
 *    1) That converting an integer a ∈ [0, q') into Montgomery space, and then recovering a from its
 *       Montgomery space representative â ∈ [0, q'), correctly works (i.e., roundtrip correctness of
 *       going to, and then coming back from, Montgomery space).
 *    2) That performing naive modular multiplication a * b (mod q') where a, b ∈ [0, q') yields the same
 *       result as the Montgomery multiplication â * b̂ * R^{-1} (mod q').
 *    3) That performing multiple chained multiplications a * b * c * d (mod q') naively where a, b, c, d ∈ [0, q')
 *       yields the same result as the chained Montgomery multiplications:
 *       (from_montgomery(montgomery_multiply(montgomery_multiply(montgomery_multiply(â, b̂), ĉ), d̂))
 *     ≡ a * b * c * d * (mod q')
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "ntt_helpers.h"

#define NUM_ITERS 10000

int main(void) {
    srand(time(NULL));

    uint32_t a, b, c, d;
    uint32_t montA, montB, montC, montD;
    uint32_t aTimesB, fourWayProduct;

    for (int i = 0; i < NUM_ITERS; ++i) {
        a = rand() % NTT_Q;
        b = rand() % NTT_Q;
        c = rand() % NTT_Q;
        d = rand() % NTT_Q;
        montA = to_montgomery(a);
        montB = to_montgomery(b);
        montC = to_montgomery(c);
        montD = to_montgomery(d);
        aTimesB = ((uint64_t)a * (uint64_t)b) % NTT_Q;
        fourWayProduct = ((uint64_t)a * (uint64_t)b) % NTT_Q;
        fourWayProduct = ((uint64_t)fourWayProduct * (uint64_t)c) % NTT_Q;
        fourWayProduct = ((uint64_t)fourWayProduct * (uint64_t)d) % NTT_Q;

        // Check Montgomery roundtrip correctness on 1/4 of all random numbers
        if (a != (from_montgomery(montA))) {
            printf("Roundtrip check failed on iteration %d\n"
                   "a = %d\n"
                   "to_montgomery(a) = %d\n"
                   "from_montgomery(to_montgomery(a)) = %d\n",
                   i, a, montA, from_montgomery(montA));
            return 1;
        }

        // Check that a * b (mod q') == â * b̂ * R^{-1} (mod q')
        if (aTimesB != from_montgomery(montgomery_multiply(montA, montB))) {
            printf("Two-way product check failed on iteration %d\n"
                   "a * b = %d\n"
                   "from_montgomery(montgomery_multiply(montA, montB)) = %d\n",
                   i, aTimesB, from_montgomery(montgomery_multiply(montA, montB)));
            return 1;
        }

        // Check that a * b * c * d (mod q') == ((((â * b̂) * R^{-1}) * ĉ) * R^{-1} * d̂) * R^{-1}
        int32_t montFourWayProduct =
            montgomery_multiply(montgomery_multiply(montgomery_multiply(montA, montB), montC), montD);

        if (fourWayProduct != from_montgomery(montFourWayProduct)) {
            printf("Four-way product check failed on iteration %d\n"
                   "a = %d, b = %d, c = %d, d = %d\n"
                   "Expected (naive):         a * b * c * d (mod q') = %d\n"
                   "Got (Montgomery): from_montgomery(â * b̂ * ĉ * d̂) = %d\n",
                   i, a, b, c, d, fourWayProduct, from_montgomery(montFourWayProduct));
            return 1;
        }
    }

    printf("All checks PASSED\n");

    return 0;
}
