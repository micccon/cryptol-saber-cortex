/*
 * Roundtrip tests for the pack_unpack.h BS<-->Poly conversion functions.
 *
 * Each test fills a polynomial (or vector) with a deterministic pattern,
 * packs it to a byte string, unpacks the byte string back, and verifies
 * every coefficient is identical to the original.
 */

#include <stdint.h>
#include <stdio.h>

#include "pack_unpack.h"
#include "params.h"
#include "types.h"

static int test_polt_roundtrip(void) {
    Poly_Zt original;
    Poly_Zt recovered;
    uint8_t packed[SABER_SCALEBYTES_KEM];

    for (int i = 0; i < SABER_N; ++i)
        original[i] = (Zt)(i & MASK_Zt);

    POLT2BS(original, packed);
    BS2POLT(recovered, packed);

    for (int i = 0; i < SABER_N; ++i) {
        if (original[i] != recovered[i]) {
            printf("[FAIL] test_polt_roundtrip: coefficient %d"
                   " (expected %u, got %u)\n",
                   i, (unsigned)original[i], (unsigned)recovered[i]);
            return 1;
        }
    }
    printf("[PASS] test_polt_roundtrip\n");
    return 0;
}

static int test_polmsg_roundtrip(void) {
    Poly_Z2 original;
    Poly_Z2 recovered;
    uint8_t packed[SABER_KEYBYTES];

    for (int i = 0; i < SABER_N; ++i)
        original[i] = (Z2)(i & MASK_Z2);

    POLmsg2BS(original, packed);
    BS2POLmsg(recovered, packed);

    for (int i = 0; i < SABER_N; ++i) {
        if (original[i] != recovered[i]) {
            printf("[FAIL] test_polmsg_roundtrip: coefficient %d"
                   " (expected %u, got %u)\n",
                   i, (unsigned)original[i], (unsigned)recovered[i]);
            return 1;
        }
    }
    printf("[PASS] test_polmsg_roundtrip\n");
    return 0;
}

static int test_polyvecq_roundtrip(void) {
    PolyVec_Zq original;
    PolyVec_Zq recovered;
    uint8_t packed[SABER_POLYVECBYTES];

    for (int l = 0; l < SABER_L; ++l)
        for (int i = 0; i < SABER_N; ++i)
            original[l][i] = (Zq)((l * SABER_N + i) & MASK_Zq);

    POLVECq2BS(original, packed);
    BS2POLVECq(recovered, packed);

    for (int l = 0; l < SABER_L; ++l) {
        for (int i = 0; i < SABER_N; ++i) {
            if (original[l][i] != recovered[l][i]) {
                printf("[FAIL] test_polyvecq_roundtrip: poly %d coefficient %d"
                       " (expected %u, got %u)\n",
                       l, i, (unsigned)original[l][i], (unsigned)recovered[l][i]);
                return 1;
            }
        }
    }
    printf("[PASS] test_polyvecq_roundtrip\n");
    return 0;
}

static int test_polyvec_p_roundtrip(void) {
    PolyVec_Zp original;
    PolyVec_Zp recovered;
    uint8_t packed[SABER_POLYVECCOMPRESSEDBYTES];

    for (int l = 0; l < SABER_L; ++l)
        for (int i = 0; i < SABER_N; ++i)
            original[l][i] = (Zp)((l * SABER_N + i) & MASK_Zp);

    POLVECp2BS(original, packed);
    BS2POLVECp(recovered, packed);

    for (int l = 0; l < SABER_L; ++l) {
        for (int i = 0; i < SABER_N; ++i) {
            if (original[l][i] != recovered[l][i]) {
                printf("[FAIL] test_polyvec_p_roundtrip: poly %d coefficient %d"
                       " (expected %u, got %u)\n",
                       l, i, (unsigned)original[l][i], (unsigned)recovered[l][i]);
                return 1;
            }
        }
    }
    printf("[PASS] test_polyvec_p_roundtrip\n");
    return 0;
}

int main(void) {
    int passed = 0, total = 0;

    total++;
    if (test_polt_roundtrip() == 0)
        passed++;
    total++;
    if (test_polmsg_roundtrip() == 0)
        passed++;
    total++;
    if (test_polyvecq_roundtrip() == 0)
        passed++;
    total++;
    if (test_polyvec_p_roundtrip() == 0)
        passed++;

    printf("pack_unpack_test: %d/%d passed\n", passed, total);
    return (passed == total) ? 0 : 1;
}
