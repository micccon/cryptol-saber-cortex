/*
 * Roundtrip tests for the pack_unpack.h BS<-->Poly conversion functions.
 *
 * Each test fills a polynomial (or vector) with a deterministic pattern,
 * packs it to a byte string, unpacks the byte string back, and verifies
 * every coefficient is identical to the original.
 */

#include <stdio.h>
#include <stdint.h>

#include "pack_unpack.h"
#include "params.h"
#include "types.h"

/* ---------------------------------------------------------------------------
 * Zt roundtrip: POLT2BS -> BS2POLT
 *
 * Fill Poly_Zt with (i & MASK_Zt), pack, unpack, compare.
 * For Saber: SABER_ET = 4, MASK_Zt = 0xF.
 * ---------------------------------------------------------------------------
 */
static int test_polt_roundtrip(void) {
    Poly_Zt original;
    Poly_Zt recovered;
    uint8_t packed[SABER_SCALEBYTES_KEM];

    // Populate original polynomial via bitmasking a counter
    for (int i = 0; i < SABER_N; ++i) {
        original[i] = (Zt)(i & MASK_Zt);
    }

    POLT2BS(original, packed);
    BS2POLT(recovered, packed);

    // Verify correctness of roundtrip
    for (int i = 0; i < SABER_N; ++i) {
        if (original[i] != recovered[i]) {
            printf("POLT roundtrip FAILED at coefficient %d "
                   "(expected %u, got %u)\n",
                   i, (unsigned)original[i], (unsigned)recovered[i]);
            return 1;
        }
    }

    puts("POLT  roundtrip PASSED");
    return 0;
}

/* ---------------------------------------------------------------------------
 * Z2 roundtrip: POLmsg2BS -> BS2POLmsg
 *
 * Fill Poly_Z2 with alternating 0/1 values, pack, unpack, compare.
 * For all parameter sets: MASK_Z2 = 0x1.
 * ---------------------------------------------------------------------------
 */
static int test_polmsg_roundtrip(void) {
    Poly_Z2 original;
    Poly_Z2 recovered;
    uint8_t packed[SABER_KEYBYTES];

    // Populate original polynomial with alternating pattern
    // 0b0, 0b1, 0b0, 0b1, ..., 0b0, 0b1
    for (int i = 0; i < SABER_N; ++i) {
        original[i] = (Z2)(i & MASK_Z2);
    }

    POLmsg2BS(original, packed);
    BS2POLmsg(recovered, packed);

    // Verify correctness of roundtrip
    for (int i = 0; i < SABER_N; ++i) {
        if (original[i] != recovered[i]) {
            printf("POLmsg roundtrip FAILED at coefficient %d "
                   "(expected %u, got %u)\n",
                   i, (unsigned)original[i], (unsigned)recovered[i]);
            return 1;
        }
    }

    puts("POLmsg roundtrip PASSED");
    return 0;
}

/* ---------------------------------------------------------------------------
 * Zq vector roundtrip: POLVECq2BS -> BS2POLVECq
 *
 * Fill PolyVec_Zq with ((l * SABER_N + i) & MASK_Zq), pack, unpack, compare.
 * For all parameter sets: SABER_EQ = 13, MASK_Zq = 0x1FFF.
 * ---------------------------------------------------------------------------
 */
static int test_polyvecq_roundtrip(void) {
    PolyVec_Zq original;
    PolyVec_Zq recovered;
    uint8_t packed[SABER_POLYVECBYTES];

    for (int l = 0; l < SABER_L; ++l) {
        for (int i = 0; i < SABER_N; ++i) {
            original[l][i] = (Zq)((l * SABER_N + i) & MASK_Zq);
        }
    }

    POLVECq2BS(original, packed);
    BS2POLVECq(recovered, packed);

    for (int l = 0; l < SABER_L; ++l) {
        for (int i = 0; i < SABER_N; ++i) {
            if (original[l][i] != recovered[l][i]) {
                printf("POLVECq roundtrip FAILED at poly %d, coefficient %d "
                       "(expected %u, got %u)\n",
                       l, i, (unsigned)original[l][i],
                       (unsigned)recovered[l][i]);
                return 1;
            }
        }
    }

    puts("POLVECq roundtrip PASSED");
    return 0;
}

/* ---------------------------------------------------------------------------
 * Zp vector roundtrip: POLVECp2BS -> BS2POLVECp
 *
 * Fill PolyVec_Zp with ((l * SABER_N + i) & MASK_Zp), pack, unpack, compare.
 * For all parameter sets: SABER_EP = 10, MASK_Zp = 0x3FF.
 * ---------------------------------------------------------------------------
 */
static int test_polyvec_p_roundtrip(void) {
    PolyVec_Zp original;
    PolyVec_Zp recovered;
    uint8_t packed[SABER_POLYVECCOMPRESSEDBYTES];

    for (int l = 0; l < SABER_L; ++l) {
        for (int i = 0; i < SABER_N; ++i) {
            original[l][i] = (Zp)((l * SABER_N + i) & MASK_Zp);
        }
    }

    POLVECp2BS(original, packed);
    BS2POLVECp(recovered, packed);

    for (int l = 0; l < SABER_L; ++l) {
        for (int i = 0; i < SABER_N; ++i) {
            if (original[l][i] != recovered[l][i]) {
                printf("POLVECp roundtrip FAILED at poly %d, coefficient %d "
                       "(expected %u, got %u)\n",
                       l, i, (unsigned)original[l][i],
                       (unsigned)recovered[l][i]);
                return 1;
            }
        }
    }

    puts("POLVECp roundtrip PASSED");
    return 0;
}

// Driver for all `pack_unpack` unit tests
int main(void) {
    int failed = 0;

    failed |= test_polt_roundtrip();
    failed |= test_polmsg_roundtrip();
    failed |= test_polyvecq_roundtrip();
    failed |= test_polyvec_p_roundtrip();

    if (failed) {
        puts("pack_unpack roundtrip tests FAILED");
        return 1;
    }

    puts("All pack_unpack roundtrip tests PASSED");
    return 0;
}
