#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "randombytes.h"

static void print_hex(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; ++i)
        printf("%02x", buf[i]);
    putchar('\n');
}

static const uint8_t kat_seed[48] = {0x06, 0x15, 0x50, 0x23, 0x4d, 0x15, 0x8c, 0x5e, 0xc9, 0x55, 0x95, 0xfe,
                                     0x04, 0xef, 0x7a, 0x25, 0x76, 0x7f, 0x2e, 0x24, 0xcc, 0x2b, 0xc4, 0x79,
                                     0xd0, 0x9d, 0x86, 0xdc, 0x9a, 0xbc, 0xfd, 0xe7, 0x05, 0x6a, 0x8c, 0x26,
                                     0x6f, 0x9e, 0xf9, 0x7e, 0xd0, 0x85, 0x41, 0xdb, 0xd2, 0xe1, 0xff, 0xa1};
static const uint8_t expected_seed_a[32] = {0x7c, 0x99, 0x35, 0xa0, 0xb0, 0x76, 0x94, 0xaa, 0x0c, 0x6d, 0x10,
                                            0xe4, 0xdb, 0x6b, 0x1a, 0xdd, 0x2f, 0xd8, 0x1a, 0x25, 0xcc, 0xb1,
                                            0x48, 0x03, 0x2d, 0xcd, 0x73, 0x99, 0x36, 0x73, 0x7f, 0x2d};
static const uint8_t expected_seed_s[32] = {0x86, 0x26, 0xed, 0x79, 0xd4, 0x51, 0x14, 0x08, 0x00, 0xe0, 0x3b,
                                            0x59, 0xb9, 0x56, 0xf8, 0x21, 0x0e, 0x55, 0x60, 0x67, 0x40, 0x7d,
                                            0x13, 0xdc, 0x90, 0xfa, 0x9e, 0x8b, 0x87, 0x2b, 0xfb, 0x8f};
static const uint8_t expected_z[32] = {0x14, 0x7c, 0x03, 0xf7, 0xa5, 0xbe, 0xbb, 0xa4, 0x06, 0xc8, 0xfa,
                                       0xe1, 0x87, 0x4d, 0x7f, 0x13, 0xc8, 0x0e, 0xfe, 0x79, 0xa3, 0xa9,
                                       0xa8, 0x74, 0xcc, 0x09, 0xfe, 0x76, 0xf6, 0x99, 0x76, 0x15};
static const uint8_t expected_m[32] = {0xc8, 0x2c, 0xe0, 0x50, 0xa6, 0xdd, 0x85, 0xfe, 0xa6, 0x3d, 0xd0,
                                       0x65, 0x6a, 0xf1, 0x46, 0xb1, 0x88, 0x0f, 0x91, 0xab, 0xc0, 0x07,
                                       0x2c, 0x92, 0xa9, 0xda, 0x17, 0x78, 0x76, 0x9c, 0x46, 0x61};

static int check_drbg_smoke_test(void) {
    uint8_t seed_a[32], seed_s[32], z[32], m[32];

    randombytes_init((uint8_t *)kat_seed, NULL, 256);
    randombytes(seed_a, sizeof(seed_a));
    randombytes(seed_s, sizeof(seed_s));
    randombytes(z, sizeof(z));
    randombytes(m, sizeof(m));

    if (memcmp(seed_a, expected_seed_a, sizeof(seed_a)) != 0) {
        printf("[FAIL] check_drbg_smoke_test: seedA mismatch\n");
        printf("       got:      ");
        print_hex(seed_a, sizeof(seed_a));
        printf("       expected: ");
        print_hex(expected_seed_a, sizeof(expected_seed_a));
        return 1;
    }
    if (memcmp(seed_s, expected_seed_s, sizeof(seed_s)) != 0) {
        printf("[FAIL] check_drbg_smoke_test: seedS mismatch\n");
        printf("       got:      ");
        print_hex(seed_s, sizeof(seed_s));
        printf("       expected: ");
        print_hex(expected_seed_s, sizeof(expected_seed_s));
        return 1;
    }
    if (memcmp(z, expected_z, sizeof(z)) != 0) {
        printf("[FAIL] check_drbg_smoke_test: z mismatch\n");
        printf("       got:      ");
        print_hex(z, sizeof(z));
        printf("       expected: ");
        print_hex(expected_z, sizeof(expected_z));
        return 1;
    }
    if (memcmp(m, expected_m, sizeof(m)) != 0) {
        printf("[FAIL] check_drbg_smoke_test: m mismatch\n");
        printf("       got:      ");
        print_hex(m, sizeof(m));
        printf("       expected: ");
        print_hex(expected_m, sizeof(expected_m));
        return 1;
    }
    printf("[PASS] check_drbg_smoke_test\n");
    return 0;
}

int main(void) {
    int passed = 0, total = 0;

    total++;
    if (check_drbg_smoke_test() == 0)
        passed++;

    printf("randombytes_test: %d/%d passed\n", passed, total);
    return (passed == total) ? 0 : 1;
}
