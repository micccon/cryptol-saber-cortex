#include "helpers.h"

uint32_t load32_le(const uint8_t bytes[4]) {
    return ((uint32_t)bytes[0]) |
           ((uint32_t)bytes[1] << 8) |
           ((uint32_t)bytes[2] << 16) |
           ((uint32_t)bytes[3] << 24);
}

void store32_le(uint8_t bytes[4], uint32_t word) {
    bytes[0] = (uint8_t)word;
    bytes[1] = (uint8_t)(word >> 8);
    bytes[2] = (uint8_t)(word >> 16);
    bytes[3] = (uint8_t)(word >> 24);
}

uint32_t hamming_weight(uint8_t bytes[], uint32_t size) {
    uint8_t cur;
    uint8_t mask = 0x01;
    uint32_t result = 0;
    for (int i = 0; i < size; i++) {
        cur = bytes[i];
        for (int j = 0; j < 8; j++) {
            result += cur & mask;
            cur = cur >> 1;
        }
    }

    return result;
}

int verify(const uint8_t *a, const uint8_t *b, size_t size) {
    uint64_t diff = 0;

    for (size_t i = 0; i < size; ++i) {
        diff |= a[i] ^ b[i];
    }

    diff = (uint64_t)(-(int64_t)diff) >> 63;
    return (int)diff;
}

void cmov(uint8_t *dst, const uint8_t *src, size_t size, uint8_t b) {
    b = (uint8_t)(-((int)b));

    for (size_t i = 0; i < size; ++i) {
        dst[i] ^= b & (src[i] ^ dst[i]);
    }
}
