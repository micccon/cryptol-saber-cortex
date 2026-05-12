#include "helpers.h"

#include <string.h>

uint32_t load32_le(const uint8_t bytes[4]) {
    return ((uint32_t)bytes[0]) | ((uint32_t)bytes[1] << 8) | ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

void store32_le(uint8_t bytes[4], uint32_t word) {
    bytes[0] = (uint8_t)word;
    bytes[1] = (uint8_t)(word >> 8);
    bytes[2] = (uint8_t)(word >> 16);
    bytes[3] = (uint8_t)(word >> 24);
}

void shift_right_u16(uint16_t *output, const uint16_t *input, size_t count, uint8_t shift) {
    for (size_t i = 0; i < count; ++i) {
        output[i] = (uint16_t)(input[i] >> shift);
    }
}

void shift_left_u16(uint16_t *output, const uint16_t *input, size_t count, uint8_t shift) {
    for (size_t i = 0; i < count; ++i) {
        output[i] = (uint16_t)(input[i] << shift);
    }
}

void transpose_matrix(PolyMatrix_Zq A) {
    // Swap upper triangle with lower triangle; diagonal polys are unchanged.
    for (size_t i = 0; i < SABER_L; ++i) {
        for (size_t j = i + 1; j < SABER_L; ++j) {
            Poly_Zq tmp;
            memcpy(tmp, A[i][j], sizeof(Poly_Zq));
            memcpy(A[i][j], A[j][i], sizeof(Poly_Zq));
            memcpy(A[j][i], tmp, sizeof(Poly_Zq));
        }
    }
}

void unpack_bit_string(const uint8_t *input_bytes, uint8_t *output_elements, uint16_t num_elements,
                       uint8_t bits_per_element) {
    uint16_t global_bit_index = 0;
    for (int i = 0; i < num_elements; i++) {
        uint8_t element = 0;
        for (int j = 0; j < bits_per_element; ++j) {
            int bit_pos = global_bit_index + j;
            int byte_index = bit_pos / 8;
            int bit_in_byte = 7 - (bit_pos % 8);
            int bit_value = (input_bytes[byte_index] >> bit_in_byte) & 1;
            element |= (bit_value << (bits_per_element - 1 - j));
        }
        output_elements[i] = element;
        global_bit_index += bits_per_element;
    }
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
