#ifndef HELPERS_H
#define HELPERS_H

#include <stdint.h>

/**
 * Helper functions for byte-level packing and unpacking of polynomial coefficients.
 *
 * @param bytes Input byte array for loading, or output byte array for storing
 */
uint32_t load32_le(const uint8_t bytes[4]);

/**
 * Helper function to store a 32-bit word into a byte array in little-endian order.
 *
 * @param bytes Output byte array (must have space for at least 4 bytes)
 * @param word 32-bit word to store
 */
void store32_le(uint8_t bytes[4], uint32_t word);

/**
 * Calculates the hamming weight of a bit string represented as a byte array.
 *
 * @param bytes Input array for calculating the hamming weight
 * @param num_bits number of bits to calculate the weight of
 */
int hamming_weight(uint8_t *bytes, uint32_t num_bits);

/**
 * Unpacks a bit string represented as a contiguous byte string with up to 8 bits per unpacked element.
 *
 * @param input_bytes
 * @param input_length in bytes
 * @param output_elements
 * @param num_elements
 * @param bits_per_element
 */
void unpack_bit_string(const uint8_t *input_bytes, uint8_t *output_elements, uint16_t num_elements,
                       uint8_t bits_per_element);

#endif
