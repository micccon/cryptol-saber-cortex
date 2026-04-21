/*
 * Utility functions shared across the Saber implementation.
 *
 * Declares the following helpers:
 *   - load32_le / store32_le:  little-endian 32-bit word packing and unpacking
 *   - transpose_matrix:        in-place transpose of a PolyMatrix_Zq
 *   - hamming_weight:          population count over a byte array
 *   - unpack_bit_string:       unpack a packed bit string into an element array
 *   - verify:                  constant-time byte-string comparison
 *   - cmov:                    constant-time conditional move
 *
 * Depends on: types.h
 */

#ifndef HELPERS_H
#define HELPERS_H

#include "types.h"

#include <stddef.h>
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
 * Computes the transpose of a polynomial matrix over Zq.
 *
 * @param input Input matrix
 * @param result Output buffer for the transposed matrix
 */
void transpose_matrix(PolyMatrix_Zq input, PolyMatrix_Zq result);

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

/**
 * Compares two byte strings of the same length.
 *
 * Returns 0 when the inputs are equal and 1 otherwise.
 *
 * @param a First byte string
 * @param b Second byte string
 * @param size Number of bytes to compare
 */
int verify(const uint8_t *a, const uint8_t *b, size_t size);

/**
 * Conditionally moves bytes from src into dst in constant time.
 *
 * If b == 1, dst is replaced with src. If b == 0, dst is unchanged.
 *
 * @param dst Destination byte string
 * @param src Source byte string
 * @param size Number of bytes to process
 * @param b Conditional move flag (0 or 1)
 */
void cmov(uint8_t *dst, const uint8_t *src, size_t size, uint8_t b);

#endif
