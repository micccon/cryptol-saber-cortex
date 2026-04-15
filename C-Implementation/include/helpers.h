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
 * @param size Length of input bytes array in bytes
 */
uint32_t hamming_weight(uint8_t bytes[], uint32_t size);

#endif
