#ifndef HELPERS_H
#define HELPERS_H

#include <stdint.h>

uint32_t load32_le(const uint8_t bytes[4]);
void store32_le(uint8_t bytes[4], uint32_t word);

#endif
