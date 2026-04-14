#include <stdint.h>
#include <time.h>
#include "cpucycles.h"

uint64_t cpucycles(void) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return (uint64_t)t.tv_sec * 1000000000ULL + t.tv_nsec;
}