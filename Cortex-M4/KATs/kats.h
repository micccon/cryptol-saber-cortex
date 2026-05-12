#ifndef KATS_H
#define KATS_H

#include <stddef.h>
#include <stdint.h>

#include "params.h"

typedef struct {
    int count;
    uint8_t seed[48];
} req_case_t;

#endif
