#if defined(__x86_64__) || defined(_M_X64)

#include "cpucycles.h"

long long cpucycles(void) {
    unsigned long long result;
    asm volatile(".byte 15;.byte 49;shlq $32,%%rdx;orq %%rdx,%%rax" : "=a"(result)::"%rdx");
    return result;
}

#endif
