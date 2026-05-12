#ifndef CPUCYCLES_H
#define CPUCYCLES_H

#if defined(__x86_64__) || defined(_M_X64)
long long cpucycles(void);
#endif

#endif