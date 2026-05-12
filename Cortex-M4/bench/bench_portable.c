/*
 * This is a benchmarking script to gather average times (in usecs)
 * per each KEM operation (KeyGen, Encaps, and Decaps). In order to make
 * this as portable as possible, this script DOES NOT measure CPU cycles,
 * nor does it attempt to estimate CPU cycles.
 *
 * The sole purpose of this script is to provide a portable benchmark using
 * time as a metric. For CPU cycles, there is a separate benchmarking script
 * for x86-64 processors, in which the `rdtsc` (Read Time-Stamp Counter)
 * instruction is used. However, such a script inherently won't run on non-x86
 * processors, nor is there an analogous way to measure CPU cycles on non-x86
 * processor; hence, this benchmark exists.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// clang-format off
#ifdef _WIN32
#   include <windows.h>
#else
#   include <sys/utsname.h>
#endif
// clang-format on

#include "kem.h"

#define NUM_ITERS 1000
#define NSECS_PER_SEC 1000000000LL
#define NSECS_PER_USEC 1000.0

void init_rng() {
    unsigned char entropy_input[48];

    time_t t;
    srand((unsigned)time(&t)); // Seed RNG w/ current time

    for (int i = 0; i < 48; ++i) {
        entropy_input[i] = rand() % 256; // Populate entropy buffer
    }

    randombytes_init(entropy_input, NULL, 256);
}

void print_sys_info() {
#ifdef _WIN32
    SYSTEM_INFO siSysInfo;
    GetSystemInfo(&siSysInfo);

    const char *arch;
    switch (siSysInfo.wProcessorArchitecture) {
    case PROCESSOR_ARCHITECTURE_AMD64:
        arch = "x86_64";
        break;
    case PROCESSOR_ARCHITECTURE_ARM64:
        arch = "arm64";
        break;
    case PROCESSOR_ARCHITECTURE_INTEL:
        arch = "x86";
        break;
    default:
        arch = "unknown";
        break;
    }

    OSVERSIONINFOEX osInfo;
    ZeroMemory(&osInfo, sizeof(OSVERSIONINFOEX));
    osInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
    GetVersionEx((LPOSVERSIONINFO)&osInfo);

    printf("---SYSTEM INFO---\n"
           "Machine: %s\n"
           "System Name: Windows\n"
           "Release: %lu.%lu\n",
           arch, osInfo.dwMajorVersion, osInfo.dwMinorVersion);
#else
    struct utsname unameData;
    uname(&unameData);
    printf("---SYSTEM INFO---\n"
           "Machine: %s\n"
           "System Name: %s\n"
           "Release: %s\n",
           unameData.machine, unameData.sysname, unameData.release);
#endif
}

void print_totals(uint64_t keygen_total, uint64_t encaps_total, uint64_t decaps_total) {
    double keygen_total_us = (double)keygen_total / NSECS_PER_USEC;
    double encaps_total_us = (double)encaps_total / NSECS_PER_USEC;
    double decaps_total_us = (double)decaps_total / NSECS_PER_USEC;
    printf("---Total Accumulated Timings (in microseconds)---\n"
           "KEM.KeyGen:\t%.3f us\n"
           "KEM.Encaps:\t%.3f us\n"
           "KEM.Decaps:\t%.3f us\n",
           keygen_total_us, encaps_total_us, decaps_total_us);
}

void print_averages(double keygen_avg, double encaps_avg, double decaps_avg) {
    double keygen_avg_us = keygen_avg / NSECS_PER_USEC;
    double encaps_avg_us = encaps_avg / NSECS_PER_USEC;
    double decaps_avg_us = decaps_avg / NSECS_PER_USEC;
    printf("---Average Time Per Operation (in microseconds)---\n"
           "KEM.KeyGen:\t%.3f us\n"
           "KEM.Encaps:\t%.3f us\n"
           "KEM.Decaps:\t%.3f us\n",
           keygen_avg_us, encaps_avg_us, decaps_avg_us);
}

void print_results(uint64_t keygen_total, uint64_t encaps_total, uint64_t decaps_total) {
    printf("\n");

    print_sys_info();
    printf("\n");

    print_totals(keygen_total, encaps_total, decaps_total);
    printf("\n");

    print_averages((double)keygen_total / NUM_ITERS, (double)encaps_total / NUM_ITERS,
                   (double)decaps_total / NUM_ITERS);
    printf("\n");
}

int main(void) {
    struct timespec start, end;

    uint64_t keygen_acc = 0U;
    uint64_t encaps_acc = 0U;
    uint64_t decaps_acc = 0U;
    int64_t elapsed_ns = 0LL; // Intermediate (signed) value

    pk_t pk;                                          // Public key buffer
    kem_sk_t sk;                                      // Secret key buffer
    ct_t ct;                                          // Ciphertext buffer
    uint8_t k_a[SABER_KEYBYTES], k_b[SABER_KEYBYTES]; // Shared secret buffers for Alice and Bob, respectively

    init_rng();

    for (int i = 0; i < NUM_ITERS; ++i) {
        /*
         * Time KEM.KeyGen
         */
        clock_gettime(CLOCK_MONOTONIC, &start);
        KEM_KeyGen(&pk, &sk);
        clock_gettime(CLOCK_MONOTONIC, &end);
        elapsed_ns = (end.tv_sec - start.tv_sec) * NSECS_PER_SEC + (end.tv_nsec - start.tv_nsec);
        keygen_acc += elapsed_ns;

        /*
         * Time KEM.Encaps
         */
        clock_gettime(CLOCK_MONOTONIC, &start);
        KEM_Encaps(&pk, k_b, &ct);
        clock_gettime(CLOCK_MONOTONIC, &end);
        elapsed_ns = (end.tv_sec - start.tv_sec) * NSECS_PER_SEC + (end.tv_nsec - start.tv_nsec);
        encaps_acc += elapsed_ns;

        /*
         * Time KEM.Decaps
         */
        clock_gettime(CLOCK_MONOTONIC, &start);
        KEM_Decaps(&ct, &sk, k_a);
        clock_gettime(CLOCK_MONOTONIC, &end);
        elapsed_ns = (end.tv_sec - start.tv_sec) * NSECS_PER_SEC + (end.tv_nsec - start.tv_nsec);
        decaps_acc += elapsed_ns;

        /*
         * Check whether both shared secrets match.
         */
        assert((memcmp(k_a, k_b, SABER_KEYBYTES) == 0) && "Alice and Bob's shared secrets don't match.");
    }

    print_results(keygen_acc, encaps_acc, decaps_acc);

    return 0;
}
