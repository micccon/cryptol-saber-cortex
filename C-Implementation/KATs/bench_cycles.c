/*
 * This is a non-portable benchmarking script to (roughly)
 * estimate CPU cycles per KEM operation (Keygen, Encaps, Decaps).
 *
 * There is a portable benchmarking script (bench_portable.c) that
 * measures the average time to execute each operation; however, the
 * nitty-gritty CPU cycle counts are important to have as well. Hence,
 * this script (which uses the x86 `rdtsc` Read Time-Stamp Counter
 * instruction) exists in addition to the time-based benchmarking script.
 */
#if defined(__x86_64__) || defined(_M_X64)

#include <assert.h>
#include <inttypes.h>
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
#include "cpucycles.h"

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
    printf("---Total CPU Cycles (across %d iterations---\n"
           "KEM.KeyGen:\t%" PRIu64 " cycles\n"
           "KEM.Encaps:\t%" PRIu64 " cycles\n"
           "KEM.Decaps:\t%" PRIu64 " cycles\n",
           NUM_ITERS, keygen_total, encaps_total, decaps_total);
}

void print_averages(uint64_t keygen_avg, uint64_t encaps_avg, uint64_t decaps_avg) {
    printf("---Average CPU Cycles Per Operation---\n"
           "KEM.KeyGen:\t%" PRIu64 " cycles\n"
           "KEM.Encaps:\t%" PRIu64 " cycles\n"
           "KEM.Decaps:\t%" PRIu64 " cycles\n",
           keygen_avg, encaps_avg, decaps_avg);
}

void print_results(uint64_t keygen_total, uint64_t encaps_total, uint64_t decaps_total) {
    printf("\n");

    print_sys_info();
    printf("\n");

    print_totals(keygen_total, encaps_total, decaps_total);
    printf("\n");

    print_averages(keygen_total / NUM_ITERS, encaps_total / NUM_ITERS, decaps_total / NUM_ITERS);
    printf("\n");
}

int main(void) {
    uint64_t start, end;

    uint64_t keygen_acc = 0U;
    uint64_t encaps_acc = 0U;
    uint64_t decaps_acc = 0U;

    pk_t pk;                                          // Public key buffer
    kem_sk_t sk;                                      // Secret key buffer
    ct_t ct;                                          // Ciphertext buffer
    uint8_t k_a[SABER_KEYBYTES], k_b[SABER_KEYBYTES]; // Shared secret buffers for Alice and Bob, respectively

    init_rng();

    for (int i = 0; i < NUM_ITERS; ++i) {
        /*
         * Time KEM.KeyGen
         */
        start = cpucycles();
        KEM_KeyGen(&pk, &sk);
        end = cpucycles();
        keygen_acc += (end - start);

        /*
         * Time KEM.Encaps
         */
        start = cpucycles();
        KEM_Encaps(&pk, k_b, &ct);
        end = cpucycles();
        encaps_acc += (end - start);

        /*
         * Time KEM.Decaps
         */
        start = cpucycles();
        KEM_Decaps(&ct, &sk, k_a);
        end = cpucycles();
        decaps_acc += (end - start);

        /*
         * Check whether both shared secrets match.
         */
        assert((memcmp(k_a, k_b, SABER_KEYBYTES) == 0) && "Alice and Bob's shared secrets don't match.");
    }

    print_results(keygen_acc, encaps_acc, decaps_acc);

    return 0;
}

#endif
