// Implementation of declarations in 'randombytes.h'

#include "randombytes.h"
#include "helpers.h"

#include <stdbool.h>
#include <string.h>

// Point to your tivaware local installation here if you want to use the hardware AES engine for testing
// Otherwise, the host-side fallback will be used.
#if defined(SABER_USE_TIVAWARE_AES)
#include "hw_memmap.h"
#include "aes.h"
#include "sysctl.h"
#else
#include "../third_party/AES/WjCryptLib_Aes.h"
#endif

#define RANDOMBYTES_SUCCESS 0

/* Internal state for the AES-256 CTR DRBG used to drive deterministic tests. */
typedef struct {
    uint8_t key[32];
    uint8_t v[16];
    uint64_t reseed_counter;
} AES256_CTR_DRBG_State;

static AES256_CTR_DRBG_State drbg_state;

#if defined(SABER_USE_TIVAWARE_AES)
static bool tivaware_aes_ready = false;

static void tivaware_aes_init(void) {
    if (tivaware_aes_ready) {
        return;
    }

    SysCtlPeripheralEnable(SYSCTL_PERIPH_CCM0);
    while (!SysCtlPeripheralReady(SYSCTL_PERIPH_CCM0)) {
    }

    tivaware_aes_ready = true;
}

/* Encrypt a single 128-bit block under AES-256 using the TivaWare AES engine. */
static void aes256_ecb(uint8_t out[16],
                       const uint8_t key[32],
                       const uint8_t input[16]) {
    uint32_t src_words[4];
    uint32_t dst_words[4];
    uint32_t key_words[8];
    unsigned i;

    tivaware_aes_init();

    for (i = 0; i < 4; ++i) {
        src_words[i] = load32_le(input + (4 * i));
    }
    for (i = 0; i < 8; ++i) {
        key_words[i] = load32_le(key + (4 * i));
    }

    AESReset(AES_BASE);
    AESConfigSet(AES_BASE,
                 AES_CFG_KEY_SIZE_256BIT |
                 AES_CFG_DIR_ENCRYPT |
                 AES_CFG_MODE_ECB);
    AESKey1Set(AES_BASE, key_words, AES_CFG_KEY_SIZE_256BIT);
    (void)AESDataProcess(AES_BASE, src_words, dst_words, sizeof(src_words));

    for (i = 0; i < 4; ++i) {
        store32_le(out + (4 * i), dst_words[i]);
    }
}
#else
/* Host-side fallback used for desktop testing when the hardware AES block is unavailable. */
static void aes256_ecb(uint8_t out[16],
                       const uint8_t key[32],
                       const uint8_t input[16]) {
    AesContext ctx;

    (void)AesInitialise(&ctx, key, AES_KEY_SIZE_256);
    AesEncrypt(&ctx, input, out);
}
#endif

/* Increment the 128-bit DRBG counter as a big-endian integer. */
static void increment_v(uint8_t v[16]) {
    for (int i = 15; i >= 0; --i) {
        if (v[i] == 0xFF) {
            v[i] = 0x00;
        } else {
            v[i]++;
            break;
        }
    }
}

/*
 * Generate the 48-byte update buffer used by CTR_DRBG and fold it back into
 * the key and counter state. When provided_data is non-NULL, it is XORed into
 * the generated material before the state is replaced.
 */
static void aes256_ctr_drbg_update(const uint8_t provided_data[48],
                                   uint8_t key[32],
                                   uint8_t v[16]) {
    uint8_t temp[48];

    for (int i = 0; i < 3; ++i) {
        increment_v(v);
        aes256_ecb(temp + (16 * i), key, v);
    }

    if (provided_data != NULL) {
        for (int i = 0; i < 48; ++i) {
            temp[i] ^= provided_data[i];
        }
    }

    memcpy(key, temp, 32);
    memcpy(v, temp + 32, 16);
}

void randombytes_init(uint8_t entropy_input[48],
                      uint8_t personalization_string[48],
                      int security_strength) {
    uint8_t seed_material[48];

    /* The current test harness only fixes the seed material, not the claimed strength. */
    (void)security_strength;

    memcpy(seed_material, entropy_input, sizeof(seed_material));

    if (personalization_string != NULL) {
        for (int i = 0; i < 48; ++i) {
            seed_material[i] ^= personalization_string[i];
        }
    }

    memset(drbg_state.key, 0, sizeof(drbg_state.key));
    memset(drbg_state.v, 0, sizeof(drbg_state.v));

    aes256_ctr_drbg_update(seed_material, drbg_state.key, drbg_state.v);
    drbg_state.reseed_counter = 1;
}

int randombytes(uint8_t *x, unsigned long long xlen) {
    uint8_t block[16];
    unsigned long long offset = 0;

    while (xlen > 0) {
        unsigned long long block_len = xlen > sizeof(block) ? sizeof(block) : xlen;

        /* Each output block comes from AES(Key, ++V) as in the NIST CTR_DRBG flow. */
        increment_v(drbg_state.v);
        aes256_ecb(block, drbg_state.key, drbg_state.v);

        memcpy(x + offset, block, block_len);
        offset += block_len;
        xlen -= block_len;
    }

    /* Advance the internal state after every request so sequential calls stay deterministic. */
    aes256_ctr_drbg_update(NULL, drbg_state.key, drbg_state.v);
    drbg_state.reseed_counter++;

    return RANDOMBYTES_SUCCESS;
}
