#include "kats.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "indcpa.h"
#include "kem.h"
#include "randombytes.h"
#include "../third_party/fips202.h"

static int hex_value(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return 10 + (c - 'a');
    }
    if (c >= 'A' && c <= 'F') {
        return 10 + (c - 'A');
    }
    return -1;
}

static int decode_hex(const char *hex, uint8_t *out, size_t out_len) {
    size_t hex_len = strlen(hex);

    if (hex_len != out_len * 2) {
        return -1;
    }

    for (size_t i = 0; i < out_len; ++i) {
        int hi = hex_value(hex[2 * i]);
        int lo = hex_value(hex[2 * i + 1]);

        if (hi < 0 || lo < 0) {
            return -1;
        }

        out[i] = (uint8_t)((hi << 4) | lo);
    }

    return 0;
}

static void trim_newline(char *line) {
    size_t len = strlen(line);

    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
        line[len - 1] = '\0';
        --len;
    }
}

static const char *skip_ws(const char *s) {
    while (*s != '\0' && isspace((unsigned char)*s)) {
        ++s;
    }
    return s;
}

static int load_next_req_case(FILE *fp, req_case_t *out) {
    char line[4096];

    // Each request case is keyed only by count and its 48-byte DRBG seed.
    memset(out, 0, sizeof(*out));
    out->count = -1;

    while (fgets(line, sizeof(line), fp) != NULL) {
        trim_newline(line);

        if (strncmp(line, "count =", 7) == 0) {
            out->count = atoi(skip_ws(line + 7));
            break;
        }
    }

    if (out->count < 0) {
        return feof(fp) ? 0 : -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        trim_newline(line);

        if (strncmp(line, "seed =", 6) == 0) {
            return decode_hex(skip_ws(line + 6), out->seed, sizeof(out->seed)) == 0 ? 1 : -1;
        }
    }

    return -1;
}

static void serialize_pk_bytes(const pk_t *pk, uint8_t out[SABER_INDCPA_PUBLICKEYBYTES]) {
    // The public-key byte string format is b || seed_A.
    memcpy(out, pk->pk, sizeof(pk->pk));
    memcpy(out + sizeof(pk->pk), pk->seed_a, sizeof(pk->seed_a));
}

static void serialize_kem_secret_key(const kem_sk_t *sk,
                                     uint8_t out[SABER_SECRETKEYBYTES]) {
    uint8_t pk_bytes[SABER_INDCPA_PUBLICKEYBYTES];

    // The KEM secret-key byte string format is sk_cpa || pk || H(pk) || z.
    serialize_pk_bytes(&sk->pk, pk_bytes);
    memcpy(out, sk->indcpa_sk.sk, SABER_INDCPA_SECRETKEYBYTES);
    memcpy(out + SABER_INDCPA_SECRETKEYBYTES, pk_bytes, SABER_INDCPA_PUBLICKEYBYTES);
    memcpy(out + SABER_INDCPA_SECRETKEYBYTES + SABER_INDCPA_PUBLICKEYBYTES,
           sk->hash_pk,
           SABER_HASHBYTES);
    memcpy(out + SABER_SECRETKEYBYTES - SABER_KEYBYTES, sk->z, SABER_KEYBYTES);
}

static void fprint_bstr(FILE *fp,
                        const char *label,
                        const uint8_t *bytes,
                        size_t len) {
    fprintf(fp, "%s", label);
    for (size_t i = 0; i < len; ++i) {
        fprintf(fp, "%02X", bytes[i]);
    }
    if (len == 0) {
        fprintf(fp, "00");
    }
    fprintf(fp, "\n");
}

int main(void) {
    FILE *req_fp;
    FILE *rsp_fp;
    req_case_t req;
    pk_t pk;
    kem_sk_t sk;
    ct_t ct;
    uint8_t pkey[SABER_INDCPA_PUBLICKEYBYTES];
    uint8_t skey[SABER_SECRETKEYBYTES];
    uint8_t ss_enc[SABER_KEYBYTES];
    uint8_t ss_dec[SABER_KEYBYTES];
    int cases_run = 0;

    req_fp = fopen("KATs/PQCkemKAT_2304.req", "r");
    if (req_fp == NULL) {
        perror("failed to open req file");
        return 1;
    }

    rsp_fp = fopen("KATs/customKAT.rsp", "w");
    if (rsp_fp == NULL) {
        perror("failed to open rsp file");
        fclose(req_fp);
        return 1;
    }

    fprintf(rsp_fp, "# Saber\n\n");

    for (;;) {
        int req_status = load_next_req_case(req_fp, &req);

        if (req_status == 0) {
            break;
        }
        if (req_status < 0) {
            puts("failed to parse request cases");
            fclose(req_fp);
            fclose(rsp_fp);
            return 1;
        }

        // Recreate the reference KAT flow: seed the DRBG from the request seed,
        // then run keygen, encaps, and decaps in sequence.
        randombytes_init(req.seed, NULL, 256);
        KEM_KeyGen(&pk, &sk);
        serialize_pk_bytes(&pk, pkey);
        serialize_kem_secret_key(&sk, skey);
        KEM_Encaps(&pk, ss_enc, &ct);
        KEM_Decaps(&ct, &sk, ss_dec);

        // Keep the same internal consistency check as the reference generator.
        if (memcmp(ss_enc, ss_dec, sizeof(ss_enc)) != 0) {
            fprintf(stderr, "KAT generation failed self-check in count %d\n", req.count);
            fclose(req_fp);
            fclose(rsp_fp);
            return 1;
        }

        // Emit one response block in the standard count/seed/pk/sk/ct/ss format.
        fprintf(rsp_fp, "count = %d\n", req.count);
        fprint_bstr(rsp_fp, "seed = ", req.seed, sizeof(req.seed));
        fprint_bstr(rsp_fp, "pk = ", pkey, sizeof(pkey));
        fprint_bstr(rsp_fp, "sk = ", skey, sizeof(skey));
        fprint_bstr(rsp_fp, "ct = ", ct.bytes, sizeof(ct.bytes));
        fprint_bstr(rsp_fp, "ss = ", ss_enc, sizeof(ss_enc));
        fprintf(rsp_fp, "\n");

        ++cases_run;
    }

    fclose(req_fp);
    fclose(rsp_fp);

    printf("Generated KAT response file for %d cases: KATs/customKAT.rsp\n", cases_run);
    return 0;
}
