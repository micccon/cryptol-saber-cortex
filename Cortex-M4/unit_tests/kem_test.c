#include <stdio.h>
#include <string.h>

#include "kem.h"
#include "randombytes.h"

static const uint8_t kat_seed[48] = {
    0x06, 0x15, 0x50, 0x23, 0x4d, 0x15, 0x8c, 0x5e,
    0xc9, 0x55, 0x95, 0xfe, 0x04, 0xef, 0x7a, 0x25,
    0x76, 0x7f, 0x2e, 0x24, 0xcc, 0x2b, 0xc4, 0x79,
    0xd0, 0x9d, 0x86, 0xdc, 0x9a, 0xbc, 0xfd, 0xe7,
    0x05, 0x6a, 0x8c, 0x26, 0x6f, 0x9e, 0xf9, 0x7e,
    0xd0, 0x85, 0x41, 0xdb, 0xd2, 0xe1, 0xff, 0xa1
};

static const char expected_pkey_hex[] =
    "29157c69a067dd1c151115a9bbeb2d6e627f4e747716efa1569c7b7858cb2e71"
    "fb52c9984c2b2f98ef255c008024c277f6a5803c6f225afd169e0fb3e87dfa11"
    "457786ccb7d6cdcd472ad7bab58a5f8f09f40a2718e9c415c2ea7113960ed0e6"
    "42fe35d01bc639548f2841c0a97d057083dd86acf474c63cb715eb815e75d738"
    "adfb2106d4ec4bb2fcd419de1dd8273fe4e18cef3ecdc48e02875484cb59b561"
    "cea994e1104d295ec6129ec6874d3871e5ff01ec53e86635d907a5a59432557b"
    "475afb8158ec006ffb19ed7fa6b67e5f129b5195146e6beca2f796c68d42335c"
    "b518a9455fdf72696c2c6352d91617dab38c4855c504f7755d14225413e7e3ee"
    "062be01a405d75d5a8ea2793eeef962b193c1811ea8169e318363dd88c013b31"
    "9053b4e7f2f930ec34e52c8131fc2d0f26fb1a08b7f49701f6ebcc67dc7ecf5b"
    "314214c7897136edd0551ca6c828d3507d57521153de39f2ec7c7935f07c20d5"
    "b30086cee8964e9be5bc74de5b95aa2210e952ef5234222934af1e1ab519d527"
    "cf8e3aa40ab34cf30229d2061f18baa2429410b8fc7aaf949178f6473b0ce2ea"
    "094b2bfd4a338b80ab6b7f002b9aa56856c4132f32a001b341ebba593a8bfe66"
    "1b50cab2cdfe80d867ab655c7b7423fa483b080fdb7e059f3cfc6528014d0f7d"
    "0dc5526fba29208ea197493b8a92d66a0a047942264302e61a08a4df3a91e8e9"
    "4dddf469d08ea54a2ecafd8e64f28d3c40d5ba885d63134550430d205e7e5caa"
    "fe854e494c483ac6ce455d8a1b35f9fd2252e2741e24747ebc052c0b3fe0046f"
    "a6fc9b0ccf038088b18ea5b7a3f77a7965640bf6c4fb89f33e30bbdd3c958892"
    "06de51960fdd6a5aa41f80c537e3bab1576214511ca21a4fd210b2a479e1d414"
    "b2a012f789f0d296e22e4a5941434400a3ffc7229068a605891fa15af03c177d"
    "0736a6c2c4fe0d481f48c45568ad92fe1850215aeded9f97b1219c2e250ecaec"
    "b99dfc01101f5d26f36b710e2da088fd989a0dce00bb18fb76903bfbd4bbe1cd"
    "66dad049ea12540e81f619fa0478d7687207ffb4eda6544192629a5bc5e51d92"
    "7fc143dac7cea36b0c7c6d13969f383b0a3bd4c978d04c65e954f82eb883a628"
    "25445e2593f5cb23745684f66e5b69d6fcbedf47507c7b942c1ddaa054f0cacf"
    "64eaa5ff31dc213e827d211d47ab0d1d6e2e507f56842d74fc2d94fbcaa9c4bf"
    "701ace46dec65a2cb9e0b69e75041c9eaed891199c95ec280201e63fc2bcef11"
    "c6ed272feceb7ea4c3c45785de6cb4ced51182b25a149f7bc005d68074cd58d9"
    "16bf48eb13d509714df03954552b3f1fd2026987cce4cec86e09596a1bfcd81c"
    "e9f2ac32935489c7edd064bba9a78ceab09d29e020c0ea8f1c70d33a813889c3";

static const char expected_ct_hex[] =
    "719fac31ae90417f2da1d37e47a065b860575d1df2de60814a39297b902afa2f"
    "5a12a0d66ed34f3afed294d40e8027102240798a9f3fb38e65bc93d0be678aeb"
    "099cff15d9d9d88239bc40e81fc74e5cc280e0495058f7aa36b333a0e8d801ec"
    "dbc94d5e12b80273a9b37f61e255ac8fcc54d8bceeec8829052fb820fa6f3f93"
    "c6b0d0d246a354602ee06294ee726db763b290738d640682106a34dd44f238e3"
    "3840bd7b01261e167d3ed6df8fa0700642fa3016b38f29cde00fa4615d97e62a"
    "e145c9003b54501636c8a2784f7f57ed0fd9ce128530f2272af12137e1274256"
    "eac34c0c901e64edf50a484178b47c971ed4f021466ae7baf8bb8caa5b9978f0"
    "5471d9da472d383ed46c44656cdfba6a03b974240df6e10d6861293b71401df5"
    "8397beb67bbe6b716bc196ce2d3e8b0a940f07c66fa947b08ea407c574990270"
    "15f52850c7bc680beb3ca5953f90891c45b9894421a95f5a69ed66b00dbd4f98"
    "51ab8ee5f60923a61e984a3a632b41b0a1245976f1a8c9d0bb2fd61d4e9c4134"
    "0ba47eeb595c20bfcb4b88ff0b19eec0e934f8ed69394af2042a84ee8ce17025"
    "2d8daefe161132870b46dae82f3a5f067f017c5fe47cfbd3845f94d8dadbdc6d"
    "b8bf72e96694ff624526edac214679721a4757e65f64be73ddc8f81926d50671"
    "9aa2fe5fc32fa45ffbe75ef6a758eaceb2c07506c4166462a0e6563d3853305b"
    "8804288f0d19d22ee96aadbb12086af3e41cbc4b08d9190368f506630378e0aa"
    "c613f5dcb8a5c5bfb63a1ad837a6563478abb6731e8ed660bcf0fbf38a853584"
    "51e4b188519e6d42c5e876617dc8c4f8d1dbd512032642f62da3a3e7fe0133bd"
    "39eaa0996955c21b020446d0ad95f148aa6a36245510d998f1802a61438b3050"
    "2604a666559ffd013eacaef008382d7e586622e8c34ac866eadd99291e9b5f8e"
    "6c3675a55afaa141b9adc0947897555a80e2a5c3824c443954dee5b776816953"
    "63b184b40fcf7824f58775dfb299b20cddfa10a62e340d5b3b52d21b7c27fbfd"
    "79a8565e69838dce5de7560bb3d6ece880d59722908f4931eccee163759c193f"
    "bc1d4e1f3b3496ce10705c8552d72ec1316940f0562c54c05d7cefaa32630a7d"
    "3b08d9fdbe24a5dd0892db51beb4fc80729e0bca84b9c22dbc56d48aea6a116b"
    "f4965b432a895dae2db869b1fe648793984fa283fd96f35a5477a628e477de7f"
    "00e7255d1d6b3f123486cf993726a53193aa9882e149eb35fe8e33d90a86fc6b"
    "4fcc68e4f514e3dfbc83771315d29d187c9ff7f95da67f4f35b6db697240ecab"
    "1b92f5b89973aa8966dc8dd874fa8f76c9cede6a37657f7b7ffe14036b97be06"
    "04e82c07a9280f206d8c1b52cffa347c038e3946e72f5a526e27eb50ac351925"
    "bc5632a1464d0f41e3f57caa3a426c2546f94f2a8df9763faf132b4f08ac06e9"
    "c8753b065d94ae275aa452588336b70183664d9c6d1b2070823226943fda1d11"
    "6ca2d766ee95b209add6bb64b9ceb9dd5eff54e76efdcb3f62773ca8f8ae7bf5";

static const uint8_t expected_ss[SABER_KEYBYTES] = {
    0x15, 0x65, 0x33, 0x53, 0x6c, 0x84, 0x35, 0xf8,
    0x2c, 0xc3, 0x6f, 0xc1, 0xef, 0x95, 0x28, 0xde,
    0xdc, 0x49, 0x22, 0x3d, 0xda, 0x00, 0x91, 0x61,
    0x7d, 0xc1, 0xac, 0xaf, 0x60, 0x58, 0xd1, 0xca
};

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

static void serialize_pk(uint8_t out[SABER_INDCPA_PUBLICKEYBYTES], const pk_t *pk) {
    memcpy(out, pk->pk, sizeof(pk->pk));
    memcpy(out + sizeof(pk->pk), pk->seed_a, sizeof(pk->seed_a));
}

static int check_round_trip(void) {
    pk_t pk;
    kem_sk_t sk;
    ct_t ct;
    uint8_t pkey[SABER_INDCPA_PUBLICKEYBYTES];
    uint8_t expected_pkey[SABER_INDCPA_PUBLICKEYBYTES];
    uint8_t expected_ct[SABER_BYTES_CCA_DEC];
    uint8_t ss_enc[SABER_KEYBYTES];
    uint8_t ss_dec[SABER_KEYBYTES];

    if (decode_hex(expected_pkey_hex, expected_pkey, sizeof(expected_pkey)) != 0) {
        puts("KEM expected pkey decode failed");
        return 1;
    }

    if (decode_hex(expected_ct_hex, expected_ct, sizeof(expected_ct)) != 0) {
        puts("KEM expected ct decode failed");
        return 1;
    }

    randombytes_init((uint8_t *)kat_seed, NULL, 256);
    KEM_KeyGen(&pk, &sk);
    KEM_Encaps(&pk, ss_enc, &ct);
    KEM_Decaps(&ct, &sk, ss_dec);
    serialize_pk(pkey, &pk);

    if (memcmp(pkey, expected_pkey, sizeof(pkey)) != 0) {
        puts("KEM pkey mismatch");
        return 1;
    }

    if (memcmp(ct.bytes, expected_ct, sizeof(ct.bytes)) != 0) {
        puts("KEM ct mismatch");
        return 1;
    }

    if (memcmp(ss_enc, expected_ss, SABER_KEYBYTES) != 0) {
        puts("KEM shared secret mismatch");
        return 1;
    }

    if (memcmp(ss_enc, ss_dec, SABER_KEYBYTES) != 0) {
        puts("KEM round-trip failed");
        return 1;
    }

    return 0;
}

int main(void) {
    if (check_round_trip() != 0) {
        return 1;
    }

    puts("KEM test passed");
    return 0;
}
