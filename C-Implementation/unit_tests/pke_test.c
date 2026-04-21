#include <stdio.h>
#include <string.h>

#include "indcpa.h"
#include "../third_party/fips202.h"

static const uint8_t expected_seed_a[SABER_SEEDBYTES] = {
    0x7c, 0x99, 0x35, 0xa0, 0xb0, 0x76, 0x94, 0xaa,
    0x0c, 0x6d, 0x10, 0xe4, 0xdb, 0x6b, 0x1a, 0xdd,
    0x2f, 0xd8, 0x1a, 0x25, 0xcc, 0xb1, 0x48, 0x03,
    0x2d, 0xcd, 0x73, 0x99, 0x36, 0x73, 0x7f, 0x2d
};

static const uint8_t expected_seed_s[SABER_NOISE_SEEDBYTES] = {
    0x86, 0x26, 0xed, 0x79, 0xd4, 0x51, 0x14, 0x08,
    0x00, 0xe0, 0x3b, 0x59, 0xb9, 0x56, 0xf8, 0x21,
    0x0e, 0x55, 0x60, 0x67, 0x40, 0x7d, 0x13, 0xdc,
    0x90, 0xfa, 0x9e, 0x8b, 0x87, 0x2b, 0xfb, 0x8f
};

static const uint8_t expected_m_raw[SABER_KEYBYTES] = {
    0xc8, 0x2c, 0xe0, 0x50, 0xa6, 0xdd, 0x85, 0xfe,
    0xa6, 0x3d, 0xd0, 0x65, 0x6a, 0xf1, 0x46, 0xb1,
    0x88, 0x0f, 0x91, 0xab, 0xc0, 0x07, 0x2c, 0x92,
    0xa9, 0xda, 0x17, 0x78, 0x76, 0x9c, 0x46, 0x61
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

static const char expected_sk_hex[] =
    "ff3f000480000000feff000800fe5f00088000f0ff018000f0ffff5f00fcffff"
    "efff010000f8ff000000fc7f0100000200000800000000000000100000800010"
    "000100000080001000fe7f00000000e0ff0700ff0f0002c0ffffff00e0ff0300"
    "00f0ff0380ff0f000120000000ffefffff7f00f0fffe3f000480ff0f00028000"
    "1000012000000000d0ff01c00010000200000480ff2f00fc7f00100001e0ffff"
    "ff00e0ff0140000000014000048000200002c0ff0700ff1f00f87f01e0ff0380"
    "ffefff002000fc7f00f0ff0180ffffffff5f00f87f001000fe7f000800fd1f00"
    "fc7f00e0ffff7f000000fefffff77f003000024000f8fffedfff070000100002"
    "0000f8ffffdfff030000100000c0ff070003c0fff77f00200004c0ffffff0020"
    "00088000f0ffff3f00080000e0ff0700ffefff0380001800020000fcff00f0ff"
    "014000f8fffe3f00fcffff1f00020000f0ff01a0fff7ff00f0ff0380fff7ff00"
    "e0ffffff00d0fffdbf001000ff3f00f8ff00c0ff0180ffffff020000048000f0"
    "fffd3f000000032000000000f0ff0300001000024000000000000002c0ff0700"
    "0020000400002000fa3f00f8ff0140000400002000048000f0ffff3f00000000"
    "10000040000000ffffffffff000000febffff7fffd5f00fc7f0010000280ff0f"
    "0000a0ff0b8000000008c0ff170000200004800010000040ff0700fe1f000880"
    "001000fe3f001000000000f8ffff1f0002400000000200000000012000000000"
    "000000c0ffffff0000000000001800ff7f00fc7f00200002c0ff1700004000fc"
    "7f02f0ffff3f00100002e0ff07800010000280ff0f00ff1f000080fe2f000000"
    "00f8ff01e0ff0380002000febf001000ffffffffffff1f000480ffffff010000"
    "fcfffeffff010000f8ff0220000400ff0f00fe3f000800fd1f00fcfffe1f0002"
    "800000000140000400011000fc3f00f8ff01c0fffb7fffffff010000f8ff03e0"
    "ff030000f0ff014000e8ff00e0ff0700000000024000f8ff0020000000000000"
    "00c0ff0f0001200004000030000000000800fe1f0004000100000440000000ff"
    "1f00f87f00c0ff038000f8ff00c0ff0780011000faffff0700ff5f00fc7f01e0"
    "ff0140ff0700feffff0b00000000feff0008000220000c8000200000c0ff0700"
    "01c0fffb7fff0f000080ff0f0000e0ff0380ff1f000280ff0f0000e0fffffffe"
    "0f00feffff07000140000400ff1f0002000000000000000080ff0f00060000f0"
    "ff004000100001f0ffff7f00f0ff0000000080ffefff054000f8ff0100001000"
    "ff0f000040001000012000000000300002c0ff1700004000fcff001000028000"
    "0800ff3f000480fe0f00fcffff0f00fdffff0300ffefffffffffffff0120000c"
    "80ff2f00feffff0700010000f4ff000000024000f0ff002000fc7f0000000280"
    "00000000e0ff070000f0ff0140000800ff3f00f8ffffffffff7f000800ffdfff"
    "0300ffefff01800010000100000480ff2f00024000080001c0ff030000f0fffd"
    "7f000800004000fc7f010000febfff1700ff5f00fc7ffe2f00fc3f00f8ff0000"
    "00fcffff0f00febfff0f0002c0ffffff0020000400000000fcffffffffff0f00"
    "004000100001a0ffff7f00000002800000000200000400ff0f00feffff0700ff"
    "1f000000000000040001f0ffff1f00f87fff0f00024000080004e0fffbfffe0f"
    "00fc7f00f0fffd3f00000000e0ff0180fff7ff010000f8ff00e0ff0300000000";

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
    pke_sk_t sk;
    ct_t ct;
    uint8_t seed_a_used[SABER_SEEDBYTES];
    uint8_t pkey[SABER_INDCPA_PUBLICKEYBYTES];
    uint8_t expected_pkey[SABER_INDCPA_PUBLICKEYBYTES];
    uint8_t expected_sk[SABER_INDCPA_SECRETKEYBYTES];
    uint8_t expected_ct[SABER_BYTES_CCA_DEC];
    uint8_t dec[SABER_KEYBYTES];
    uint8_t m[SABER_KEYBYTES];
    uint8_t hash_pk[SABER_HASHBYTES];
    uint8_t kr[SABER_KEYBYTES + SABER_HASHBYTES];
    uint8_t coins[SABER_NOISE_SEEDBYTES];

    if (decode_hex(expected_pkey_hex, expected_pkey, sizeof(expected_pkey)) != 0) {
        puts("PKE expected pkey decode failed");
        return 1;
    }

    if (decode_hex(expected_sk_hex, expected_sk, sizeof(expected_sk)) != 0) {
        puts("PKE expected sk decode failed");
        return 1;
    }

    if (decode_hex(expected_ct_hex, expected_ct, sizeof(expected_ct)) != 0) {
        puts("PKE expected ct decode failed");
        return 1;
    }

    memcpy(seed_a_used, expected_seed_a, sizeof(seed_a_used));
    shake128(seed_a_used, sizeof(seed_a_used), seed_a_used, sizeof(seed_a_used));
    PKE_KeyGen_Deterministic(&pk, &sk, seed_a_used, (uint8_t *)expected_seed_s);

    serialize_pk(pkey, &pk);
    sha3_256(m, expected_m_raw, SABER_KEYBYTES);
    sha3_256(hash_pk, pkey, sizeof(pkey));
    memcpy(kr, m, SABER_KEYBYTES);
    memcpy(kr + SABER_KEYBYTES, hash_pk, SABER_HASHBYTES);
    sha3_512(kr, kr, sizeof(kr));
    memcpy(coins, kr + SABER_KEYBYTES, sizeof(coins));

    PKE_Enc(m, coins, &pk, &ct);
    PKE_Dec(&ct, &sk, dec);

    if (memcmp(pkey, expected_pkey, sizeof(pkey)) != 0) {
        puts("PKE pkey mismatch");
        return 1;
    }

    if (memcmp(sk.sk, expected_sk, sizeof(sk.sk)) != 0) {
        puts("PKE sk mismatch");
        return 1;
    }

    if (memcmp(ct.bytes, expected_ct, sizeof(ct.bytes)) != 0) {
        puts("PKE ct mismatch");
        return 1;
    }

    if (memcmp(dec, m, SABER_KEYBYTES) != 0) {
        puts("PKE round-trip failed");
        return 1;
    }

    return 0;
}

int main(void) {
    if (check_round_trip() != 0) {
        return 1;
    }

    puts("PKE test passed");
    return 0;
}
