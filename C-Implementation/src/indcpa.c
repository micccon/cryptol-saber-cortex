#include "indcpa.h"

#include <string.h>

void PKE_KeyGen_Deterministic(pk_t *pk,
                              pke_sk_t *sk,
                              uint8_t seed_a[SABER_SEEDBYTES],
                              uint8_t seed_s[SABER_NOISE_SEEDBYTES]) {
    // Store the public matrix seed in the public key.
    memcpy(pk->seed_a, seed_a, SABER_SEEDBYTES);

    // Generate matrix A from seed_a.
    PolyMatrix_Zq A;
    memset(A, 0, sizeof(A));
    gen_matrix(pk->seed_a, A);

    // Generate secret vector s from seed_s.
    PolyVec_Zq s;
    memset(s, 0, sizeof(s));
    gen_secret(seed_s, s);

    // Transpose A to obtain A^T for the keygen matrix-vector product.
    PolyMatrix_Zq AT;
    memset(AT, 0, sizeof(AT));
    transpose_matrix(A, AT);

    // Compute b = A^T * s in R_q.
    PolyVec_Zq b;
    memset(b, 0, sizeof(b));
    matrix_vector_mul(AT, s, b);

    // Round b from Zq down to Zp using the Saber H1 constant.
    PolyVec_Zp b1;
    memset(b1, 0, sizeof(b1));
    for (size_t i = 0; i < SABER_L; ++i) {
        // For each coefficient, add h1 and shift right, then mask to Zp.
        for (size_t j = 0; j < SABER_N; ++j) {
            b1[i][j] = (Zp)(((b[i][j] + H1) >> (SABER_EQ - SABER_EP)) & MASK_Zp);
        }
    }

    // Pack the secret vector and rounded public vector into the key structs.
    POLVECq2BS(s, sk->sk);
    POLVECp2BS(b1, pk->pk);
}

void PKE_KeyGen(pk_t *pk, pke_sk_t *sk) {
    // Get random seeds for the public matrix and secret vector
    uint8_t seed_a[SABER_SEEDBYTES];
    uint8_t seed_s[SABER_NOISE_SEEDBYTES];

    // Use randombytes to fill the seeds
    // Then verwrite seed_a with its hash to decorrelate it from the secret seed
    randombytes(seed_a, SABER_SEEDBYTES);
    shake128(seed_a, SABER_SEEDBYTES, seed_a, SABER_SEEDBYTES);
    randombytes(seed_s, SABER_NOISE_SEEDBYTES);

    // Call the deterministic keygen with the generated seeds
    PKE_KeyGen_Deterministic(pk, sk, seed_a, seed_s);
}

void PKE_Enc(uint8_t m[SABER_KEYBYTES],
             uint8_t seed_s[SABER_SEEDBYTES],
             pk_t *pk,
             ct_t *ct) {
    // Generate matrix A from seed_a in the public key.
    PolyMatrix_Zq A;
    memset(A, 0, sizeof(A));
    gen_matrix(pk->seed_a, A);

    // Generate the ephemeral secret vector s' from the encryption seed.
    PolyVec_Zq s;
    memset(s, 0, sizeof(s));
    gen_secret(seed_s, s);

    // Compute b = A * s' in R_q.
    PolyVec_Zq b;
    memset(b, 0, sizeof(b));
    matrix_vector_mul(A, s, b);

    // Round b from Zq down to Zp to form the first ciphertext component.
    PolyVec_Zp b1;
    memset(b1, 0, sizeof(b1));
    for (size_t i = 0; i < SABER_L; ++i) {
        for (size_t j = 0; j < SABER_N; ++j) {
            b1[i][j] = (Zp)(((b[i][j] + H1) >> (SABER_EQ - SABER_EP)) & MASK_Zp);
        }
    }

    // Recover the public-key vector b from its packed Zp encoding.
    PolyVec_Zp b0;
    memset(b0, 0, sizeof(b0));
    BS2POLVECp(b0, pk->pk);

    // Reduce the ephemeral secret vector from Zq to Zp for the inner product.
    PolyVec_Zp s1;
    memset(s1, 0, sizeof(s1));
    for (size_t i = 0; i < SABER_L; ++i) {
        for (size_t j = 0; j < SABER_N; ++j) {
            s1[i][j] = (Zp)(s[i][j] & MASK_Zp);
        }
    }

    // Compute v' = <b, s' mod p> in R_p.
    Poly_Zp v1;
    memset(v1, 0, sizeof(v1));
    inner_prod(b0, s1, v1);

    // Decode the message bits and lift them into Zp by shifting left EP - 1.
    Poly_Z2 m_bits;
    Poly_Zp m1;
    memset(m_bits, 0, sizeof(m_bits));
    memset(m1, 0, sizeof(m1));
    BS2POLmsg(m_bits, m);
    for (size_t i = 0; i < SABER_N; ++i) {
        m1[i] = (Zp)((m_bits[i] << (SABER_EP - 1)) & MASK_Zp);
    }

    // Compute cm = (v' - mp + H1) >> (EP - ET) in R_p, then compress into Zt.
    Poly_Zt cm;
    memset(cm, 0, sizeof(cm));
    for (size_t i = 0; i < SABER_N; ++i) {
        Zp diff = (Zp)((v1[i] - m1[i]) & MASK_Zp);
        cm[i] = (Zt)(((diff + H1) >> (SABER_EP - SABER_ET)) & MASK_Zt);
    }

    // Pack the ciphertext as POLT2BS(cm) || POLVECp2BS(b').
    POLT2BS(cm, ct->bytes);
    POLVECp2BS(b1, ct->bytes + SABER_SCALEBYTES_KEM);
}

void PKE_Dec(ct_t *ct, pke_sk_t *sk, uint8_t m[SABER_KEYBYTES]) {
    // Recover the secret vector s from its packed Zq encoding.
    PolyVec_Zq s;
    memset(s, 0, sizeof(s));
    BS2POLVECq(s, sk->sk);

    // Recover cm from the first ciphertext component.
    Poly_Zt cm0;
    memset(cm0, 0, sizeof(cm0));
    BS2POLT(cm0, ct->bytes);

    // Lift cm back into Zp by shifting left EP - ET.
    Poly_Zp cm1;
    memset(cm1, 0, sizeof(cm1));
    for (size_t i = 0; i < SABER_N; ++i) {
        cm1[i] = (Zp)((cm0[i] << (SABER_EP - SABER_ET)) & MASK_Zp);
    }

    // Recover b' from the second ciphertext component.
    PolyVec_Zp b1;
    memset(b1, 0, sizeof(b1));
    BS2POLVECp(b1, ct->bytes + SABER_SCALEBYTES_KEM);

    // Reduce the secret vector from Zq to Zp for the inner product.
    PolyVec_Zp s1;
    memset(s1, 0, sizeof(s1));
    for (size_t i = 0; i < SABER_L; ++i) {
        for (size_t j = 0; j < SABER_N; ++j) {
            s1[i][j] = (Zp)(s[i][j] & MASK_Zp);
        }
    }

    // Compute v = <b', s mod p> in R_p.
    Poly_Zp v;
    memset(v, 0, sizeof(v));
    inner_prod(b1, s1, v);

    // Recover the message polynomial by shifting right EP - 1.
    Poly_Z2 m1;
    memset(m1, 0, sizeof(m1));
    for (size_t i = 0; i < SABER_N; ++i) {
        Zp diff = (Zp)((v[i] - cm1[i]) & MASK_Zp);
        m1[i] = (Z2)(((diff + H2) >> (SABER_EP - 1)) & MASK_Z2);
    }

    // Pack the recovered message bits into the output byte string.
    POLmsg2BS(m1, m);
}
