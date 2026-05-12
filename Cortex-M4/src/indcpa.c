#include "indcpa.h"

#include <string.h>

// Rounds each coefficient of v in-place from Zq to Zp using the Saber H1 shift.
static void polyvec_round_zq_to_zp(PolyVec_Zq v) {
    for (size_t i = 0; i < SABER_L; ++i)
        for (size_t j = 0; j < SABER_N; ++j)
            v[i][j] = ((v[i][j] + H1) >> (SABER_EQ - SABER_EP)) & MASK_Zp;
}

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

    // Transpose A in-place to obtain A^T; eliminates the need for a second matrix buffer.
    transpose_matrix(A);

    // Compute b = A^T * s in R_q.
    PolyVec_Zq b;
    memset(b, 0, sizeof(b));
    matrix_vector_mul(A, s, b);

    // Round b in-place from Zq to Zp.
    polyvec_round_zq_to_zp(b);

    // Pack the secret vector and rounded public vector into the key structs.
    POLVECq2BS(s, sk->sk);
    POLVECp2BS(b, pk->pk);
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

    // Compute b = A * s' in R_q, then round in-place to Zp (reused for the first ciphertext component).
    PolyVec_Zq b;
    memset(b, 0, sizeof(b));
    matrix_vector_mul(A, s, b);
    polyvec_round_zq_to_zp(b);

    // Recover the public-key vector b0 from its packed Zp encoding.
    PolyVec_Zp b0;
    memset(b0, 0, sizeof(b0));
    BS2POLVECp(b0, pk->pk);

    // Reduce s in-place from Zq to Zp for the inner product; s is reused for s1.
    for (size_t i = 0; i < SABER_L; ++i) {
        for (size_t j = 0; j < SABER_N; ++j) {
            s[i][j] &= MASK_Zp;
        }
    }

    // Compute v' = <b0, s' mod p> in R_p.
    // v1 is reused for cm: after the compression loop below, v1 holds the second ciphertext component.
    Poly_Zp v1;
    memset(v1, 0, sizeof(v1));
    inner_prod(b0, s, v1);

    // Decode the message bits and lift in-place into Zp by shifting left EP - 1.
    // m_bits is reused for m1: after the loop, m_bits holds the lifted message polynomial.
    Poly_Z2 m_bits;
    memset(m_bits, 0, sizeof(m_bits));
    BS2POLmsg(m_bits, m);
    for (size_t i = 0; i < SABER_N; ++i) {
        m_bits[i] = (m_bits[i] << (SABER_EP - 1)) & MASK_Zp;
    }

    // Compute cm = (v' - mp + H1) >> (EP - ET) in-place on v1, compressed into Zt.
    for (size_t i = 0; i < SABER_N; ++i) {
        Zp diff = (v1[i] - m_bits[i]) & MASK_Zp;
        v1[i] = ((diff + H1) >> (SABER_EP - SABER_ET)) & MASK_Zt;
    }

    // Pack the ciphertext as POLVECp2BS(b') || POLT2BS(cm).
    // b and v1 hold Zp and Zt values respectively; underlying type is uint16_t throughout.
    POLVECp2BS(b, ct->bytes);
    POLT2BS(v1, ct->bytes + SABER_POLYVECCOMPRESSEDBYTES);
}

void PKE_Dec(ct_t *ct, pke_sk_t *sk, uint8_t m[SABER_KEYBYTES]) {
    // Recover the secret vector s from its packed Zq encoding.
    PolyVec_Zq s;
    memset(s, 0, sizeof(s));
    BS2POLVECq(s, sk->sk);

    // Recover b' from the first ciphertext component.
    PolyVec_Zp b1;
    memset(b1, 0, sizeof(b1));
    BS2POLVECp(b1, ct->bytes);

    // Recover cm from the second ciphertext component.
    Poly_Zt cm0;
    memset(cm0, 0, sizeof(cm0));
    BS2POLT(cm0, ct->bytes + SABER_POLYVECCOMPRESSEDBYTES);

    // Lift cm back into Zp by shifting left EP - ET.
    Poly_Zp cm1;
    memset(cm1, 0, sizeof(cm1));
    for (size_t i = 0; i < SABER_N; ++i) {
        cm1[i] = (Zp)((cm0[i] << (SABER_EP - SABER_ET)) & MASK_Zp);
    }

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
