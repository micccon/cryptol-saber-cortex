/*
 * Interface for NTT helper methods, including Montgomery Multiplication/Reduction
 *
 * A goal of this project is to optimize the speed of our SABER implementation. One of
 * the known bottlenecks of our original, working C implementation lies in the MatrixVectorMul
 * and InnerProd functions, which require calls to `poly_mul` in order to compute negatively-wrapped
 * convolutions (NWC's) of polynomials. These functions use the naive schoolbook method, which takes
 * O(n^2) time.
 *
 * The SABER reference implementation uses Toom-Cook and Karatsuba to optimize this, but research
 * suggests that lifting polynomial arithmetic to a Number Theoretic Transform (NTT)-friendly ring
 * and performing operations there yields similar (often better) performances.
 *
 * Depends on: nothing :)
 */

// TURN OFF clang-format for this file for readability purposes
// clang-format off

#ifndef NTT_HELPERS_H
#define NTT_HELPERS_H

#include <stdint.h>
#include "params.h"

/*
 * This is the NTT prime modulus (i.e., the ring we're lifting SABER's polynomial multiplication into).
 * Note that it has ~nothing~ to do with SABER's own modulus (q = 2^{13}). 
 */
#define NTT_Q      25166081     // NTT prime for Saber/Firesaber

/*
 * This is the negated inverse of q' in Z_{2^{32}}. It's necessary for Montgomery Reduction to work, and is the value
 * such that q' * q'_inv ≡ -1 (mod R)
 */
#define NTT_Q_INV  41877759     // -q'^{-1} mod 2^32

/*
 * R^2 mod q', where R = 2^32. We use this value to convert values into Montgomery form via
 * Montgomery multiplication.
 */
#define NTT_R2     13990637     // R^2 mod q'

/**
 * Computes T * R^{-1} mod q' for a 64-bit input T.
 *
 * @param  a    64-bit value to reduce
 * @return      32-bit r ∈ [0, q') such that r ≡ T * R^{-1} (mod q')
 */
uint32_t montgomery_reduce(uint64_t a);

/**
 * Computes the Montgomery product of two values already in Montgomery form.
 * 
 * @param  a    First 32-bit Montgomery-form multiplicand
 * @param  b    Second 32-bit Montgomery-form multiplicand
 * @return      Montgomery Product r such that r ≡ â * b̂ * R (mod q')
 */
uint32_t montgomery_multiply(uint32_t a, uint32_t b);

/**
 * Converts an integer into its Montgomery representative.
 * 
 * @param  a    Arbitrary 32-bit integer such that a ∈ [0, q')
 * @return      â, the Montgomery representation of a, such that â ≡ a * R (mod q')
 */
uint32_t to_montgomery(uint32_t a);

/**
 * Recovers an integer from its Montgomery representative.
 * 
 * @param  a    â, the 32-bit Montgomery-form value such that â ≡ a * R (mod q')
 * @return      Recovered value r such that r ≡ a (mod q')
 */
uint32_t from_montgomery(uint32_t a);


/*
 * 128^{-1} mod q', in Montgomery form. Multiply each coefficient by this after
 * the GS butterfly loop to complete the INTT normalization.
 */
#define NTT_INV128 8388351

/*
 * These are the precomputed twiddle factors that will be used in the NTT operation.
 */
static const uint32_t zetas[128] = {
           0, 22244723, 23962974, 14962374, 20971417, 19430452, 18588637,  1776511,
    21131262,   647681,  2559945, 22470430,  9084979, 17864924, 13528086,  7261676,
    17105251, 23177096,  9344183,  2733537, 22500797, 24257295, 12030083, 13715241,
    23479184,  7944926,  5669200, 20806964, 20355585, 18019917, 18898725, 20872158,
    14994574,  8693725, 14846885,  6726360, 14660437,    42688, 15663744, 14255816,
    15932507, 12991730, 19981966, 24096732, 18929621, 24551809,  1134236, 19847105,
    22443020,  7460755, 16472287, 24577585,  8064557,   819256,  9600669, 10575964,
    21073794, 21905048, 11307548,  5563113, 18234579,  2510833, 15599039, 13185653,
     2489589, 17333049, 17957306,  2873802,  4271989, 24466058, 16001902, 15918842,
    18846441, 19144768, 13482094,  7016738,  2706077,  5432373,  1965477,  9310726,
    23806625,  1195379,  7332469,  6415135,  6248029,  4491945, 19325871,  8016266,
     1036751,  1022443, 22053197, 17671155, 21434067,  3804472, 21105416, 19948194,
    10212579, 21637634,  7434030,  2953912, 12940233, 14187113,   716072, 24947990,
    10566799, 11534198, 25006194,  1638182, 24214209,  5856816, 11994445, 12118088,
     9812256, 23934554,   834331, 17677557,  9743860, 13563401,  9780974, 13684452,
    13686251,  7345613, 23385120, 14036444, 21424172,  3776945,    25277, 12674977
};

/*
 * Precomputed inverse twiddle factors that will be used in the INTT operation.
 */
static const uint32_t inv_zetas[128] = {
           0, 12491104, 25140804, 21389136,  3741909, 11129637,  1780961, 17820468,
    11479830, 11481629, 15385107, 11602680, 15422221,  7488524, 24331750,  1231527,
    15353825, 13047993, 13171636, 19309265,   951872, 23527899,   159887, 13631883,
    14599282,   218091, 24450009, 10978968, 12225848, 22212169, 17732051,  3528447,
    14953502,  5217887,  4060665, 21361609,  3732014,  7494926,  3112884, 24143638,
    24129330, 17149815,  5840210, 20674136, 18918052, 18750946, 17833612, 23970702,
     1359456, 15855355, 23200604, 19733708, 22460004, 18149343, 11683987,  6021313,
     6319640,  9247239,  9164179,   700023, 20894092, 22292279,  7208775,  7833032,
    22676492, 11980428,  9567042, 22655248,  6931502, 19602968, 13858533,  3261033,
     4092287, 14590117, 15565412, 24346825, 17101524,   588496,  8693794, 17705326,
     2723061,  5318976, 24031845,   614272,  6236460,  1069349,  5184115, 12174351,
     9233574, 10910265,  9502337, 25123393, 10505644, 18439721, 10319196, 16472356,
    10171507,  4293923,  6267356,  7146164,  4810496,  4359117, 19496881, 17221155,
     1686897, 11450840, 13135998,   908786,  2665284, 22432544, 15821898,  1988985,
     8060830, 17904405, 11637995,  7301157, 16081102,  2695651, 22606136, 24518400,
     4034819, 23389570,  6577444,  5735629,  4194664, 10203707,  1203107,  2921358
};

/**
 * Performs an in-place, iterative, incomplete Cooley-Tukey NTT on a 256-coefficient
 * polynomial over Z_{q'}. Runs 7 levels of radix-2 butterflies (len = 128 down to 2),
 * leaving 128 degree-1 sub-polynomials rather than reducing all the way to scalars.
 * The base-case multiplication of the resulting degree-1 pairs is handled separately
 * by ntt_base_mul().
 *
 * @param a  The normal-form coefficient representation of the input polynomial
 */
void ntt(uint32_t a[SABER_N]);

/**
 * Multiplies two polynomials in the NTT domain by performing 128 independent
 * degree-1 polynomial multiplications in Z_{q'}[x]/(x^2 - zeta_i), one for
 * each pair of coefficients left by the incomplete NTT. This is the base-case
 * schoolbook step that completes the NTT-based polynomial multiplication.
 *
 * Both inputs must already be in NTT form (i.e., output of ntt()). The result
 * is written into a separate output array, also in NTT form, ready to be passed
 * to intt().
 *
 * @param  a        First 256-coefficient NTT-domain input polynomial
 * @param  b        Second 256-coefficient NTT-domain input polynomial
 * @param  result   Output array of 256 coefficients in NTT domain,
 *                  where result ≡ a · b (mod x^{256} + 1) in NTT form
 */
 void ntt_base_mul(const uint32_t a[SABER_N],
    const uint32_t b[SABER_N],
    uint32_t result[SABER_N]);

/**
 * Performs an in-place, iterative, incomplete Gentleman-Sande INTT on a 256-coefficient
 * polynomial in NTT domain over Z_{q'}. Runs 7 levels of radix-2 butterflies (len = 2 up
 * to 128), then multiplies every coefficient by NTT_INV128 = to_montgomery(128^{-1} mod q')
 * to normalize. On exit, each coefficient is the Montgomery representative of the recovered
 * polynomial coefficient.
 *
 * @param a  The NTT-domain coefficient array to invert in-place
 */
void inv_ntt(uint32_t a[SABER_N]);

#endif
