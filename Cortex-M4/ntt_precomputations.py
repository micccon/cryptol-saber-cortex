q = 25166081  # chosen: prime, 2^8 | (q-1), product-overflow safe for SABER
R = 2**32     # Montgomery parameter

# Sanity checks on q
assert (q - 1) % 256 == 0, "2^8 must divide q-1 for a 256-point NTT"
assert all(q % i != 0 for i in range(2, int(q**0.5) + 1)), "q must be prime"

# -q^{-1} mod R  →  NTT_Q_INV
# The value such that q * NTT_Q_INV ≡ -1 (mod R)
q_inv = (-pow(q, -1, R)) % R
assert (q * q_inv) % R == R - 1  # verify

# R^2 mod q  →  NTT_R2
r2 = pow(R, 2, q)

print(f"#define NTT_Q     {q}")
print(f"#define NTT_Q_INV {q_inv}")
print(f"#define NTT_R2    {r2}")

# Precompute twiddle factors for NTT

def bitrev(k, bits):
    return int(f"{k:0{bits}b}"[::-1], 2)

def to_montgomery(x):
    return (x * R) % q

bits = 7  # for 128-point NTT
zetas = [0] * 128

g = 17                             # a primtiive root mod q
# 17 is a primitive root iff 17^((q-1)/p) != 1 for each prime p | (q-1)
# q-1 = 2^8 * 5 * 19661
prime_factors = [2, 5, 19661]
assert all(pow(g, (q - 1) // p, q) != 1 for p in prime_factors), "g is not a primitive root"

omega = pow(g, (q - 1) // 256, q)  # a primitive 256th root of unity
assert pow(omega, 256, q) == 1,  "omega is not a 256th root of unity"
assert pow(omega, 128, q) != 1,  "omega is not primitive (order < 256)"

for i in range(1, 128):
    exp = bitrev(i, bits)
    zeta = pow(omega, exp, q)
    zetas[i] = to_montgomery(zeta)

vals = ", ".join(str(z) for z in zetas[1:])
print(f"static const uint32_t zetas[128] = {{0, {vals}}};")

# Build inv_zetas for INTT, laid out for ascending k in the len=2→128 loop
ntt_level_ranges = [range(64, 128), range(32, 64), range(16, 32), range(8, 16),
                    range(4, 8),    range(2, 4),    range(1, 2)]

inv_zetas = [0]  # index 0 unused
for level_range in ntt_level_ranges:
    for k_ntt in level_range:
        exp     = bitrev(k_ntt, 7)
        inv_exp = (256 - exp) % 256
        inv_zetas.append(to_montgomery(pow(omega, inv_exp, q)))
print("static const uint32_t inv_zetas[128] = {", end="")
print(", ".join(str(z) for z in inv_zetas), end="")
print("};")

inv128      = pow(128, q - 2, q)        # 128^{-1} mod q'
inv128_mont = to_montgomery(inv128)     # Montgomery form — this is your NTT_INV128 constant
print(f"#define NTT_INV128 {inv128_mont}")