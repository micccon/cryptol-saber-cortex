# C Implementation Optimizations

Covers two categories: compiler/linker flags applied in the Makefile, and source-level
changes that reduce peak stack usage. No heap allocations were introduced. All 100 KAT
vectors pass unchanged after each change.

---

## Summary

### Compiler flags (`Makefile`)

| Flag | Where | Effect |
|---|---|---|
| `-flto` | `CFLAGS` + link | Cross-TU dead code elimination + cross-module inlining |
| `-ffunction-sections -fdata-sections` | `CFLAGS` | One ELF section per symbol, enabling linker GC |
| `-Wl,--gc-sections` | `LDFLAGS` | Linker removes every section not reachable from an entry point |
| `-mcpu=cortex-m4 -mthumb` | `CFLAGS` (override) | Target the M4 core with Thumb-2 encoding — set at call site for cross-builds |

### Source-level stack changes

| Change | File(s) | Stack saved |
|---|---|---|
| Eliminate `buf_matrix` copy in `gen_matrix` | `arithmetic.c` | 3,744 B + memcpy |
| In-place `transpose_matrix`, drop `AT` in KeyGen | `helpers.h`, `helpers.c`, `indcpa.c` | 4,608 B |
| Drop `b1` in `PKE_KeyGen_Deterministic` | `indcpa.c` | 1,536 B |
| Reuse `b`, `s`, `m_bits`, `v1` in `PKE_Enc` | `indcpa.c` | 4,096 B |
| Extract `polyvec_round_zq_to_zp` helper | `indcpa.c` | (deduplication) |

**Total stack reduction: ~13,984 bytes** across the two hottest call paths
(`PKE_KeyGen_Deterministic` and `PKE_Enc`).

---

## 1. `gen_matrix` — eliminate `buf_matrix` copy

**File:** `src/arithmetic.c`

### Problem

`gen_matrix` allocated two equally-sized stack arrays (3,744 bytes each) and copied
one into the other just to reinterpret the layout as 2D:

```c
uint8_t buf[SABER_L * SABER_L * SABER_N * SABER_EQ / 8];       // 3,744 B
shake128(buf, sizeof(buf), seed, SABER_SEEDBYTES);

uint8_t buf_matrix[SABER_L * SABER_L][SABER_EQ * SABER_N / 8]; // 3,744 B — redundant
memcpy(buf_matrix, buf, sizeof(buf_matrix));                     // unnecessary copy
```

`buf_matrix` is the same bytes as `buf` — the only difference is how the compiler
indexes into it.

### Fix

Replace the second array with a pointer cast that reinterprets `buf` as the 2D layout
directly:

```c
uint8_t buf[SABER_L * SABER_L * SABER_N * SABER_EQ / 8];
shake128(buf, sizeof(buf), seed, SABER_SEEDBYTES);

uint8_t (*buf_matrix)[SABER_EQ * SABER_N / 8] =
    (uint8_t (*)[SABER_EQ * SABER_N / 8])buf;
```

### Savings

- **3,744 bytes** of stack removed
- One 3,744-byte `memcpy` eliminated
- No change to output or indexing logic

---

## 2. `transpose_matrix` — in-place, drop `AT` in `PKE_KeyGen_Deterministic`

**Files:** `include/helpers.h`, `src/helpers.c`, `src/indcpa.c`

### Problem

`transpose_matrix(input, result)` required a separate output matrix. At the call site
in `PKE_KeyGen_Deterministic`, this meant two 4,608-byte matrices lived on the stack
simultaneously — `A` and `AT` — even though `A` was dead the moment the copy finished:

```c
PolyMatrix_Zq A;   // 4,608 B
gen_matrix(pk->seed_a, A);
// ...
PolyMatrix_Zq AT;  // 4,608 B — second full copy of A, just transposed
memset(AT, 0, sizeof(AT));
transpose_matrix(A, AT);
matrix_vector_mul(AT, s, b); // A is dead here
```

### Fix

Changed `transpose_matrix` to operate in-place by swapping `A[i][j]` with `A[j][i]`
for all `i < j` (upper triangle with lower triangle). A single `Poly_Zq` (512-byte)
scratch buffer handles the swap:

```c
void transpose_matrix(PolyMatrix_Zq A) {
    for (size_t i = 0; i < SABER_L; ++i)
        for (size_t j = i + 1; j < SABER_L; ++j) {
            Poly_Zq tmp;
            memcpy(tmp,     A[i][j], sizeof(Poly_Zq));
            memcpy(A[i][j], A[j][i], sizeof(Poly_Zq));
            memcpy(A[j][i], tmp,     sizeof(Poly_Zq));
        }
}
```

`PKE_KeyGen_Deterministic` becomes:

```c
transpose_matrix(A);          // A is now A^T in-place
matrix_vector_mul(A, s, b);  // AT eliminated entirely
```

### Savings

- **4,608 bytes** of stack removed (`AT` gone from `PKE_KeyGen_Deterministic`)
- Signature change: `(PolyMatrix_Zq input, PolyMatrix_Zq result)` → `(PolyMatrix_Zq A)`

---

## 3. Drop `b1` in `PKE_KeyGen_Deterministic`

**File:** `src/indcpa.c`

### Problem

After computing `b = A^T * s`, the result was rounded from Zq to Zp into a separate
`b1` buffer (1,536 bytes), which was then immediately packed and discarded:

```c
PolyVec_Zp b1;  // 1,536 B — b is still live here
memset(b1, 0, sizeof(b1));
for (size_t i = 0; i < SABER_L; ++i)
    for (size_t j = 0; j < SABER_N; ++j)
        b1[i][j] = (Zp)(((b[i][j] + H1) >> (SABER_EQ - SABER_EP)) & MASK_Zp);
POLVECp2BS(b1, pk->pk); // b1 used once and done
```

### Fix

Round `b` in-place (using the extracted helper, see change 5) and pack from `b` directly:

```c
polyvec_round_zq_to_zp(b);
POLVECp2BS(b, pk->pk);
```

Safe because `b` is read before being overwritten at each index, and is not used after
the rounding loop. Since all coefficient types are `typedef uint16_t`, `PolyVec_Zq`
and `PolyVec_Zp` are the same underlying type — no cast required.

### Savings

- **1,536 bytes** of stack removed

---

## 4. Buffer reuse in `PKE_Enc`

**File:** `src/indcpa.c`

### Problem

`PKE_Enc` declared six large polynomial buffers, several of which were only used to
hold a transformed version of a buffer that was no longer needed:

| Buffer | Size | Role |
|---|---|---|
| `b` (PolyVec_Zq) | 1,536 B | Result of `A * s` |
| `b1` (PolyVec_Zp) | 1,536 B | `b` rounded to Zp — **b is dead after this** |
| `s` (PolyVec_Zq) | 1,536 B | Ephemeral secret |
| `s1` (PolyVec_Zp) | 1,536 B | `s` masked to Zp — **s is dead after this** |
| `v1` (Poly_Zp) | 512 B | Inner product result |
| `cm` (Poly_Zt) | 512 B | Compression of `v1 - m1` — **v1 is dead after this** |
| `m_bits` (Poly_Z2) | 512 B | Decoded message bits |
| `m1` (Poly_Zp) | 512 B | `m_bits` shifted to Zp — **m_bits is dead after this** |

Every dead-after transformation is an opportunity to reuse the original buffer.

### Fix

Four in-place rewrites, each safe because the operation reads then writes at the same
index with no aliasing:

#### `b` reused for `b1` (saves 1,536 B)
```c
matrix_vector_mul(A, s, b);
polyvec_round_zq_to_zp(b); // b now holds Zp values
// ...
POLVECp2BS(b, ct->bytes);  // pack directly from b
```

#### `s` reused for `s1` (saves 1,536 B)
```c
for (size_t i = 0; i < SABER_L; ++i)
    for (size_t j = 0; j < SABER_N; ++j)
        s[i][j] &= MASK_Zp; // mask in-place
inner_prod(b0, s, v1);      // pass s directly
```

#### `m_bits` reused for `m1` (saves 512 B)
```c
BS2POLmsg(m_bits, m);
for (size_t i = 0; i < SABER_N; ++i)
    m_bits[i] = (m_bits[i] << (SABER_EP - 1)) & MASK_Zp; // lift in-place
```

#### `v1` reused for `cm` (saves 512 B)
```c
inner_prod(b0, s, v1);
for (size_t i = 0; i < SABER_N; ++i) {
    Zp diff = (v1[i] - m_bits[i]) & MASK_Zp;
    v1[i] = ((diff + H1) >> (SABER_EP - SABER_ET)) & MASK_Zt; // compress in-place
}
POLT2BS(v1, ct->bytes + SABER_POLYVECCOMPRESSEDBYTES);
```

### Savings

- **4,096 bytes** of stack removed from `PKE_Enc`

---

## 5. Extract `polyvec_round_zq_to_zp` helper

**File:** `src/indcpa.c`

### Problem

The Zq-to-Zp rounding loop:
```c
for (size_t i = 0; i < SABER_L; ++i)
    for (size_t j = 0; j < SABER_N; ++j)
        v[i][j] = ((v[i][j] + H1) >> (SABER_EQ - SABER_EP)) & MASK_Zp;
```
appeared verbatim in both `PKE_KeyGen_Deterministic` and `PKE_Enc`, duplicating code
and emitting two copies in the binary.

### Fix

Extracted as a `static` helper at the top of `indcpa.c`:

```c
static void polyvec_round_zq_to_zp(PolyVec_Zq v) {
    for (size_t i = 0; i < SABER_L; ++i)
        for (size_t j = 0; j < SABER_N; ++j)
            v[i][j] = ((v[i][j] + H1) >> (SABER_EQ - SABER_EP)) & MASK_Zp;
}
```

Being `static` allows the compiler to inline it at both call sites at `-O3`, so
there is no call overhead — this is purely a source-level deduplication.

### Savings

- One redundant copy of the loop removed from the compiled binary
- Eliminates future divergence risk if the rounding formula ever changes

---

## 6. Compiler and linker flags

**File:** `Makefile`

### `-flto` — Link-Time Optimization

```makefile
CFLAGS ?= ... -flto ...
```

Passes the compiler's IR through to the linker so it can see the whole program at
once. Two effects relevant here:

- **Size**: functions that are called from only one translation unit (e.g. internal
  helpers that happen to be in a separate `.c`) can be inlined and their out-of-line
  copy removed.
- **Speed**: cross-module inlining exposes more opportunities for constant folding,
  dead store elimination, and register allocation across call boundaries.

Must be present in both `CFLAGS` (compile step) and the link command. Since the
Makefile uses single-step compilation, `$(LDFLAGS)` being passed to the same `$(CC)`
invocation is sufficient.

### `-ffunction-sections` / `-fdata-sections` + `-Wl,--gc-sections`

```makefile
CFLAGS  ?= ... -ffunction-sections -fdata-sections
LDFLAGS ?= -Wl,--gc-sections
```

By default, the linker keeps entire object files even if only one function inside them
is referenced. `-ffunction-sections` / `-fdata-sections` tell the compiler to give
every function and variable its own ELF section. The linker flag `--gc-sections` then
garbage-collects every section that is not reachable from a live entry point.

This is particularly effective for test and bench binaries that pull in `FULL_KEM_SRCS`
but only exercise a subset of the API.

### Cortex-M4 cross-compilation flags

`-march=native` was intentionally **not** added to the Makefile. That flag reads the
host CPU's capabilities at compile time, so on an x86_64 build machine it would emit
x86 instructions — wrong for a cross-compiled ARM binary.

For a Cortex-M4 target, pass the CPU flags via `CFLAGS` at the call site:

```sh
make CC=arm-none-eabi-gcc \
     CFLAGS="-O3 -std=gnu2x -flto -ffunction-sections -fdata-sections \
             -mcpu=cortex-m4 -mthumb -mfpu=fpv4-sp-d16 -mfloat-abi=hard"
```

Key flags for Cortex-M4:

| Flag | Purpose |
|---|---|
| `-mcpu=cortex-m4` | Targets the M4 core (enables DSP instructions) |
| `-mthumb` | Emits compact Thumb-2 instruction encoding |
| `-mfpu=fpv4-sp-d16` | Enables the M4's single-precision FPU |
| `-mfloat-abi=hard` | Passes float args in FPU registers (ABI must match libc) |

If the board has no FPU or the toolchain libc uses soft-float, use
`-mfloat-abi=softfp` (or `-mfloat-abi=soft` to disable the FPU entirely).

### Overriding from the command line

All Makefile variables use `?=`, so `CFLAGS` and `LDFLAGS` can be replaced entirely:

```sh
make CC=arm-none-eabi-gcc \
     CFLAGS="..." \
     LDFLAGS="-Wl,--gc-sections"
```
