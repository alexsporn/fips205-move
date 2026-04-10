# Gas Optimizations

Analysis and optimizations applied to reduce Move VM gas consumption during
SLH-DSA signature verification.

## Results

| Metric | Before | After | Change |
|---|---|---|---|
| **Total gas** | **3,857,031,826** | **1,582,057,847** | **-59.0%** |
| VM events | 58,734 | 39,658 | -32.5% |

### Per-function comparison (self gas)

| Function | Before | After | Savings |
|---|---|---|---|
| `thash::build_prefix` | 825M (21.4%) | 258M (16.3%) | -567M (-69%) |
| `vector::append` | 689M (17.9%) | **eliminated** | -689M (-100%) |
| `adrs::compress` | 516M (13.4%) | **eliminated** | -516M (-100%) |
| `thash::truncate_n` | 449M (11.7%) | 270M (17.0%) | -179M (-40%) |
| `thash::f` (overhead) | 427M (11.1%) | 416M (26.3%) | -11M |
| `vector::reverse` | 395M (10.2%) | **eliminated** | -395M (-100%) |
| `utils::slice` | 216M (5.6%) | 213M (13.5%) | unchanged |
| `adrs::set_u32` | 91M (2.4%) | 89M (5.6%) | unchanged |
| `hash::sha2_256` | 47M (1.2%) | 46M (2.9%) | unchanged |

Three entire functions were eliminated from the profile: `vector::append`,
`vector::reverse`, and `adrs::compress`.

## Baseline Profile (SLH-DSA-SHA2-128s transfer, before optimization)

Total gas: **3,857,031,826** (~3.86B)

The actual SHA-256 computation was only **1.2%** of gas. The remaining 98.8% was
Move-level byte manipulation overhead: copying vectors, pushing bytes
one-at-a-time, and `vector::append` (which internally reverses the source
vector).

### Top self-gas consumers before optimization

| Function | Self Gas | % | Calls | Issue |
|---|---|---|---|---|
| `thash::build_prefix` | 825M | 21.4% | 2,188 | Copies pk_seed + 48 zero-pads + appends ADRS each call |
| `vector::append` | 689M | 17.9% | 2,462 | Internally does reverse + pop-push loop |
| `adrs::compress` | 516M | 13.4% | 2,188 | Creates intermediate 22-byte vector |
| `thash::truncate_n` | 449M | 11.7% | 2,188 | Allocates new 16-byte vector per call |
| `thash::f` (overhead) | 427M | 11.1% | 1,949 | Orchestration around the above |
| `vector::reverse` | 395M | 10.2% | 2,462 | Called internally by every append |
| `utils::slice` | 216M | 5.6% | 510 | Creates new vectors by push_back loop |
| `adrs::set_u32` | 91M | 2.4% | 2,815 | 4x borrow_mut per call |
| `hash::sha2_256` | 47M | 1.2% | 2,190 | The actual cryptographic hash |

### Call structure

```
verify_internal (3.86B, 100%)
└─ fors_pk_from_sig (362M, 9.4%)
│  ├─ 14x f() for leaf hashes
│  ├─ 168x h() for auth paths (14 trees x 12 levels)
│  └─ 1x t_l() for root compression
└─ ht_verify (3.49B, 90.5%)
   └─ 7x xmss_pk_from_sig
      ├─ 7x wots_pk_from_sig (3.24B, 84%)
      │  ├─ 245x chain() -> 1,949x f()  <- HOT PATH
      │  └─ 7x t_l()
      └─ 63x h() for Merkle auth paths
```

## Optimizations Applied

### 1. Precompute padded PK seed — measured -567M on build_prefix

`build_prefix` was called 2,188 times. Each call copied `pk_seed` (16 bytes)
and pushed 48 zero bytes one-at-a-time. The pk_seed and its padding are
identical across all calls.

**Fix:** `pad_pk_seed()` in `thash.move` precomputes `pk_seed || zeros(48)`
once at the start of `verify_internal` and the 64-byte result is threaded
through the entire call chain (`slh_dsa` -> `ht` -> `xmss` -> `wots` ->
`fors` -> `thash`). Each `build_prefix` call now does a single 64-byte vector
copy instead of 16-byte copy + 48 push_backs.

### 2. Inline ADRS compression — eliminated compress + append + reverse

`build_prefix` called `adrs::compress()` which created a new 22-byte vector,
then `input.append(compressed)` internally reversed the 22-byte vector and
pop-pushed each byte. Combined cost: `compress` (516M) + `append` (612M) +
`reverse` (351M) = ~1.48B on the build_prefix path alone.

**Fix:** `build_prefix` now pushes the 22 relevant ADRS bytes directly from the
full 32-byte ADRS vector using individual `push_back` calls. No intermediate
vector, no append, no reverse.

### 3. In-place truncation via pop_back — measured -179M on truncate_n

`truncate_n` was called 2,188 times. Each call allocated a new vector and
pushed the first `n` bytes one at a time (16 push_backs + 1 vector allocation).

**Fix:** `truncate_n` now takes ownership of the digest and removes excess
trailing bytes with `pop_back`. For n=16 and SHA-256's 32-byte output, this
pops 16 bytes instead of allocating a new vector + pushing 16 bytes.

### 4. Replace append with push_back loops — eliminated all append/reverse gas

`vector::append` in Move internally reverses the source vector before popping
elements, making it O(2n) instead of O(n). Every accumulator pattern
(`tmp.append(node)` in WOTS+, `roots.append(node)` in FORS, context wrapping
in `verify`, message assembly in `h_msg` and `t_l`) paid this reverse penalty.

**Fix:** All `append` calls replaced with `push_back` loops that push bytes
directly from the source vector by index. This completely eliminated
`vector::append` (689M) and `vector::reverse` (395M) from the profile.

## Optimized Profile (SLH-DSA-SHA2-128s transfer, after optimization)

Total gas: **1,582,057,847** (~1.58B)

### Top self-gas consumers after optimization

| Function | Self Gas | % | Calls |
|---|---|---|---|
| `thash::f` (overhead) | 416M | 26.3% | 1,919 |
| `thash::truncate_n` | 270M | 17.0% | 2,158 |
| `thash::build_prefix` | 258M | 16.3% | 2,158 |
| `utils::slice` | 213M | 13.5% | 510 |
| `thash::h` | 92M | 5.8% | 231 |
| `adrs::set_u32` | 89M | 5.6% | 2,785 |
| `wots::wots_pk_from_sig` | 62M | 3.9% | 7 |
| `thash::t_l` | 52M | 3.3% | 8 |
| `hash::sha2_256` | 46M | 2.9% | 2,160 |
| `wots::chain` | 33M | 2.1% | 245 |

The remaining costs are dominated by irreducible work: 64-byte vector copies
in `build_prefix`, `pop_back` loops in `truncate_n`, byte pushing in `f()`,
and `utils::slice` vector construction.

## Possible Future Optimizations

### Offset-based slice avoidance

`utils::slice` (213M, 13.5%) creates new vectors by push_back loop. Hot-path
callers (245 WOTS chain slices, 63 XMSS auth path slices) could accept
`(vector_ref, offset)` pairs instead of pre-sliced vectors, but this requires
a larger API refactor.

### SHA-256 midstate precomputation (framework-level)

The first 64 bytes of every SHA-256 input (padded pk_seed) are identical across
all ~2,160 hash calls. A framework native like `sha256_with_midstate(midstate,
data)` would let us precompute the intermediate SHA-256 state after the first
block and skip ~2,159 redundant compression function evaluations.
