# Gas Optimizations

Analysis and optimizations applied to reduce Move VM gas consumption during
SLH-DSA signature verification. Two rounds of optimization were performed.

## Results

| Metric | Baseline | Round 1 | Round 2 |
|---|---|---|---|
| **Total gas** | **3,857,031,826** | **1,582,057,847** (-59.0%) | **1,032,063,672** (-73.2%) |
| VM events | 58,734 | 39,658 (-32.5%) | 12,464 (-78.8%) |

### Per-function comparison (self gas)

| Function | Baseline | After Round 1 | After Round 2 |
|---|---|---|---|
| `thash::build_prefix` | 825M (21.4%) | 258M (16.3%) | 15M (1.5%) |
| `vector::append` | 689M (17.9%) | **eliminated** | **eliminated** |
| `adrs::compress` | 516M (13.4%) | **eliminated** | **eliminated** |
| `thash::truncate_n` | 449M (11.7%) | 270M (17.0%) | 16M (1.6%) |
| `thash::f` | 427M (11.1%) | 416M (26.3%) | **absorbed into fused chain** |
| `vector::reverse` | 395M (10.2%) | **eliminated** | **eliminated** |
| `utils::slice` | 216M (5.6%) | 213M (13.5%) | **eliminated** |
| `adrs::set_u32` | 91M (2.4%) | 89M (5.6%) | 20M (1.9%) |
| `hash::sha2_256` | 47M (1.2%) | 46M (2.9%) | 46M (4.4%) |
| `wots::chain` (fused) | 33M (0.9%) | 33M (2.1%) | 747M (72.4%) |

Seven functions were completely eliminated from the profile. The fused chain
now contains 72.4% of all gas — it absorbed work previously spread across
`thash::f`, `build_prefix`, `truncate_n`, `utils::slice`, and `adrs::set_hash`.
The `build_prefix` and `truncate_n` calls dropped from ~2,158 to 253 (only
non-chain callers remain). `adrs::set_u32` dropped from 2,785 to 880 calls
(1,905 chain `set_hash` calls eliminated).

## Baseline Profile (SLH-DSA-SHA2-128s transfer)

Total gas: **3,857,031,826** (~3.86B)

The actual SHA-256 computation was only **1.2%** of gas. The remaining 98.8% was
Move-level byte manipulation overhead: copying vectors, pushing bytes
one-at-a-time, and `vector::append` (which internally reverses the source
vector).

### Top self-gas consumers (baseline)

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
├─ fors_pk_from_sig (362M, 9.4%)
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

## Round 1 Optimizations

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

## Round 1 Profile (SLH-DSA-SHA2-128s transfer)

Total gas: **1,582,057,847** (~1.58B, -59.0% from baseline)

### Top self-gas consumers after Round 1

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

The remaining costs after Round 1 were dominated by:
- Repeated build_prefix + truncate_n calls from the chain hot loop (~1,919 of
  the ~2,158 calls)
- `utils::slice` creating intermediate vectors (510 calls)

## Round 2 Optimizations

### 5. Fused chain — prefix template + inline hash/truncate + skip adrs updates

Within `chain()`, `thash::f` / `build_prefix` / `truncate_n` were called
~1,919 times but the ADRS only changes in 4 bytes (the hash field at positions
82-85 of the input) between steps. Everything else — padded pk_seed, layer,
tree address, type, keypair, chain — stays fixed within a single chain call.

**Fix:** `chain()` in `wots.move` is now fully fused:
1. Builds an 86-byte prefix template **once per chain** (245 times total
   instead of 1,919 times)
2. Per step: copies the template (single 86-byte native copy), updates 4 hash
   bytes via `borrow_mut`, pushes 16 message bytes, calls `sha2_256`, and
   truncates via `pop_back` — all inline without calling `thash::f`,
   `build_prefix`, or `truncate_n`
3. First step reads message bytes directly from the signature at an offset
   (no intermediate slice vector)
4. Skips `adrs::set_hash` entirely — the caller (`wots_pk_from_sig`) calls
   `set_type_and_clear` after the chain loop, which overwrites the hash field

**Measured impact:** `build_prefix` dropped from 258M to 15M (253 non-chain
calls remain). `truncate_n` dropped from 270M to 16M. `thash::f` was
completely eliminated (absorbed into the fused chain). `adrs::set_u32` dropped
from 89M to 20M (1,905 fewer set_hash calls).

**Input prefix template layout (86 bytes):**
```
[0..63]:  padded pk_seed (constant across all chains)
[64]:     adrs[3]     — layer LSB
[65..72]: adrs[8..15] — tree address
[73]:     adrs[19]    — type LSB
[74..77]: adrs[20..23] — keypair
[78..81]: adrs[24..27] — chain (fixed within one chain call)
[82..85]: adrs[28..31] — hash (updated per step via borrow_mut)
```

### 6. Offset-based reads — eliminated nearly all utils::slice calls

`utils::slice` (213M, 13.5%) created new vectors by push_back loop. 510 calls
produced intermediate vectors just to pass data from one function to another.
The data was already present in the signature vector — it just needed to be
read at the right offset.

**Fix:** All functions now accept `(sig, offset)` pairs instead of pre-sliced
vectors. New offset-based thash variants (`f_from`, `h_right_from`,
`h_left_from`) read message bytes directly from a source vector at an offset.

| Caller | Change | Slices eliminated |
|---|---|---|
| `slh_dsa::verify_internal` | Passes full `sig` with `fors_offset` / `ht_offset` to fors and ht | 2 (2,912 + 4,928 bytes) |
| `ht::ht_verify` | Passes `(sig, layer_offset)` to xmss | 7 (704 bytes each) |
| `xmss::xmss_pk_from_sig` | Passes `(sig, xmss_offset)` to wots; reads auth path via `h_right_from` / `h_left_from` | 7 + 63 (560 + 16 bytes) |
| `wots::wots_pk_from_sig` | Passes `(sig, chain_offset)` to fused chain | 245 (16 bytes each) |
| `fors::fors_pk_from_sig` | Uses `f_from` for leaf hashes, `h_*_from` for auth paths | 14 + 168 (16 bytes each) |

**Measured impact:** `utils::slice` completely eliminated from the profile
(~504 of 510 calls removed). The remaining ~6 are one-time slices in
`verify_internal` (pk_seed, pk_root, R, md) with negligible cost.

## Round 2 Profile (SLH-DSA-SHA2-128s transfer)

Total gas: **1,032,063,672** (~1.03B, -73.2% from baseline, -34.8% from Round 1)

### Top self-gas consumers after Round 2

| Function | Self Gas | % | Calls |
|---|---|---|---|
| `wots::chain` (fused) | 747M | 72.4% | 245 |
| `wots::wots_pk_from_sig` | 62M | 6.0% | 7 |
| `thash::t_l` | 52M | 5.0% | 8 |
| `hash::sha2_256` | 46M | 4.4% | 2,160 |
| `thash::h_right_from` | 27M | 2.6% | 117 |
| `thash::h_left_from` | 25M | 2.4% | 114 |
| `adrs::set_u32` | 20M | 1.9% | 880 |
| `thash::truncate_n` | 16M | 1.6% | 253 |
| `thash::build_prefix` | 15M | 1.5% | 253 |
| `utils::base_2b` | 7M | 0.7% | 15 |

The fused chain now contains 72.4% of all gas. The remaining 27.6% is split
across WOTS+ accumulation (62M), T_l compression (52M), irreducible SHA-256
(46M), and auth path hashing (52M combined `h_left_from` / `h_right_from`).
All other functions are under 2% each.

## Possible Future Optimizations

### SHA-256 midstate precomputation (framework-level)

The first 64 bytes of every SHA-256 input (padded pk_seed) are identical across
all ~2,160 hash calls. A framework native like `sha256_with_midstate(midstate,
data)` would let us precompute the intermediate SHA-256 state after the first
block and skip ~2,159 redundant compression function evaluations. Currently
SHA-256 accounts for 46M (4.4%), but this percentage would grow if future
optimizations further reduce Move-level overhead.
