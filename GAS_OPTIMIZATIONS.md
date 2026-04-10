# Gas Optimizations

Analysis and optimizations applied to reduce Move VM gas consumption during
SLH-DSA signature verification. Four rounds of optimization were performed.

## Results

Raw gas totals vary between transactions because WOTS+ digit distributions
differ per signature, producing different chain step counts. The normalized
**gas per SHA-256 call** metric controls for this variance and gives the true
efficiency improvement.

| Round | Total Gas | SHA-256 Calls | Gas / Hash Call | vs Baseline |
|---|---|---|---|---|
| Baseline | 3,857,031,826 | 2,190 | 1,761,201 | — |
| Round 1 | 1,582,057,847 | 2,160 | 732,434 | -58.4% |
| Round 2 | 1,032,063,672 | 2,160 | 477,807 | -72.9% |
| Round 3 | 923,434,412 | 2,100 | 439,730 | -75.0% |
| **Round 4** | **926,570,900** | **2,220** | **417,374** | **-76.3%** |

### Per-function comparison (self gas)

| Function | Baseline | After R1 | After R2 | After R3 | After R4 |
|---|---|---|---|---|---|
| `thash::build_prefix` | 825M | 258M | 15M | 15M | 1M |
| `vector::append` | 689M | **gone** | **gone** | **gone** | **gone** |
| `adrs::compress` | 516M | **gone** | **gone** | **gone** | **gone** |
| `thash::truncate_n` | 449M | 270M | 16M | 16M | 1M |
| `thash::f` | 427M | 416M | **absorbed** | **absorbed** | **absorbed** |
| `vector::reverse` | 395M | **gone** | **gone** | **gone** | **gone** |
| `utils::slice` | 216M | 213M | **gone** | **gone** | **gone** |
| `thash::h_left/right_from` | — | — | 52M | 52M | **absorbed** |
| `adrs::set_u32` | 91M | 89M | 20M | 20M | 12M |
| `hash::sha2_256` | 47M | 46M | 46M | 44M | 48M |
| `wots::chain` (fused) | 33M | 33M | 747M | 639M | 675M |

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

### 1. Precompute padded PK seed

`build_prefix` was called 2,188 times. Each call copied `pk_seed` (16 bytes)
and pushed 48 zero bytes one-at-a-time. The pk_seed and its padding are
identical across all calls.

**Fix:** `pad_pk_seed()` in `thash.move` precomputes `pk_seed || zeros(48)`
once at the start of `verify_internal` and the 64-byte result is threaded
through the entire call chain (`slh_dsa` -> `ht` -> `xmss` -> `wots` ->
`fors` -> `thash`). Each `build_prefix` call now does a single 64-byte vector
copy instead of 16-byte copy + 48 push_backs.

### 2. Inline ADRS compression

`build_prefix` called `adrs::compress()` which created a new 22-byte vector,
then `input.append(compressed)` internally reversed the 22-byte vector and
pop-pushed each byte. Combined cost: `compress` (516M) + `append` (612M) +
`reverse` (351M) = ~1.48B on the build_prefix path alone.

**Fix:** `build_prefix` now pushes the 22 relevant ADRS bytes directly from the
full 32-byte ADRS vector using individual `push_back` calls. No intermediate
vector, no append, no reverse.

### 3. In-place truncation via pop_back

`truncate_n` was called 2,188 times. Each call allocated a new vector and
pushed the first `n` bytes one at a time (16 push_backs + 1 vector allocation).

**Fix:** `truncate_n` now takes ownership of the digest and removes excess
trailing bytes with `pop_back`. For n=16 and SHA-256's 32-byte output, this
pops 16 bytes instead of allocating a new vector + pushing 16 bytes.

### 4. Replace append with push_back loops

`vector::append` in Move internally reverses the source vector before popping
elements, making it O(2n) instead of O(n). Every accumulator pattern
(`tmp.append(node)` in WOTS+, `roots.append(node)` in FORS, context wrapping
in `verify`, message assembly in `h_msg` and `t_l`) paid this reverse penalty.

**Fix:** All `append` calls replaced with `push_back` loops that push bytes
directly from the source vector by index. This completely eliminated
`vector::append` (689M) and `vector::reverse` (395M) from the profile.

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
| `slh_dsa::verify_internal` | Passes full `sig` with `fors_offset` / `ht_offset` | 2 (2,912 + 4,928 bytes) |
| `ht::ht_verify` | Passes `(sig, layer_offset)` to xmss | 7 (704 bytes each) |
| `xmss::xmss_pk_from_sig` | Passes `(sig, xmss_offset)` to wots; reads auth via `h_*_from` | 7 + 63 (560 + 16 bytes) |
| `wots::wots_pk_from_sig` | Passes `(sig, chain_offset)` to fused chain | 245 (16 bytes each) |
| `fors::fors_pk_from_sig` | Uses `f_from` for leaf hashes, `h_*_from` for auth paths | 14 + 168 (16 bytes each) |

## Round 3 Optimizations

### 7. 102-byte template — eliminate push_back in chain steps

The Round 2 fused chain used an 86-byte prefix template and appended 16
message bytes per step via `push_back`. Each `push_back` includes capacity
checks and potential resize overhead.

**Fix:** The template is now 102 bytes (86 prefix + 16 message placeholder
zeros). Per step, message bytes are written via `borrow_mut` into pre-allocated
positions 86-101 instead of `push_back`. A single `copy(102)` replaces
`copy(86) + 16 push_back`.

### 8. Skip intermediate truncation — only truncate the final output

SHA-256 produces 32 bytes but only 16 are needed (n=16). The Round 2 chain
truncated via 16 `pop_back` operations after every step. However, the next
step only reads the first 16 bytes of the previous output (`tmp[0..15]`),
so the extra 16 bytes are harmless.

**Fix:** Intermediate hash results are kept at 32 bytes. Only the final
chain output is truncated to n bytes before returning. This eliminates
~1,674 truncation loops (16 `pop_back` each = ~26,784 operations).

### 9. Single-byte hash update — 1 borrow_mut instead of 4

For all FIPS 205 variants, the Winternitz parameter w ≤ 256, so the hash
step index j always fits in a single byte. The upper 3 bytes of the hash
field (positions 82-84) are always zero, which is already set in the template.

**Fix:** Only position 85 is updated per step (1 `borrow_mut` instead of 4).

**Chain input template layout (102 bytes):**
```
[0..63]:   padded pk_seed (constant across all chains)
[64]:      adrs[3]     — layer LSB
[65..72]:  adrs[8..15] — tree address
[73]:      adrs[19]    — type LSB
[74..77]:  adrs[20..23] — keypair
[78..81]:  adrs[24..27] — chain (fixed within one chain call)
[82..85]:  0,0,0,0     — hash field (only byte 85 updated per step)
[86..101]: 0..0        — message (16 bytes, updated per step via borrow_mut)
```

## Round 4 Optimizations

### 10. Fused auth path walks — template for Merkle tree hashing

The auth path walks in XMSS (63 h calls) and FORS (168 h calls) each called
`h_right_from` / `h_left_from`, which internally called `build_prefix` and
`truncate_n` per level. Combined: 231 calls × (build_prefix + 32 push_backs +
truncate_n) = 52M self + 32M sub-calls.

**Fix:** Both `xmss.move` and `fors.move` now fuse the auth path walk inline:
1. Build a 118-byte H template once (86 prefix + 16 m1 + 16 m2 placeholders).
   FORS reuses one template across all 14 trees (layer, tree_addr, type,
   keypair are constant).
2. Per level: copies the template (single 118-byte native copy), updates
   tree_height (1 `borrow_mut` at position 81) and tree_index (4 `borrow_mut`
   at positions 82-85), writes m1/m2 (32 `borrow_mut`), and calls `sha2_256`
3. Skips intermediate truncation — intermediate hashes stay at 32 bytes;
   FORS pushes only first n bytes into roots; XMSS truncates only the final
   result
4. Skips all ADRS updates during the walk — tracks tree_index as a local
   variable. The caller overwrites the ADRS after the walk returns.
5. Eliminates `h_right_from`, `h_left_from`, `build_prefix`, and `truncate_n`
   from the auth path hot loop

**Measured impact:** `build_prefix` dropped from 253 to 22 calls (1M, was 15M).
`truncate_n` dropped from 253 to 22 calls (1M, was 16M). `h_left/right_from`
completely eliminated. `adrs::set_u32` dropped from 880 to 418 calls (12M,
was 20M). The work is now visible as self-time in `xmss::xmss_pk_from_sig`
(44M) and `fors::fors_pk_from_sig` (20M).

**Auth path template layout (118 bytes):**
```
[0..63]:   padded pk_seed (constant)
[64]:      adrs[3]     — layer LSB
[65..72]:  adrs[8..15] — tree address
[73]:      adrs[19]    — type LSB
[74..77]:  adrs[20..23] — keypair (constant per tree type)
[78..81]:  0,0,0,0     — tree_height (byte 81 updated per level)
[82..85]:  0,0,0,0     — tree_index (updated per level)
[86..101]: 0..0        — m1 / left child (16 bytes, updated per level)
[102..117]: 0..0       — m2 / right child (16 bytes, updated per level)
```

## Round 4 Profile (SLH-DSA-SHA2-128s transfer)

Total gas: **926,570,900** (~927M). Normalized: **417,374 gas per SHA-256 call**
(-76.3% from baseline).

### Top self-gas consumers after Round 4

| Function | Self Gas | % | Calls |
|---|---|---|---|
| `wots::chain` (fused) | 675M | 72.9% | 245 |
| `wots::wots_pk_from_sig` | 62M | 6.7% | 7 |
| `thash::t_l` | 52M | 5.6% | 8 |
| `hash::sha2_256` | 48M | 5.1% | 2,220 |
| `xmss::xmss_pk_from_sig` (fused auth) | 44M | 4.7% | 7 |
| `fors::fors_pk_from_sig` (fused auth) | 20M | 2.2% | 1 |
| `adrs::set_u32` | 12M | 1.3% | 418 |
| `utils::base_2b` | 7M | 0.8% | 15 |
| `thash::build_prefix` | 1M | 0.1% | 22 |
| `thash::truncate_n` | 1M | 0.1% | 22 |

The remaining gas is dominated by the fused chain's irreducible per-step work
(102-byte vector copy + 17 `borrow_mut` + SHA-256), WOTS+ accumulation (62M),
T_l compression (52M), and the fused auth path walks (64M combined). The
SHA-256 native cost (48M, 5.1%) is now the floor — all Move-level overhead
has been minimized to ~4.2x the hash cost.

## Possible Future Optimizations

### SHA-256 midstate precomputation (framework-level)

The first 64 bytes of every SHA-256 input (padded pk_seed) are identical across
all ~2,200 hash calls. A framework native like `sha256_with_midstate(midstate,
data)` would precompute the intermediate SHA-256 state after the first block
and skip ~2,199 redundant compression function evaluations. This would also
reduce the vector copy per step from 102 → 38 bytes, roughly halving the
chain cost.
