# SLH-DSA Signature Verification in Move

> **Experimental software.** This implementation has not been audited and is not intended for production use. Use at your own risk.

A pure Move implementation of **FIPS 205 (SLH-DSA)** post-quantum digital signature verification, targeting the **IOTA** blockchain.

This package implements the **SHA2-128s** and **SHA2-128f** parameter sets, with a generic architecture designed for future extension to 192/256-bit variants once SHA-512 native support is available.

## What is SLH-DSA?

**SLH-DSA** (Stateless Hash-Based Digital Signature Algorithm), standardized as [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) by NIST in August 2024, is a post-quantum signature scheme. Its security relies solely on the collision resistance and one-wayness of SHA-256 -- no algebraic structure means it is immune to Shor's algorithm (quantum attacks that break RSA and elliptic curve cryptography).

SLH-DSA builds signatures from three nested layers of hash-based constructions:

```
SLH-DSA Signature
  |
  +-- FORS (Forest of Random Subsets)    -- few-time signature from random subsets
  |     |
  |     +-- k binary Merkle trees (height a each)
  |
  +-- Hypertree                          -- certifies the FORS key
        |
        +-- d XMSS trees (height h/d each)
              |
              +-- WOTS+ one-time signatures (len hash chains, Winternitz w=16)
```

## Supported Parameter Sets

### SHA2-128s (small signatures)

| Parameter | Value | Description |
|-----------|-------|-------------|
| `n` | 16 | Security parameter (bytes); hash output length |
| `h` | 63 | Total hypertree height |
| `d` | 7 | Number of XMSS tree layers |
| `h/d` | 9 | Height of each XMSS tree (512 leaves) |
| `a` | 12 | FORS tree height (4096 leaves per tree) |
| `k` | 14 | Number of FORS trees |
| `w` | 16 | Winternitz parameter |
| `len` | 35 | WOTS+ chain count (len1=32 + len2=3) |
| `m` | 30 | Message digest bytes (21 + 7 + 2) |

### SHA2-128f (fast signing)

| Parameter | Value | Description |
|-----------|-------|-------------|
| `n` | 16 | Security parameter (bytes); hash output length |
| `h` | 66 | Total hypertree height |
| `d` | 22 | Number of XMSS tree layers |
| `h/d` | 3 | Height of each XMSS tree (8 leaves) |
| `a` | 6 | FORS tree height (64 leaves per tree) |
| `k` | 33 | Number of FORS trees |
| `w` | 16 | Winternitz parameter |
| `len` | 35 | WOTS+ chain count (len1=32 + len2=3) |
| `m` | 34 | Message digest bytes (25 + 8 + 1) |

### Key and Signature Sizes

| Component | 128s | 128f |
|-----------|------|------|
| Public key | 32 bytes | 32 bytes |
| **Signature** | **7,856 bytes** | **17,088 bytes** |
| -- Randomness (R) | 16 bytes | 16 bytes |
| -- FORS signature | 2,912 bytes | 3,696 bytes |
| -- Hypertree signature | 4,928 bytes | 13,376 bytes |
| ~SHA-256 calls | ~2,100 | ~6,100 |

### Future Parameter Sets (require SHA-512)

| Variant | n | Sig bytes | Status |
|---------|---|-----------|--------|
| SHA2-192s | 24 | 16,224 | Planned (needs `sha2_512`) |
| SHA2-192f | 24 | 35,664 | Planned (needs `sha2_512`) |
| SHA2-256s | 32 | 29,792 | Planned (needs `sha2_512`) |
| SHA2-256f | 32 | 49,856 | Planned (needs `sha2_512`) |

## Quick Start

### Build

```bash
iota move build
```

### Test

Tests require a high gas limit due to the many SHA-256 calls per verification:

```bash
iota move test -i 100000000000
```

### Usage in Move

```move
use fips205::slh_dsa_sha2_128s;  // or slh_dsa_sha2_128f

// Verify with empty context (most common)
let is_valid: bool = slh_dsa_sha2_128s::verify(&msg, &sig, &pk);

// Verify with a context string for domain separation (0-255 bytes)
let is_valid: bool = slh_dsa_sha2_128s::verify_with_context(&msg, &sig, &pk, &ctx);
```

Both variants implement FIPS 205 Algorithm 20 ("pure" mode). The message is internally wrapped as `M' = toByte(0,1) || toByte(|ctx|,1) || ctx || M` per Section 10.2.

## Module Architecture

```
slh_dsa_sha2_128s.move   Public entry point (128s)  ──┐
slh_dsa_sha2_128f.move   Public entry point (128f)  ──┤
                                                       │
params.move              Parameter set definitions  ───┤
                                                       ▼
slh_dsa.move             Core verify logic (parameterized)
    |                      verify()          = Algorithm 20 (context wrapping)
    |                      verify_internal() = Algorithm 22 (raw)
    |
    +-- fors.move        FORS public key recovery (Algorithm 17)
    |     |
    |     +-- thash.move   Tweakable SHA-256 hash functions (F, H, T_l)
    |     +-- adrs.move    ADRS domain separation structure
    |     +-- utils.move   Byte manipulation helpers
    |
    +-- ht.move          Hypertree verification (Algorithm 13)
          |
          +-- xmss.move  XMSS tree verification (Algorithm 11)
                |
                +-- wots.move  WOTS+ signature recovery (Algorithm 8)
                      |
                      +-- thash.move
                      +-- adrs.move
                      +-- utils.move
```

### Module Descriptions

#### `slh_dsa_sha2_128s.move` / `slh_dsa_sha2_128f.move` -- Entry Points

Thin wrappers that call `slh_dsa::verify` with the correct parameter set. Expose `verify()` (empty context) and `verify_with_context()`. These are the only modules with `public` functions.

#### `params.move` -- Parameter Set Configuration

Defines the `Params` struct bundling all SLH-DSA constants (n, h, d, h', a, k, w, len, m, etc.) plus precomputed derived sizes. Provides constructors `sha2_128s()` and `sha2_128f()`. Adding a new variant is as simple as adding a new constructor.

#### `slh_dsa.move` -- Core Verification Logic

Two verification functions, matching FIPS 205:

- **`verify`** (Algorithm 20): Takes a message and context string, constructs `M' = [0x00, ctx_len, ctx, M]`, calls `verify_internal`. Context must be 0-255 bytes.
- **`verify_internal`** (Algorithm 22): The core cryptographic algorithm. Takes an already-wrapped message and performs the full verification pipeline:

  1. Validates public key and signature lengths against the parameter set
  2. Parses PK into `pk_seed` and `pk_root` (n bytes each)
  3. Parses signature into `R` (randomness), FORS signature, and hypertree signature
  4. Computes the m-byte message digest via `H_msg` (MGF1-SHA-256)
  5. Splits the digest into FORS indices, tree index, and leaf index
  6. Recovers the FORS public key from the FORS signature component
  7. Verifies the hypertree signature against `pk_root`

#### `fors.move` -- Forest of Random Subsets

Implements FIPS 205 Algorithm 17 (`fors_pkFromSig`).

Recovers the FORS public key by:
- Extracting k leaf indices (a bits each) from the message digest
- For each tree: hashing the secret value to get the leaf, then walking the authentication path to compute the tree root
- Compressing all k roots into a single public key via `T_k`

#### `ht.move` -- Hypertree

Implements FIPS 205 Algorithm 13 (`ht_verify`).

Verifies a chain of d XMSS trees from bottom to top:
- Layer 0: verifies the FORS public key as a leaf in the bottom XMSS tree
- Layers 1 to d-1: each layer verifies the root of the previous layer's tree
- The final root must match `pk_root`

At each layer, `idx_tree` is shifted right by h' bits to select the next tree, and the low h' bits become the next `idx_leaf`.

#### `xmss.move` -- Extended Merkle Signature Scheme

Implements FIPS 205 Algorithm 11 (`xmss_pkFromSig`).

Each XMSS signature contains:
- A WOTS+ signature (len * n bytes)
- An authentication path (h' * n bytes)

The function:
1. Recovers the WOTS+ public key from the signature
2. Walks the h'-level Merkle authentication path to compute the tree root

#### `wots.move` -- Winternitz One-Time Signature

Implements FIPS 205 Algorithms 5 and 8 (`chain` and `wots_pkFromSig`).

WOTS+ uses len hash chains of length w (Winternitz parameter):
1. The n-byte message is converted to len1 base-w digits
2. A len2-digit checksum is computed and appended (total: len chain lengths)
3. Each signature chain value is hashed forward `(w-1 - digit)` times to reach the chain endpoint
4. All len endpoints are compressed into the WOTS+ public key via `T_len`

The chain computation dominates gas cost (~85% of total verification).

#### `thash.move` -- Tweakable Hash Functions

All hash functions use SHA-256 with a common input structure:

```
[ PK.seed (n) | zero-padding (64-n) | ADRS_c (22) | message (varies) ]
  <------------- 64 bytes (one SHA-256 block) ------------>
```

The 64-byte prefix (PK.seed + padding) fills exactly one SHA-256 block, enabling potential precomputation optimizations in native implementations.

| Function | Purpose |
|----------|---------|
| `F` | WOTS+ chain step, FORS leaf hash |
| `H` | Merkle tree internal node |
| `T_len` | WOTS+ public key compression |
| `T_k` | FORS public key compression |
| `H_msg` | Message digest (MGF1-SHA-256) |

`H_msg` uses MGF1-SHA-256 expansion. For 128s (m=30), 1 iteration suffices. For 128f (m=34), 2 iterations are needed.

#### `adrs.move` -- Address Structure

The ADRS (Address) is a 32-byte domain separation value included in every hash call. It ensures that identical inputs in different contexts produce different outputs.

**Full ADRS layout (32 bytes, all fields big-endian):**

```
Offset  Size  Field
 0       4    Layer address       (hypertree layer)
 4       4    Padding             (always zero)
 8       4    Tree address high   (upper 32 bits of tree index)
12       4    Tree address low    (lower 32 bits of tree index)
16       4    Type                (0=WOTS_HASH, 1=WOTS_PK, 2=TREE, 3=FORS_TREE, 4=FORS_ROOTS)
20       4    Key pair address    (leaf index within XMSS tree)
24       4    Chain / Tree height (WOTS+ chain index, or Merkle tree level)
28       4    Hash / Tree index   (WOTS+ step index, or Merkle node position)
```

Compressed to 22 bytes for SHA-256 input by dropping redundant high bytes (Algorithm 24).

#### `utils.move` -- Byte Manipulation Helpers

| Function | Description |
|----------|-------------|
| `slice(v, start, end)` | Extract sub-range `[start, end)` from a byte vector |
| `to_int(v, start, len)` | Interpret bytes as big-endian `u64` |
| `to_byte(x, n)` | Convert `u64` to n-byte big-endian byte vector |
| `base_2b(input, b, out_len)` | Extract base-2^b digits from a byte string |

## Gas Cost Analysis (SHA2-128s)

Gas formula per `sha2_256` call: `52 + (2 x input_bytes)`.

| Component | Hash calls | Gas each | Total gas |
|-----------|-----------|----------|-----------|
| H_msg (message digest) | 2 | 220 | 440 |
| FORS: F (leaf hashing) | 14 | 256 | 3,584 |
| FORS: H (auth paths) | 168 | 288 | 48,384 |
| FORS: T_k (root compression) | 1 | 672 | 672 |
| WOTS+ chains (7 layers x ~262 F) | ~1,838 | 256 | 470,528 |
| WOTS+ T_len (pk compression) | 7 | 1,344 | 9,408 |
| XMSS: H (auth paths) | 63 | 288 | 18,144 |
| **Total** | **~2,093** | | **~551,000** |

WOTS+ chain computation dominates at ~85% of total cost.

## Signature Format (SHA2-128s)

```
Offset   Size   Component
0        16     R (randomness)
16       2912   FORS signature
  Per tree (14 trees, 208 bytes each):
    +0     16     Secret value (sk)
    +16    192    Authentication path (12 nodes x 16 bytes)
2928     4928   Hypertree signature
  Per layer (7 layers, 704 bytes each):
    +0     560    WOTS+ signature (35 chains x 16 bytes)
    +560   144    Authentication path (9 nodes x 16 bytes)
```

**Total:** 16 + 2,912 + 4,928 = **7,856 bytes**

## Testing

64 tests validated against two independent sources:

| Test file | Source | Tests |
|-----------|--------|-------|
| `slh_dsa_sha2_128s_tests` | Rust `fips205` v0.4 crate | 4 |
| `slh_dsa_sha2_128f_tests` | Rust `fips205` v0.4 crate | 4 |
| `slh_dsa_sha2_128s_acvp_tests` | NIST ACVP (`internal`, Algorithm 22) | 14 |
| `slh_dsa_sha2_128f_acvp_tests` | NIST ACVP (`internal`, Algorithm 22) | 14 |
| `slh_dsa_sha2_128s_acvp_ctx_tests` | NIST ACVP (`external/pure`, Algorithm 20 with context) | 14 |
| `slh_dsa_sha2_128f_acvp_ctx_tests` | NIST ACVP (`external/pure`, Algorithm 20 with context) | 14 |

ACVP vectors sourced from the [NIST ACVP Server](https://github.com/usnistgov/ACVP-Server) (`SLH-DSA-sigVer-FIPS205`). Invalid test cases cover: modified R, modified FORS signature, modified hypertree signature, modified message, signature too short, and signature too long.

The `external/preHash` ACVP vectors (pre-hash mode with OID prefix) are not implemented -- this mode is for signing large data without buffering and is not relevant for on-chain verification.

## Design Decisions

### Verification-Only

This package only implements signature **verification** (the on-chain operation). Key generation and signing are not included -- those operations happen off-chain and are available in the [Rust reference implementation](https://github.com/integritychain/fips205).

### Generic Parameterization

All algorithm modules receive a `&Params` struct rather than using hardcoded constants. Adding a new parameter set requires only a new `Params` constructor and a thin entry-point module. The hash function (`thash.move`) is SHA-256 specific; future SHA-512 variants would need a parallel `thash_sha512.move`.

### Flat Byte Vectors

All data structures (ADRS, signatures, keys) are represented as flat `vector<u8>` rather than Move structs. This avoids Move's struct serialization overhead and maps directly to the byte-level specification.

### Package Visibility

All internal functions use `public(package)` visibility. Only the entry-point modules expose `public` functions.

## Move-Specific Notes

- **No recursion:** Move disallows recursive calls. All tree traversals use iterative loops.
- **No const generics:** Parameters passed via `&Params` struct at runtime.
- **No index assignment:** `v[i] = x` not supported; all mutations use `*v.borrow_mut(i) = x`.
- **Integer casts:** Shift operators require `u8` right operands. Values are cast explicitly.

## Security Considerations

- **128-bit classical security** -- equivalent to Ed25519/P-256
- **Post-quantum secure** -- based solely on SHA-256 properties (one-wayness, collision resistance); no algebraic structure vulnerable to Shor's algorithm
- **Domain separation** -- every hash call includes a unique ADRS value, preventing cross-context attacks
- **Context support** -- optional context strings for application-level domain separation
- **Stateless** -- no state management required between signing operations (unlike XMSS/LMS)

## References

- **FIPS 205:** https://csrc.nist.gov/pubs/fips/205/final
- **Rust reference implementation:** https://github.com/integritychain/fips205
- **NIST ACVP test vectors:** https://github.com/usnistgov/ACVP-Server
- **SLH-DSA specification (original SPHINCS+):** https://sphincs.org/
- **IOTA Move documentation:** https://docs.iota.org/developer/

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
