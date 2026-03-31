/// Tweakable hash functions for SLH-DSA SHA-256 variants (FIPS 205 Section 11.1).
///
/// All tweakable hashes share a common SHA-256 input structure:
///
/// ```
/// [ PK.seed (n bytes) | zero padding (64-n bytes) | ADRS_c (22 bytes) | message (varies) ]
///   <-------------- 64 bytes (one SHA-256 block) --------------------------->
/// ```
///
/// The first 64 bytes fill exactly one SHA-256 compression block, enabling an
/// optimization where the intermediate state can be precomputed once per PK.seed.
///
/// All outputs are truncated from 32 bytes (SHA-256) to n bytes.
///
/// ## SHA-256 Specificity
///
/// This module is specific to SHA-256-based variants (SLH-DSA-SHA2-128s/128f).
/// Future SHA-512-based variants (192s/192f/256s/256f) would need a parallel
/// `thash_sha512` module with 128-byte block padding and SHA-512 calls.
module fips205::thash {
    use std::hash;
    use fips205::adrs;
    use fips205::params::{Self, Params};

    /// SHA-256 block size in bytes. The PK.seed is padded to this length.
    const SHA256_BLOCK: u64 = 64;

    /// Build the common tweakable hash prefix: `pk_seed(n) || zeros(64-n) || ADRS_c(22)`.
    ///
    /// The prefix is 64 + 22 = 86 bytes for n=16 (SHA2-128 variants).
    fun build_prefix(pk_seed: &vector<u8>, adrs_bytes: &vector<u8>, p: &Params): vector<u8> {
        let n = params::n(p);
        let mut input = *pk_seed;
        // Pad pk_seed to SHA-256 block boundary (64 bytes)
        let pad_len = SHA256_BLOCK - n;
        let mut i = 0;
        while (i < pad_len) {
            input.push_back(0u8);
            i = i + 1;
        };
        // Append compressed ADRS (22 bytes)
        let compressed = adrs::compress(adrs_bytes);
        input.append(compressed);
        input
    }

    /// Truncate a 32-byte SHA-256 digest to n bytes.
    fun truncate_n(digest: vector<u8>, p: &Params): vector<u8> {
        let n = params::n(p);
        let mut result = vector[];
        let mut i = 0;
        while (i < n) {
            result.push_back(digest[i]);
            i = i + 1;
        };
        result
    }

    /// F: single-block tweakable hash (FIPS 205 Section 11.1).
    ///
    /// Used for WOTS+ chain steps and FORS leaf hashing.
    /// Input: `prefix || m(n)`. Output: n bytes.
    ///
    /// This is the most frequently called hash function (~85% of verification gas).
    public(package) fun f(
        pk_seed: &vector<u8>,
        adrs: &vector<u8>,
        m: &vector<u8>,
        p: &Params,
    ): vector<u8> {
        let n = params::n(p);
        let mut input = build_prefix(pk_seed, adrs, p);
        let mut i = 0;
        while (i < n) {
            input.push_back(m[i]);
            i = i + 1;
        };
        truncate_n(hash::sha2_256(input), p)
    }

    /// H: two-block tweakable hash for Merkle tree nodes (FIPS 205 Section 11.1).
    ///
    /// Computes parent from left child `m1` and right child `m2`.
    /// Input: `prefix || m1(n) || m2(n)`. Output: n bytes.
    public(package) fun h(
        pk_seed: &vector<u8>,
        adrs: &vector<u8>,
        m1: &vector<u8>,
        m2: &vector<u8>,
        p: &Params,
    ): vector<u8> {
        let n = params::n(p);
        let mut input = build_prefix(pk_seed, adrs, p);
        let mut i = 0;
        while (i < n) {
            input.push_back(m1[i]);
            i = i + 1;
        };
        i = 0;
        while (i < n) {
            input.push_back(m2[i]);
            i = i + 1;
        };
        truncate_n(hash::sha2_256(input), p)
    }

    /// T_l: multi-block tweakable hash for public key compression (FIPS 205 Section 11.1).
    ///
    /// Compresses `l` hash values (flat `ml` of `l * n` bytes) into n bytes.
    /// Used as T_len (WOTS+ pk, l=len) and T_k (FORS roots, l=k).
    public(package) fun t_l(
        pk_seed: &vector<u8>,
        adrs: &vector<u8>,
        ml: &vector<u8>,
        p: &Params,
    ): vector<u8> {
        let mut input = build_prefix(pk_seed, adrs, p);
        input.append(*ml);
        truncate_n(hash::sha2_256(input), p)
    }

    /// H_msg: message digest using MGF1-SHA-256 (FIPS 205 Section 11.2).
    ///
    /// Produces an m-byte digest from the message, randomness, and public key.
    /// The output is split by the caller into FORS indices, tree index, and leaf index.
    ///
    /// ## Algorithm
    /// 1. Inner digest: `SHA-256(R || pk_seed || pk_root || msg)`
    /// 2. MGF1 seed: `R || pk_seed || inner_digest`
    /// 3. Expand: for counter = 0, 1, ...: `SHA-256(seed || counter_be32)`, concatenate
    ///    until m bytes are produced.
    ///
    /// For m=30 (128s): 1 MGF1 iteration. For m=34 (128f): 2 iterations.
    public(package) fun h_msg(
        r: &vector<u8>,
        pk_seed: &vector<u8>,
        pk_root: &vector<u8>,
        msg: &vector<u8>,
        p: &Params,
    ): vector<u8> {
        let m = params::m(p);

        // Step 1: inner digest
        let mut hash_input = *r;
        hash_input.append(*pk_seed);
        hash_input.append(*pk_root);
        hash_input.append(*msg);
        let digest = hash::sha2_256(hash_input);

        // Step 2: build MGF1 seed = R || pk_seed || digest
        let mut seed = *r;
        seed.append(*pk_seed);
        seed.append(digest);

        // Step 3: MGF1 expansion to m bytes
        let mut result = vector[];
        let mut counter: u32 = 0;
        while (result.length() < m) {
            // SHA-256(seed || counter_be32)
            let mut mgf_input = seed;
            mgf_input.push_back(((counter >> 24) as u8));
            mgf_input.push_back((((counter >> 16) & 0xFF) as u8));
            mgf_input.push_back((((counter >> 8) & 0xFF) as u8));
            mgf_input.push_back(((counter & 0xFF) as u8));
            let block = hash::sha2_256(mgf_input);

            // Append min(32, m - result.length()) bytes
            let remaining = m - result.length();
            let take = if (remaining < 32) { remaining } else { 32 };
            let mut i = 0;
            while (i < take) {
                result.push_back(block[i]);
                i = i + 1;
            };
            counter = counter + 1;
        };
        result
    }
}
