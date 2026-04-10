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
/// ## Gas Optimizations
///
/// - `padded_pk_seed` (pk_seed || zeros to 64 bytes) is precomputed once per
///   verification and threaded through to avoid repeated zero-padding.
/// - ADRS compression is inlined: relevant bytes are pushed directly from the
///   full 32-byte ADRS, eliminating an intermediate vector allocation.
/// - `truncate_n` uses `pop_back` instead of allocating a new vector.
/// - `append` calls are replaced with `push_back` loops to avoid the expensive
///   internal `reverse` operation that `vector::append` performs.
/// - Offset-based variants (`f_from`, `h_right_from`, `h_left_from`) read
///   message bytes directly from a source vector at an offset, eliminating
///   intermediate `utils::slice` allocations in hot paths.
module fips205::thash {
    use std::hash;
    use fips205::params::{Self, Params};

    /// SHA-256 block size in bytes. The PK.seed is padded to this length.
    const SHA256_BLOCK: u64 = 64;

    /// Precompute the padded PK.seed: `pk_seed(n) || zeros(64-n)`.
    ///
    /// Called once at the start of verification and reused across all ~2,100+
    /// tweakable hash calls, avoiding repeated zero-padding loops.
    public(package) fun pad_pk_seed(pk_seed: &vector<u8>, p: &Params): vector<u8> {
        let n = params::n(p);
        let mut padded = *pk_seed;
        let pad_len = SHA256_BLOCK - n;
        let mut i = 0;
        while (i < pad_len) {
            padded.push_back(0u8);
            i = i + 1;
        };
        padded
    }

    /// Build the tweakable hash input prefix: `padded_pk_seed(64) || ADRS_c(22)`.
    ///
    /// Inlines the ADRS compression (FIPS 205 Algorithm 24) to avoid creating an
    /// intermediate 22-byte vector and the expensive `vector::append`.
    ///
    /// Compressed ADRS layout (22 bytes):
    /// `layer_lsb(1) || tree_addr(8) || type_lsb(1) || keypair(4) || chain(4) || hash(4)`
    fun build_prefix(padded_pk_seed: &vector<u8>, adrs: &vector<u8>): vector<u8> {
        let mut input = *padded_pk_seed;
        // Inline compressed ADRS (22 bytes) — no intermediate vector, no append
        input.push_back(adrs[3]);   // layer LSB
        input.push_back(adrs[8]);   // tree address bytes 8-15
        input.push_back(adrs[9]);
        input.push_back(adrs[10]);
        input.push_back(adrs[11]);
        input.push_back(adrs[12]);
        input.push_back(adrs[13]);
        input.push_back(adrs[14]);
        input.push_back(adrs[15]);
        input.push_back(adrs[19]);  // type LSB
        input.push_back(adrs[20]);  // keypair, chain, hash (bytes 20-31)
        input.push_back(adrs[21]);
        input.push_back(adrs[22]);
        input.push_back(adrs[23]);
        input.push_back(adrs[24]);
        input.push_back(adrs[25]);
        input.push_back(adrs[26]);
        input.push_back(adrs[27]);
        input.push_back(adrs[28]);
        input.push_back(adrs[29]);
        input.push_back(adrs[30]);
        input.push_back(adrs[31]);
        input
    }

    /// Truncate a 32-byte SHA-256 digest to n bytes (in-place via pop_back).
    fun truncate_n(mut digest: vector<u8>, p: &Params): vector<u8> {
        let n = params::n(p);
        let to_remove = digest.length() - n;
        let mut i = 0;
        while (i < to_remove) {
            digest.pop_back();
            i = i + 1;
        };
        digest
    }

    /// F: single-block tweakable hash (FIPS 205 Section 11.1).
    ///
    /// Message is read from a separate vector.
    /// For the hot-path chain loop, use the fused chain in wots.move instead.
    public(package) fun f(
        padded_pk_seed: &vector<u8>,
        adrs: &vector<u8>,
        m: &vector<u8>,
        p: &Params,
    ): vector<u8> {
        let n = params::n(p);
        let mut input = build_prefix(padded_pk_seed, adrs);
        let mut i = 0;
        while (i < n) {
            input.push_back(m[i]);
            i = i + 1;
        };
        truncate_n(hash::sha2_256(input), p)
    }

    /// F with offset: reads n message bytes from `source[offset .. offset+n]`.
    ///
    /// Avoids creating an intermediate slice vector when the message bytes are
    /// part of a larger signature buffer.
    public(package) fun f_from(
        padded_pk_seed: &vector<u8>,
        adrs: &vector<u8>,
        source: &vector<u8>,
        offset: u64,
        p: &Params,
    ): vector<u8> {
        let n = params::n(p);
        let mut input = build_prefix(padded_pk_seed, adrs);
        let mut i = 0;
        while (i < n) {
            input.push_back(source[offset + i]);
            i = i + 1;
        };
        truncate_n(hash::sha2_256(input), p)
    }

    /// H: two-block tweakable hash for Merkle tree nodes (FIPS 205 Section 11.1).
    ///
    /// Computes parent from left child `m1` and right child `m2`.
    public(package) fun h(
        padded_pk_seed: &vector<u8>,
        adrs: &vector<u8>,
        m1: &vector<u8>,
        m2: &vector<u8>,
        p: &Params,
    ): vector<u8> {
        let n = params::n(p);
        let mut input = build_prefix(padded_pk_seed, adrs);
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

    /// H with right child from offset: `m1` is a vector, right child read from
    /// `source[offset .. offset+n]`. Used for auth paths where the auth node
    /// comes from the signature buffer and the computed node is the left child.
    public(package) fun h_right_from(
        padded_pk_seed: &vector<u8>,
        adrs: &vector<u8>,
        m1: &vector<u8>,
        source: &vector<u8>,
        offset: u64,
        p: &Params,
    ): vector<u8> {
        let n = params::n(p);
        let mut input = build_prefix(padded_pk_seed, adrs);
        let mut i = 0;
        while (i < n) {
            input.push_back(m1[i]);
            i = i + 1;
        };
        i = 0;
        while (i < n) {
            input.push_back(source[offset + i]);
            i = i + 1;
        };
        truncate_n(hash::sha2_256(input), p)
    }

    /// H with left child from offset: left child read from
    /// `source[offset .. offset+n]`, `m2` is a vector. Used for auth paths
    /// where the auth node is the left child.
    public(package) fun h_left_from(
        padded_pk_seed: &vector<u8>,
        adrs: &vector<u8>,
        source: &vector<u8>,
        offset: u64,
        m2: &vector<u8>,
        p: &Params,
    ): vector<u8> {
        let n = params::n(p);
        let mut input = build_prefix(padded_pk_seed, adrs);
        let mut i = 0;
        while (i < n) {
            input.push_back(source[offset + i]);
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
    public(package) fun t_l(
        padded_pk_seed: &vector<u8>,
        adrs: &vector<u8>,
        ml: &vector<u8>,
        p: &Params,
    ): vector<u8> {
        let mut input = build_prefix(padded_pk_seed, adrs);
        let ml_len = ml.length();
        let mut i = 0;
        while (i < ml_len) {
            input.push_back(ml[i]);
            i = i + 1;
        };
        truncate_n(hash::sha2_256(input), p)
    }

    /// H_msg: message digest using MGF1-SHA-256 (FIPS 205 Section 11.2).
    ///
    /// Note: This function uses raw pk_seed (not padded) since it has a different
    /// hash input structure that doesn't use the tweakable hash prefix.
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
        let pk_seed_len = pk_seed.length();
        let mut i = 0;
        while (i < pk_seed_len) {
            hash_input.push_back(pk_seed[i]);
            i = i + 1;
        };
        let pk_root_len = pk_root.length();
        i = 0;
        while (i < pk_root_len) {
            hash_input.push_back(pk_root[i]);
            i = i + 1;
        };
        let msg_len = msg.length();
        i = 0;
        while (i < msg_len) {
            hash_input.push_back(msg[i]);
            i = i + 1;
        };
        let digest = hash::sha2_256(hash_input);

        // Step 2: build MGF1 seed = R || pk_seed || digest
        let mut seed = *r;
        i = 0;
        while (i < pk_seed_len) {
            seed.push_back(pk_seed[i]);
            i = i + 1;
        };
        let digest_len = digest.length();
        i = 0;
        while (i < digest_len) {
            seed.push_back(digest[i]);
            i = i + 1;
        };

        // Step 3: MGF1 expansion to m bytes
        let mut result = vector[];
        let mut counter: u32 = 0;
        while (result.length() < m) {
            let mut mgf_input = seed;
            mgf_input.push_back(((counter >> 24) as u8));
            mgf_input.push_back((((counter >> 16) & 0xFF) as u8));
            mgf_input.push_back((((counter >> 8) & 0xFF) as u8));
            mgf_input.push_back(((counter & 0xFF) as u8));
            let block = hash::sha2_256(mgf_input);

            let remaining = m - result.length();
            let take = if (remaining < 32) { remaining } else { 32 };
            let mut j = 0;
            while (j < take) {
                result.push_back(block[j]);
                j = j + 1;
            };
            counter = counter + 1;
        };
        result
    }
}
