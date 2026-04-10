/// SLH-DSA signature verification core logic (FIPS 205 Algorithm 20).
///
/// This module contains the parameter-agnostic verification algorithm. It is called
/// by the parameter-set-specific entry points (`slh_dsa_sha2_128s`, `slh_dsa_sha2_128f`)
/// which supply the correct `Params`.
///
/// Two API variants are provided:
/// - `verify` / `verify_internal`: takes a single contiguous signature vector.
/// - `verify_split` / `verify_internal_split`: takes the signature as two parts
///   (R+FORS and HT), avoiding the `vector::append` cost when the signature
///   exceeds the transaction argument size limit (e.g. 128f at 17,088 bytes).
///
/// ## Gas Optimizations
///
/// - The padded PK.seed is precomputed once and threaded through the entire
///   call chain.
/// - The full signature vector is passed by reference with offsets to fors and ht,
///   eliminating the large sig_fors and sig_ht slice allocations.
module fips205::slh_dsa {
    use fips205::adrs;
    use fips205::thash;
    use fips205::fors;
    use fips205::ht;
    use fips205::utils;
    use fips205::params::{Self, Params};

    /// Verify an SLH-DSA signature using the given parameter set.
    ///
    /// This is the "pure" variant. The message is internally prepended with
    /// context wrapping per FIPS 205 Section 10.2.
    public(package) fun verify(
        msg: &vector<u8>,
        sig: &vector<u8>,
        pk: &vector<u8>,
        ctx: &vector<u8>,
        p: &Params,
    ): bool {
        // Context must be at most 255 bytes (FIPS 205 Section 10.2)
        if (ctx.length() > 255) return false;

        // Construct context-wrapped message for "pure" variant (Algorithm 20):
        // M' = toByte(0, 1) || toByte(|ctx|, 1) || ctx || M
        let mut wrapped_msg = vector[0u8, (ctx.length() as u8)];
        let ctx_len = ctx.length();
        let mut i = 0;
        while (i < ctx_len) {
            wrapped_msg.push_back(ctx[i]);
            i = i + 1;
        };
        let msg_len = msg.length();
        i = 0;
        while (i < msg_len) {
            wrapped_msg.push_back(msg[i]);
            i = i + 1;
        };

        verify_internal(&wrapped_msg, sig, pk, p)
    }

    /// Internal verification (FIPS 205 Algorithm 22: `slh_verify_internal`).
    ///
    /// Verifies a signature against a pre-processed message (already includes any
    /// context wrapping). This is the raw algorithm used by NIST ACVP test vectors.
    public(package) fun verify_internal(
        msg: &vector<u8>,
        sig: &vector<u8>,
        pk: &vector<u8>,
        p: &Params,
    ): bool {
        let n = params::n(p);

        // Validate sizes
        if (sig.length() != params::sig_len(p)) return false;
        if (pk.length() != params::pk_len(p)) return false;

        // Parse public key: pk_seed(n) || pk_root(n)
        let pk_seed = utils::slice(pk, 0, n);
        let pk_root = utils::slice(pk, n, 2 * n);

        // Precompute padded pk_seed once for entire verification
        let padded_pk_seed = thash::pad_pk_seed(&pk_seed, p);

        // Signature layout: R(n) || sig_fors(fors_sig_len) || sig_ht(d * xmss_sig_len)
        // We pass the full sig with offsets instead of slicing.
        let r = utils::slice(sig, 0, n);
        let fors_offset = n;
        let ht_offset = n + params::fors_sig_len(p);

        // Compute m-byte message digest (uses raw pk_seed, not padded)
        let digest = thash::h_msg(&r, &pk_seed, &pk_root, msg, p);

        // Split digest: md || idx_tree_bytes || idx_leaf_bytes
        let md_len = params::md_len(p);
        let idx_tree_len = params::idx_tree_len(p);
        let idx_leaf_len = params::idx_leaf_len(p);

        let md = utils::slice(&digest, 0, md_len);

        let idx_tree_bits = params::idx_tree_bits(p);
        let idx_tree_mask = (1u64 << (idx_tree_bits as u8)) - 1;
        let idx_tree = utils::to_int(&digest, md_len, idx_tree_len) & idx_tree_mask;

        let idx_leaf_bits = params::idx_leaf_bits(p);
        let idx_leaf_mask = (1u64 << (idx_leaf_bits as u8)) - 1;
        let idx_leaf = ((utils::to_int(&digest, md_len + idx_tree_len, idx_leaf_len)
            & idx_leaf_mask) as u32);

        // Set up FORS address
        let mut sig_adrs = adrs::new();
        adrs::set_tree_address(&mut sig_adrs, idx_tree);
        adrs::set_type_and_clear(&mut sig_adrs, adrs::type_fors_tree());
        adrs::set_keypair(&mut sig_adrs, idx_leaf);

        // Recover FORS public key from signature (reads from sig at fors_offset)
        let pk_fors = fors::fors_pk_from_sig(
            sig, fors_offset, &md, &padded_pk_seed, &mut sig_adrs, p,
        );

        // Verify hypertree signature (reads from sig at ht_offset)
        ht::ht_verify(
            &pk_fors, sig, ht_offset, &padded_pk_seed, idx_tree, idx_leaf, &pk_root, p,
        )
    }

    /// Verify with context, split signature variant.
    ///
    /// Takes the signature as two parts split at the natural FORS/HT boundary:
    /// - `sig_r_fors`: R(n) || sig_fors (n + fors_sig_len bytes)
    /// - `sig_ht`: hypertree signature (d * xmss_sig_len bytes)
    ///
    /// This avoids the `vector::append` cost when the full signature exceeds
    /// the transaction argument size limit.
    public(package) fun verify_split(
        msg: &vector<u8>,
        sig_r_fors: &vector<u8>,
        sig_ht: &vector<u8>,
        pk: &vector<u8>,
        ctx: &vector<u8>,
        p: &Params,
    ): bool {
        if (ctx.length() > 255) return false;

        let mut wrapped_msg = vector[0u8, (ctx.length() as u8)];
        let ctx_len = ctx.length();
        let mut i = 0;
        while (i < ctx_len) {
            wrapped_msg.push_back(ctx[i]);
            i = i + 1;
        };
        let msg_len = msg.length();
        i = 0;
        while (i < msg_len) {
            wrapped_msg.push_back(msg[i]);
            i = i + 1;
        };

        verify_internal_split(&wrapped_msg, sig_r_fors, sig_ht, pk, p)
    }

    /// Internal verification, split signature variant.
    ///
    /// `sig_r_fors`: R(n) || sig_fors — must be exactly n + fors_sig_len bytes.
    /// `sig_ht`: hypertree signature — must be exactly d * xmss_sig_len bytes.
    public(package) fun verify_internal_split(
        msg: &vector<u8>,
        sig_r_fors: &vector<u8>,
        sig_ht: &vector<u8>,
        pk: &vector<u8>,
        p: &Params,
    ): bool {
        let n = params::n(p);

        // Validate sizes
        if (sig_r_fors.length() != n + params::fors_sig_len(p)) return false;
        if (sig_ht.length() != params::sig_len(p) - n - params::fors_sig_len(p)) return false;
        if (pk.length() != params::pk_len(p)) return false;

        // Parse public key
        let pk_seed = utils::slice(pk, 0, n);
        let pk_root = utils::slice(pk, n, 2 * n);

        let padded_pk_seed = thash::pad_pk_seed(&pk_seed, p);

        // R is at sig_r_fors[0..n], FORS starts at offset n
        let r = utils::slice(sig_r_fors, 0, n);

        let digest = thash::h_msg(&r, &pk_seed, &pk_root, msg, p);

        let md_len = params::md_len(p);
        let idx_tree_len = params::idx_tree_len(p);
        let idx_leaf_len = params::idx_leaf_len(p);

        let md = utils::slice(&digest, 0, md_len);

        let idx_tree_bits = params::idx_tree_bits(p);
        let idx_tree_mask = (1u64 << (idx_tree_bits as u8)) - 1;
        let idx_tree = utils::to_int(&digest, md_len, idx_tree_len) & idx_tree_mask;

        let idx_leaf_bits = params::idx_leaf_bits(p);
        let idx_leaf_mask = (1u64 << (idx_leaf_bits as u8)) - 1;
        let idx_leaf = ((utils::to_int(&digest, md_len + idx_tree_len, idx_leaf_len)
            & idx_leaf_mask) as u32);

        let mut sig_adrs = adrs::new();
        adrs::set_tree_address(&mut sig_adrs, idx_tree);
        adrs::set_type_and_clear(&mut sig_adrs, adrs::type_fors_tree());
        adrs::set_keypair(&mut sig_adrs, idx_leaf);

        // FORS reads from sig_r_fors at offset n (R is at 0..n)
        let pk_fors = fors::fors_pk_from_sig(
            sig_r_fors, n, &md, &padded_pk_seed, &mut sig_adrs, p,
        );

        // HT reads from sig_ht at offset 0 (no concatenation needed)
        ht::ht_verify(
            &pk_fors, sig_ht, 0, &padded_pk_seed, idx_tree, idx_leaf, &pk_root, p,
        )
    }
}
