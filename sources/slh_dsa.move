/// SLH-DSA signature verification core logic (FIPS 205 Algorithm 20).
///
/// This module contains the parameter-agnostic verification algorithm. It is called
/// by the parameter-set-specific entry points (`slh_dsa_sha2_128s`, `slh_dsa_sha2_128f`)
/// which supply the correct `Params`.
///
/// ## Verification Flow
///
/// 1. Validate public key and signature lengths against the parameter set
/// 2. Parse PK into `pk_seed` and `pk_root` (n bytes each)
/// 3. Parse signature into randomness R, FORS signature, and hypertree signature
/// 4. Wrap message for the "pure" variant: `[0x00, 0x00] || msg`
/// 5. Compute m-byte message digest via H_msg (MGF1-SHA-256)
/// 6. Extract FORS indices (`md`), tree index, and leaf index from the digest
/// 7. Recover the FORS public key from the FORS signature
/// 8. Verify the hypertree signature chains up to `pk_root`
module fips205::slh_dsa {
    use fips205::adrs;
    use fips205::thash;
    use fips205::fors;
    use fips205::ht;
    use fips205::utils;
    use fips205::params::{Self, Params};

    /// Verify an SLH-DSA signature using the given parameter set.
    ///
    /// This is the "pure" variant with empty context (`ctx = []`).
    /// The message is internally prepended with `[0x00, 0x00]` per FIPS 205 Section 10.2.
    ///
    /// `msg`: arbitrary-length message.
    /// `sig`: signature bytes (length must match `params.sig_len`).
    /// `pk`:  public key bytes (length must match `params.pk_len`).
    /// `ctx`: context string (0-255 bytes) for domain separation.
    /// `p`:   parameter set configuration.
    ///
    /// Returns true iff the signature is valid.
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
        wrapped_msg.append(*ctx);
        wrapped_msg.append(*msg);

        verify_internal(&wrapped_msg, sig, pk, p)
    }

    /// Internal verification (FIPS 205 Algorithm 22: `slh_verify_internal`).
    ///
    /// Verifies a signature against a pre-processed message (already includes any
    /// context wrapping). This is the raw algorithm used by NIST ACVP test vectors.
    ///
    /// For normal use, call `verify()` instead, which handles context wrapping.
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

        // Parse signature: R(n) || sig_fors || sig_ht
        let r = utils::slice(sig, 0, n);
        let fors_end = n + params::fors_sig_len(p);
        let sig_fors = utils::slice(sig, n, fors_end);
        let sig_ht = utils::slice(sig, fors_end, params::sig_len(p));

        // Compute m-byte message digest
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
        let idx_leaf = ((utils::to_int(&digest, md_len + idx_tree_len, idx_leaf_len))
            & idx_leaf_mask as u32);

        // Set up FORS address
        let mut sig_adrs = adrs::new();
        adrs::set_tree_address(&mut sig_adrs, idx_tree);
        adrs::set_type_and_clear(&mut sig_adrs, adrs::type_fors_tree());
        adrs::set_keypair(&mut sig_adrs, idx_leaf);

        // Recover FORS public key from signature
        let pk_fors = fors::fors_pk_from_sig(
            &sig_fors, &md, &pk_seed, &mut sig_adrs, p,
        );

        // Verify hypertree signature
        ht::ht_verify(&pk_fors, &sig_ht, &pk_seed, idx_tree, idx_leaf, &pk_root, p)
    }
}
