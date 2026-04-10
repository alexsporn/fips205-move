/// Hypertree signature verification for SLH-DSA.
///
/// The hypertree is a tower of d XMSS trees stacked vertically. It certifies the
/// FORS public key by chaining tree roots upward until the final root matches PK.root.
///
/// At each layer transition, the low hp bits of the remaining tree index become
/// the leaf index in the next layer, and the index is right-shifted by hp bits.
///
/// ## Reference
/// FIPS 205 Algorithm 13 (ht_verify)
module fips205::ht {
    use fips205::adrs;
    use fips205::utils;
    use fips205::xmss;
    use fips205::params::{Self, Params};

    /// Verify a hypertree signature (FIPS 205 Algorithm 13).
    ///
    /// `msg`:       n bytes (the FORS public key).
    /// `sig_ht`:    `d * xmss_sig_len` flat bytes.
    /// `padded_pk_seed`: precomputed pk_seed || zeros (64 bytes).
    /// `idx_tree`:  tree index from message digest (h - hp bits).
    /// `idx_leaf`:  leaf index from message digest (hp bits).
    /// `pk_root`:   n bytes (expected root).
    ///
    /// Returns true iff the computed root matches pk_root.
    public(package) fun ht_verify(
        msg: &vector<u8>,
        sig_ht: &vector<u8>,
        padded_pk_seed: &vector<u8>,
        idx_tree: u64,
        idx_leaf: u32,
        pk_root: &vector<u8>,
        p: &Params,
    ): bool {
        let d = params::d(p);
        let hp = params::hp(p);
        let xmss_sig_size = params::xmss_sig_len(p);
        let leaf_mask = (1u64 << (hp as u8)) - 1;

        let mut ht_adrs = adrs::new();
        adrs::set_tree_address(&mut ht_adrs, idx_tree);

        // Layer 0
        let sig_0 = utils::slice(sig_ht, 0, xmss_sig_size);
        let mut node = xmss::xmss_pk_from_sig(
            idx_leaf, &sig_0, msg, padded_pk_seed, &mut ht_adrs, p,
        );

        // Layers 1 .. d-1
        let mut tree = idx_tree;
        let mut j: u64 = 1;
        while (j < d) {
            let leaf = ((tree & leaf_mask) as u32);
            tree = tree >> (hp as u8);
            adrs::set_layer(&mut ht_adrs, (j as u32));
            adrs::set_tree_address(&mut ht_adrs, tree);
            let sig_offset = j * xmss_sig_size;
            let sig_j = utils::slice(sig_ht, sig_offset, sig_offset + xmss_sig_size);
            node = xmss::xmss_pk_from_sig(
                leaf, &sig_j, &node, padded_pk_seed, &mut ht_adrs, p,
            );
            j = j + 1;
        };

        // Final root must equal pk_root
        &node == pk_root
    }
}
