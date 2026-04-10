/// FORS (Forest of Random Subsets) signature verification for SLH-DSA.
///
/// FORS is a few-time signature scheme that signs a message digest by revealing
/// one secret leaf value from each of k independent binary Merkle trees (height a).
/// The message digest provides an a-bit index into each tree.
///
/// ## Gas Optimizations
/// - Reads secret leaves and auth path nodes directly from `sig` at offsets
///   using `f_from` and `h_*_from`, eliminating all intermediate slice vectors.
/// - Uses push_back loops instead of append for root accumulation.
///
/// ## Reference
/// FIPS 205 Algorithm 17 (fors_pkFromSig)
module fips205::fors {
    use fips205::adrs;
    use fips205::thash;
    use fips205::utils;
    use fips205::params::{Self, Params};

    /// Compute FORS public key from signature (FIPS 205 Algorithm 17).
    ///
    /// Reads FORS data directly from `sig[fors_offset..]` (k*(1+a)*n bytes).
    /// `md`: `ceil(k * a / 8)` bytes of message digest.
    /// `padded_pk_seed`: precomputed pk_seed || zeros (64 bytes).
    /// `adrs`: must have type=FORS_TREE, tree and keypair set.
    ///
    /// Returns the n-byte FORS public key.
    /// NOTE: adrs is modified (type changed to FORS_ROOTS on return).
    public(package) fun fors_pk_from_sig(
        sig: &vector<u8>,
        fors_offset: u64,
        md: &vector<u8>,
        padded_pk_seed: &vector<u8>,
        adrs: &mut vector<u8>,
        p: &Params,
    ): vector<u8> {
        let n = params::n(p);
        let k = params::k(p);
        let a = params::a(p);
        let leaves_per_tree = 1u64 << (a as u8);  // 2^a
        let tree_sig_size = (1 + a) * n;

        // Extract k leaf indices, each a bits, from md
        let indices = utils::base_2b(md, a, k);

        // Accumulate tree roots (flat, k * n bytes)
        let mut roots = vector[];

        let mut i: u64 = 0;
        while (i < k) {
            let tree_offset = fors_offset + i * tree_sig_size;

            // Compute leaf hash — read secret directly from sig at offset
            adrs::set_tree_height(adrs, 0);
            adrs::set_tree_index(adrs, ((i * leaves_per_tree + indices[i]) as u32));
            let mut node = thash::f_from(padded_pk_seed, adrs, sig, tree_offset, p);

            // Walk authentication path upward (a levels)
            // Read auth nodes directly from sig at offsets
            let mut j: u64 = 0;
            while (j < a) {
                let auth_offset = tree_offset + n + j * n;

                adrs::set_tree_height(adrs, ((j + 1) as u32));

                if ((indices[i] >> (j as u8)) & 1 == 0) {
                    let ti = adrs::get_tree_index(adrs);
                    adrs::set_tree_index(adrs, ti / 2);
                    node = thash::h_right_from(
                        padded_pk_seed, adrs, &node, sig, auth_offset, p,
                    );
                } else {
                    let ti = adrs::get_tree_index(adrs);
                    adrs::set_tree_index(adrs, (ti - 1) / 2);
                    node = thash::h_left_from(
                        padded_pk_seed, adrs, sig, auth_offset, &node, p,
                    );
                };

                j = j + 1;
            };

            // Push node bytes directly instead of append
            let mut j = 0;
            while (j < n) {
                roots.push_back(node[j]);
                j = j + 1;
            };
            i = i + 1;
        };

        // Compress k roots into FORS public key using T_k
        let kp = adrs::get_keypair(adrs);
        adrs::set_type_and_clear(adrs, adrs::type_fors_roots());
        adrs::set_keypair(adrs, kp);
        thash::t_l(padded_pk_seed, adrs, &roots, p)
    }
}
