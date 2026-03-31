/// FORS (Forest of Random Subsets) signature verification for SLH-DSA.
///
/// FORS is a few-time signature scheme that signs a message digest by revealing
/// one secret leaf value from each of k independent binary Merkle trees (height a).
/// The message digest provides an a-bit index into each tree.
///
/// During verification, each revealed leaf is hashed, then the authentication path
/// (a sibling hashes) recomputes the tree root. All k roots are compressed into
/// a single FORS public key via T_k.
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
    /// `sig_fors`: `k * (1 + a) * n` flat bytes.
    /// `md`:       `ceil(k * a / 8)` bytes of message digest.
    /// `pk_seed`:  n bytes.
    /// `adrs`:     must have type=FORS_TREE, tree and keypair set.
    ///
    /// Returns the n-byte FORS public key.
    /// NOTE: adrs is modified (type changed to FORS_ROOTS on return).
    public(package) fun fors_pk_from_sig(
        sig_fors: &vector<u8>,
        md: &vector<u8>,
        pk_seed: &vector<u8>,
        adrs: &mut vector<u8>,
        p: &Params,
    ): vector<u8> {
        let n = params::n(p);
        let k = params::k(p);
        let a = params::a(p);
        let leaves_per_tree = 1u64 << (a as u8);  // 2^a

        // Extract k leaf indices, each a bits, from md
        let indices = utils::base_2b(md, a, k);

        // Accumulate tree roots (flat, k * n bytes)
        let mut roots = vector[];

        let mut i: u64 = 0;
        while (i < k) {
            // Parse this tree's portion: secret + auth path
            let tree_offset = i * (1 + a) * n;
            let sk = utils::slice(sig_fors, tree_offset, tree_offset + n);

            // Compute leaf hash
            adrs::set_tree_height(adrs, 0);
            adrs::set_tree_index(adrs, ((i * leaves_per_tree + indices[i]) as u32));
            let mut node = thash::f(pk_seed, adrs, &sk, p);

            // Walk authentication path upward (a levels)
            let mut j: u64 = 0;
            while (j < a) {
                let auth_offset = tree_offset + n + j * n;
                let auth_node = utils::slice(sig_fors, auth_offset, auth_offset + n);

                adrs::set_tree_height(adrs, ((j + 1) as u32));

                if ((indices[i] >> (j as u8)) & 1 == 0) {
                    let ti = adrs::get_tree_index(adrs);
                    adrs::set_tree_index(adrs, ti / 2);
                    node = thash::h(pk_seed, adrs, &node, &auth_node, p);
                } else {
                    let ti = adrs::get_tree_index(adrs);
                    adrs::set_tree_index(adrs, (ti - 1) / 2);
                    node = thash::h(pk_seed, adrs, &auth_node, &node, p);
                };

                j = j + 1;
            };

            roots.append(node);
            i = i + 1;
        };

        // Compress k roots into FORS public key using T_k
        let kp = adrs::get_keypair(adrs);
        adrs::set_type_and_clear(adrs, adrs::type_fors_roots());
        adrs::set_keypair(adrs, kp);
        thash::t_l(pk_seed, adrs, &roots, p)
    }
}
