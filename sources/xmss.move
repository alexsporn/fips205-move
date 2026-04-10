/// XMSS (eXtended Merkle Signature Scheme) tree verification for SLH-DSA.
///
/// Each XMSS tree has height h' = h/d, giving 2^(h') leaves. Each leaf is a WOTS+
/// public key. An XMSS signature contains a WOTS+ signature plus a Merkle
/// authentication path of h' sibling hashes.
///
/// ## Gas Optimizations
/// - Reads WOTS+ signature and auth path directly from `sig` at offsets,
///   eliminating all intermediate slice vectors.
///
/// ## Reference
/// FIPS 205 Algorithm 11 (xmss_pkFromSig)
module fips205::xmss {
    use fips205::adrs;
    use fips205::thash;
    use fips205::wots;
    use fips205::params::{Self, Params};

    /// Compute XMSS public key (tree root) from signature (FIPS 205 Algorithm 11).
    ///
    /// Reads XMSS data directly from `sig[xmss_offset..]` ((len+hp)*n bytes).
    /// `idx`: leaf index within this XMSS tree (0 .. 2^hp - 1).
    /// `msg`: n bytes (leaf value to verify).
    /// `padded_pk_seed`: precomputed pk_seed || zeros (64 bytes).
    /// `adrs`: must have layer and tree address set.
    ///
    /// Returns the n-byte tree root.
    /// NOTE: adrs is modified (type changed to TREE on return).
    public(package) fun xmss_pk_from_sig(
        idx: u32,
        sig: &vector<u8>,
        xmss_offset: u64,
        msg: &vector<u8>,
        padded_pk_seed: &vector<u8>,
        adrs: &mut vector<u8>,
        p: &Params,
    ): vector<u8> {
        let n = params::n(p);
        let hp = params::hp(p);
        let len = params::len(p);

        // Step 1: recover WOTS+ public key
        // WOTS+ sig is at xmss_offset, length len*n
        adrs::set_type_and_clear(adrs, adrs::type_wots_hash());
        adrs::set_keypair(adrs, idx);
        let mut node = wots::wots_pk_from_sig(
            sig, xmss_offset, msg, padded_pk_seed, adrs, p,
        );

        // Step 2: walk up the XMSS Merkle tree (hp levels)
        // Auth path starts at xmss_offset + len*n
        adrs::set_type_and_clear(adrs, adrs::type_tree());
        adrs::set_tree_index(adrs, idx);
        let auth_base = xmss_offset + len * n;

        let mut k: u64 = 0;
        while (k < hp) {
            let auth_offset = auth_base + k * n;

            adrs::set_tree_height(adrs, ((k + 1) as u32));

            if (((idx as u64) >> (k as u8)) & 1 == 0) {
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

            k = k + 1;
        };

        node
    }
}
