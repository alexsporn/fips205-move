/// XMSS (eXtended Merkle Signature Scheme) tree verification for SLH-DSA.
///
/// Each XMSS tree has height h' = h/d, giving 2^(h') leaves. Each leaf is a WOTS+
/// public key. An XMSS signature contains a WOTS+ signature plus a Merkle
/// authentication path of h' sibling hashes.
///
/// ## Gas Optimizations
/// - Reads WOTS+ signature and auth path directly from `sig` at offsets.
/// - Fused auth path walk: builds a 118-byte H template once per tree, then
///   per level copies the template and writes height/index/messages via
///   borrow_mut. Skips ADRS updates and intermediate truncation.
///
/// ## Reference
/// FIPS 205 Algorithm 11 (xmss_pkFromSig)
module fips205::xmss {
    use std::hash;
    use fips205::adrs;
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
    /// NOTE: adrs is modified during WOTS+ recovery.
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
        adrs::set_type_and_clear(adrs, adrs::type_wots_hash());
        adrs::set_keypair(adrs, idx);
        let mut node = wots::wots_pk_from_sig(
            sig, xmss_offset, msg, padded_pk_seed, adrs, p,
        );

        // Step 2: fused Merkle tree walk (hp levels)
        // Build 118-byte H template: prefix(86) + m1(16) + m2(16)
        // ADRS: type=TREE, tree_index=idx, height/index updated per level via borrow_mut
        adrs::set_type_and_clear(adrs, adrs::type_tree());
        adrs::set_tree_index(adrs, idx);

        let mut h_tpl = *padded_pk_seed;
        h_tpl.push_back(adrs[3]);   // [64] layer LSB
        h_tpl.push_back(adrs[8]);   // [65..72] tree address
        h_tpl.push_back(adrs[9]);
        h_tpl.push_back(adrs[10]);
        h_tpl.push_back(adrs[11]);
        h_tpl.push_back(adrs[12]);
        h_tpl.push_back(adrs[13]);
        h_tpl.push_back(adrs[14]);
        h_tpl.push_back(adrs[15]);
        h_tpl.push_back(adrs[19]);  // [73] type LSB (TREE=2)
        h_tpl.push_back(0u8);       // [74..77] keypair (0, cleared)
        h_tpl.push_back(0u8);
        h_tpl.push_back(0u8);
        h_tpl.push_back(0u8);
        h_tpl.push_back(0u8);       // [78..81] tree_height placeholder
        h_tpl.push_back(0u8);
        h_tpl.push_back(0u8);
        h_tpl.push_back(0u8);
        h_tpl.push_back(0u8);       // [82..85] tree_index placeholder
        h_tpl.push_back(0u8);
        h_tpl.push_back(0u8);
        h_tpl.push_back(0u8);
        // m1 + m2 placeholders (32 bytes, positions 86-117)
        h_tpl.push_back(0u8); h_tpl.push_back(0u8); h_tpl.push_back(0u8); h_tpl.push_back(0u8);
        h_tpl.push_back(0u8); h_tpl.push_back(0u8); h_tpl.push_back(0u8); h_tpl.push_back(0u8);
        h_tpl.push_back(0u8); h_tpl.push_back(0u8); h_tpl.push_back(0u8); h_tpl.push_back(0u8);
        h_tpl.push_back(0u8); h_tpl.push_back(0u8); h_tpl.push_back(0u8); h_tpl.push_back(0u8);
        h_tpl.push_back(0u8); h_tpl.push_back(0u8); h_tpl.push_back(0u8); h_tpl.push_back(0u8);
        h_tpl.push_back(0u8); h_tpl.push_back(0u8); h_tpl.push_back(0u8); h_tpl.push_back(0u8);
        h_tpl.push_back(0u8); h_tpl.push_back(0u8); h_tpl.push_back(0u8); h_tpl.push_back(0u8);
        h_tpl.push_back(0u8); h_tpl.push_back(0u8); h_tpl.push_back(0u8); h_tpl.push_back(0u8);

        let auth_base = xmss_offset + len * n;
        let mut ti = (idx as u64);

        let mut k: u64 = 0;
        while (k < hp) {
            let auth_offset = auth_base + k * n;

            // Compute new tree_index based on idx bit k
            let even = ((idx as u64) >> (k as u8)) & 1 == 0;
            if (even) {
                ti = ti / 2;
            } else {
                ti = (ti - 1) / 2;
            };

            let mut input = h_tpl;
            // Update tree_height (position 81, height < 256)
            *input.borrow_mut(81) = ((k + 1) as u8);
            // Update tree_index (positions 82-85)
            let ti32 = (ti as u32);
            *input.borrow_mut(82) = ((ti32 >> 24) as u8);
            *input.borrow_mut(83) = (((ti32 >> 16) & 0xFF) as u8);
            *input.borrow_mut(84) = (((ti32 >> 8) & 0xFF) as u8);
            *input.borrow_mut(85) = ((ti32 & 0xFF) as u8);

            // Write m1 (left child) and m2 (right child) via borrow_mut
            let mut i = 0;
            if (even) {
                // node is left, auth from sig is right
                while (i < n) { *input.borrow_mut(86 + i) = node[i]; i = i + 1; };
                i = 0;
                while (i < n) { *input.borrow_mut(102 + i) = sig[auth_offset + i]; i = i + 1; };
            } else {
                // auth from sig is left, node is right
                while (i < n) { *input.borrow_mut(86 + i) = sig[auth_offset + i]; i = i + 1; };
                i = 0;
                while (i < n) { *input.borrow_mut(102 + i) = node[i]; i = i + 1; };
            };

            // Hash — skip truncation for intermediate levels
            node = hash::sha2_256(input);

            k = k + 1;
        };

        // Truncate final result to n bytes
        let to_pop = node.length() - n;
        let mut i = 0;
        while (i < to_pop) { node.pop_back(); i = i + 1; };
        node
    }
}
