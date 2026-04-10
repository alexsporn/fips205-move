/// FORS (Forest of Random Subsets) signature verification for SLH-DSA.
///
/// FORS is a few-time signature scheme that signs a message digest by revealing
/// one secret leaf value from each of k independent binary Merkle trees (height a).
/// The message digest provides an a-bit index into each tree.
///
/// ## Gas Optimizations
/// - Reads secret leaves via `f_from` directly from sig at offsets.
/// - Fused auth path walk: builds a 118-byte H template once (reused across
///   all k trees), per level copies the template and writes height/index/messages
///   via borrow_mut. Skips intermediate truncation.
/// - Uses push_back loops instead of append for root accumulation.
///
/// ## Reference
/// FIPS 205 Algorithm 17 (fors_pkFromSig)
module fips205::fors {
    use std::hash;
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

        // Build 118-byte H template for auth path walks.
        // Layer, tree_addr, type(FORS_TREE), keypair are constant across all k trees.
        // Tree_height and tree_index change per level (written via borrow_mut).
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
        h_tpl.push_back(adrs[19]);  // [73] type LSB (FORS_TREE=3)
        h_tpl.push_back(adrs[20]);  // [74..77] keypair (= idx_leaf, set by caller)
        h_tpl.push_back(adrs[21]);
        h_tpl.push_back(adrs[22]);
        h_tpl.push_back(adrs[23]);
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

        // Accumulate tree roots (flat, k * n bytes)
        let mut roots = vector[];

        let mut i: u64 = 0;
        while (i < k) {
            let tree_offset = fors_offset + i * tree_sig_size;

            // Compute leaf hash — read secret directly from sig at offset
            // (f_from still uses adrs directly, only 14 calls so not worth fusing)
            adrs::set_tree_height(adrs, 0);
            adrs::set_tree_index(adrs, ((i * leaves_per_tree + indices[i]) as u32));
            let mut node = thash::f_from(padded_pk_seed, adrs, sig, tree_offset, p);

            // Fused auth path walk (a levels) using template
            let mut ti = (i * leaves_per_tree + indices[i]);
            let mut j: u64 = 0;
            while (j < a) {
                let auth_offset = tree_offset + n + j * n;

                // Compute new tree_index
                let even = (indices[i] >> (j as u8)) & 1 == 0;
                if (even) {
                    ti = ti / 2;
                } else {
                    ti = (ti - 1) / 2;
                };

                let mut input = h_tpl;
                // Update tree_height (position 81, height < 256)
                *input.borrow_mut(81) = ((j + 1) as u8);
                // Update tree_index (positions 82-85)
                let ti32 = (ti as u32);
                *input.borrow_mut(82) = ((ti32 >> 24) as u8);
                *input.borrow_mut(83) = (((ti32 >> 16) & 0xFF) as u8);
                *input.borrow_mut(84) = (((ti32 >> 8) & 0xFF) as u8);
                *input.borrow_mut(85) = ((ti32 & 0xFF) as u8);

                // Write m1 (left child) and m2 (right child) via borrow_mut
                let mut m = 0;
                if (even) {
                    // node is left, auth from sig is right
                    while (m < n) { *input.borrow_mut(86 + m) = node[m]; m = m + 1; };
                    m = 0;
                    while (m < n) { *input.borrow_mut(102 + m) = sig[auth_offset + m]; m = m + 1; };
                } else {
                    // auth from sig is left, node is right
                    while (m < n) { *input.borrow_mut(86 + m) = sig[auth_offset + m]; m = m + 1; };
                    m = 0;
                    while (m < n) { *input.borrow_mut(102 + m) = node[m]; m = m + 1; };
                };

                // Hash — skip truncation for intermediate levels
                node = hash::sha2_256(input);

                j = j + 1;
            };

            // Push first n bytes of node into roots (node may be 32 bytes if untruncated)
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
