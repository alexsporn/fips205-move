/// WOTS+ (Winternitz One-Time Signature) verification for SLH-DSA.
///
/// WOTS+ signs an n-byte message by encoding it as base-w digits, where each digit
/// selects a position within a hash chain. Verification completes each chain from
/// the signature value to the endpoint, then compresses all endpoints.
///
/// For all SHA2-128 variants (w=16): 35 chains, each of length 16 (steps 0..15).
/// Average chain completion: 7.5 F calls per chain.
///
/// ## Gas Optimizations (Round 2)
///
/// The chain function is fully fused: it builds an 86-byte SHA-256 input prefix
/// template once per chain, then per step only copies the template, updates
/// 4 bytes (hash field) via borrow_mut, pushes 16 message bytes, hashes, and
/// truncates inline. This eliminates ~1,674 separate build_prefix + truncate_n
/// calls and ~1,905 adrs::set_hash calls.
///
/// Reads signature bytes at offsets (no intermediate slice vectors).
///
/// ## References
/// - FIPS 205 Algorithm 5 (chain)
/// - FIPS 205 Algorithm 8 (wots_pkFromSig)
module fips205::wots {
    use std::hash;
    use fips205::adrs;
    use fips205::thash;
    use fips205::utils;
    use fips205::params::{Self, Params};

    /// Compute WOTS+ public key from signature (FIPS 205 Algorithm 8).
    ///
    /// Reads WOTS+ chain values directly from `sig[sig_offset..]` (len*n bytes).
    /// `msg`: n bytes (message to verify).
    /// `padded_pk_seed`: precomputed pk_seed || zeros (64 bytes).
    /// `adrs`: must have type=WOTS_HASH and key pair set.
    ///
    /// Returns the n-byte WOTS+ public key.
    /// NOTE: adrs is modified (type changed to WOTS_PK on return).
    public(package) fun wots_pk_from_sig(
        sig: &vector<u8>,
        sig_offset: u64,
        msg: &vector<u8>,
        padded_pk_seed: &vector<u8>,
        adrs: &mut vector<u8>,
        p: &Params,
    ): vector<u8> {
        let n = params::n(p);
        let w = params::w(p);
        let len = params::len(p);
        let len1 = params::len1(p);
        let len2 = params::len2(p);
        let lgw = params::lgw(p);

        // Step 1: convert message to base-w digits
        let mut lengths = utils::base_2b(msg, lgw, len1);

        // Step 2: compute checksum
        let mut csum: u64 = 0;
        let mut i: u64 = 0;
        while (i < len1) {
            csum = csum + (w - 1 - lengths[i]);
            i = i + 1;
        };

        // Step 3: left-shift checksum
        let shift = (8 - ((len2 * lgw) % 8)) % 8;
        csum = csum << (shift as u8);

        // Step 4: append checksum digits
        let csum_byte_len = (len2 * lgw + 7) / 8;
        let csum_bytes = utils::to_byte(csum, csum_byte_len);
        let csum_digits = utils::base_2b(&csum_bytes, lgw, len2);
        i = 0;
        while (i < len2) {
            lengths.push_back(csum_digits[i]);
            i = i + 1;
        };

        // Step 5: complete each chain from signature value to endpoint
        let mut tmp = vector[];
        i = 0;
        while (i < len) {
            adrs::set_chain(adrs, (i as u32));
            let chain_offset = sig_offset + i * n;
            let start = lengths[i];
            let steps = w - 1 - start;
            let node = chain(sig, chain_offset, start, steps, padded_pk_seed, adrs, p);
            // Push node bytes directly instead of append
            let mut j = 0;
            while (j < n) {
                tmp.push_back(node[j]);
                j = j + 1;
            };
            i = i + 1;
        };

        // Step 6: compress chain endpoints into WOTS+ public key
        let kp = adrs::get_keypair(adrs);
        adrs::set_type_and_clear(adrs, adrs::type_wots_pk());
        adrs::set_keypair(adrs, kp);
        thash::t_l(padded_pk_seed, adrs, &tmp, p)
    }

    /// Fused WOTS+ chain function (FIPS 205 Algorithm 5).
    ///
    /// Reads the initial chain value from `sig[sig_offset .. sig_offset+n]`.
    /// Builds the 86-byte SHA-256 input prefix template once per chain, then
    /// per step: copies template, updates 4 hash bytes, pushes 16 message bytes,
    /// hashes, and truncates — all inline without calling thash::f/build_prefix/
    /// truncate_n. Does NOT update adrs (caller doesn't need hash field after).
    ///
    /// Input prefix template layout (86 bytes):
    /// ```
    /// [0..63]:  padded pk_seed (constant)
    /// [64]:     adrs[3]  — layer LSB
    /// [65..72]: adrs[8..15] — tree address
    /// [73]:     adrs[19] — type LSB
    /// [74..77]: adrs[20..23] — keypair
    /// [78..81]: adrs[24..27] — chain (fixed within this chain call)
    /// [82..85]: adrs[28..31] — hash (updated per step via borrow_mut)
    /// ```
    fun chain(
        sig: &vector<u8>,
        sig_offset: u64,
        start: u64,
        steps: u64,
        padded_pk_seed: &vector<u8>,
        adrs: &vector<u8>,
        p: &Params,
    ): vector<u8> {
        let n = params::n(p);

        if (steps == 0) {
            // Return n bytes from sig at offset (no hash needed)
            let mut result = vector[];
            let mut i = 0;
            while (i < n) {
                result.push_back(sig[sig_offset + i]);
                i = i + 1;
            };
            return result
        };

        // Build 86-byte prefix template for this chain.
        // Only the hash field (positions 82-85) changes between steps.
        let mut prefix_tpl = *padded_pk_seed;
        prefix_tpl.push_back(adrs[3]);   // [64] layer LSB
        prefix_tpl.push_back(adrs[8]);   // [65..72] tree address
        prefix_tpl.push_back(adrs[9]);
        prefix_tpl.push_back(adrs[10]);
        prefix_tpl.push_back(adrs[11]);
        prefix_tpl.push_back(adrs[12]);
        prefix_tpl.push_back(adrs[13]);
        prefix_tpl.push_back(adrs[14]);
        prefix_tpl.push_back(adrs[15]);
        prefix_tpl.push_back(adrs[19]);  // [73] type LSB
        prefix_tpl.push_back(adrs[20]);  // [74..77] keypair
        prefix_tpl.push_back(adrs[21]);
        prefix_tpl.push_back(adrs[22]);
        prefix_tpl.push_back(adrs[23]);
        prefix_tpl.push_back(adrs[24]);  // [78..81] chain
        prefix_tpl.push_back(adrs[25]);
        prefix_tpl.push_back(adrs[26]);
        prefix_tpl.push_back(adrs[27]);
        prefix_tpl.push_back(0u8);       // [82..85] hash placeholder
        prefix_tpl.push_back(0u8);
        prefix_tpl.push_back(0u8);
        prefix_tpl.push_back(0u8);

        let to_pop = 32 - n;

        // First step: read message from sig at offset
        let mut input = prefix_tpl;
        let hv0 = (start as u32);
        *input.borrow_mut(82) = ((hv0 >> 24) as u8);
        *input.borrow_mut(83) = (((hv0 >> 16) & 0xFF) as u8);
        *input.borrow_mut(84) = (((hv0 >> 8) & 0xFF) as u8);
        *input.borrow_mut(85) = ((hv0 & 0xFF) as u8);
        let mut i = 0;
        while (i < n) {
            input.push_back(sig[sig_offset + i]);
            i = i + 1;
        };
        let mut digest = hash::sha2_256(input);
        i = 0;
        while (i < to_pop) { digest.pop_back(); i = i + 1; };
        let mut tmp = digest;

        // Remaining steps: read message from previous output
        let mut j = start + 1;
        while (j < start + steps) {
            let hv = (j as u32);
            let mut inp = prefix_tpl;
            *inp.borrow_mut(82) = ((hv >> 24) as u8);
            *inp.borrow_mut(83) = (((hv >> 16) & 0xFF) as u8);
            *inp.borrow_mut(84) = (((hv >> 8) & 0xFF) as u8);
            *inp.borrow_mut(85) = ((hv & 0xFF) as u8);
            i = 0;
            while (i < n) {
                inp.push_back(tmp[i]);
                i = i + 1;
            };
            let mut d = hash::sha2_256(inp);
            i = 0;
            while (i < to_pop) { d.pop_back(); i = i + 1; };
            tmp = d;
            j = j + 1;
        };
        tmp
    }
}
