/// WOTS+ (Winternitz One-Time Signature) verification for SLH-DSA.
///
/// WOTS+ signs an n-byte message by encoding it as base-w digits, where each digit
/// selects a position within a hash chain. Verification completes each chain from
/// the signature value to the endpoint, then compresses all endpoints.
///
/// For all SHA2-128 variants (w=16): 35 chains, each of length 16 (steps 0..15).
/// Average chain completion: 7.5 F calls per chain.
///
/// ## Gas Optimizations (Round 3)
///
/// The chain function is fully fused with three additional micro-optimizations:
/// 1. **102-byte template**: Pre-allocates message space in the template. Per step,
///    message bytes are written via `borrow_mut` instead of `push_back`, eliminating
///    capacity checks and resize overhead.
/// 2. **Skip intermediate truncation**: SHA-256 produces 32 bytes but only 16 are
///    needed. Intermediate results are kept at 32 bytes — the next step reads only
///    the first 16 — and truncation happens only on the final output.
/// 3. **Single-byte hash update**: For w ≤ 256 (all FIPS 205 variants), the hash
///    step index fits in one byte. The upper 3 bytes are pre-zeroed in the template,
///    so only position 85 needs updating (1 borrow_mut instead of 4).
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
    /// Builds a 102-byte SHA-256 input template once per chain (86-byte prefix +
    /// 16-byte message placeholder), then per step: copies template, updates hash
    /// byte and message bytes via borrow_mut, hashes, and skips truncation until
    /// the final step.
    ///
    /// Input template layout (102 bytes):
    /// ```
    /// [0..63]:   padded pk_seed (constant)
    /// [64]:      adrs[3]     — layer LSB
    /// [65..72]:  adrs[8..15] — tree address
    /// [73]:      adrs[19]    — type LSB
    /// [74..77]:  adrs[20..23] — keypair
    /// [78..81]:  adrs[24..27] — chain (fixed within this chain call)
    /// [82..85]:  0,0,0,0     — hash field (only byte 85 updated per step)
    /// [86..101]: 0..0        — message placeholder (16 bytes, updated per step)
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

        // Build 102-byte input template for this chain.
        // Prefix (86 bytes): padded_pk_seed(64) + compressed ADRS(22)
        // Message (16 bytes): placeholder zeros, overwritten per step via borrow_mut
        let mut input_tpl = *padded_pk_seed;
        // Compressed ADRS (22 bytes, positions 64-85)
        input_tpl.push_back(adrs[3]);   // [64] layer LSB
        input_tpl.push_back(adrs[8]);   // [65..72] tree address
        input_tpl.push_back(adrs[9]);
        input_tpl.push_back(adrs[10]);
        input_tpl.push_back(adrs[11]);
        input_tpl.push_back(adrs[12]);
        input_tpl.push_back(adrs[13]);
        input_tpl.push_back(adrs[14]);
        input_tpl.push_back(adrs[15]);
        input_tpl.push_back(adrs[19]);  // [73] type LSB
        input_tpl.push_back(adrs[20]);  // [74..77] keypair
        input_tpl.push_back(adrs[21]);
        input_tpl.push_back(adrs[22]);
        input_tpl.push_back(adrs[23]);
        input_tpl.push_back(adrs[24]);  // [78..81] chain
        input_tpl.push_back(adrs[25]);
        input_tpl.push_back(adrs[26]);
        input_tpl.push_back(adrs[27]);
        input_tpl.push_back(0u8);       // [82..85] hash (only byte 85 changes)
        input_tpl.push_back(0u8);
        input_tpl.push_back(0u8);
        input_tpl.push_back(0u8);
        // Message placeholder (16 bytes, positions 86-101)
        input_tpl.push_back(0u8);
        input_tpl.push_back(0u8);
        input_tpl.push_back(0u8);
        input_tpl.push_back(0u8);
        input_tpl.push_back(0u8);
        input_tpl.push_back(0u8);
        input_tpl.push_back(0u8);
        input_tpl.push_back(0u8);
        input_tpl.push_back(0u8);
        input_tpl.push_back(0u8);
        input_tpl.push_back(0u8);
        input_tpl.push_back(0u8);
        input_tpl.push_back(0u8);
        input_tpl.push_back(0u8);
        input_tpl.push_back(0u8);
        input_tpl.push_back(0u8);

        // First step: read message from sig at offset
        let mut input = input_tpl;
        // Hash step fits in one byte for all FIPS 205 variants (w ≤ 256)
        *input.borrow_mut(85) = (start as u8);
        let mut i = 0;
        while (i < n) {
            *input.borrow_mut(86 + i) = sig[sig_offset + i];
            i = i + 1;
        };
        // Don't truncate intermediate results — next step reads only first n bytes
        let mut tmp = hash::sha2_256(input);  // 32 bytes

        // Remaining steps: read message from previous hash output
        let mut j = start + 1;
        while (j < start + steps) {
            let mut inp = input_tpl;
            *inp.borrow_mut(85) = (j as u8);
            i = 0;
            while (i < n) {
                *inp.borrow_mut(86 + i) = tmp[i];
                i = i + 1;
            };
            tmp = hash::sha2_256(inp);  // 32 bytes, skip truncation
            j = j + 1;
        };

        // Truncate only the final result to n bytes
        let to_pop = tmp.length() - n;
        i = 0;
        while (i < to_pop) { tmp.pop_back(); i = i + 1; };
        tmp
    }
}
