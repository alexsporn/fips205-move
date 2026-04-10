/// WOTS+ (Winternitz One-Time Signature) verification for SLH-DSA.
///
/// WOTS+ signs an n-byte message by encoding it as base-w digits, where each digit
/// selects a position within a hash chain. Verification completes each chain from
/// the signature value to the endpoint, then compresses all endpoints.
///
/// For all SHA2-128 variants (w=16): 35 chains, each of length 16 (steps 0..15).
/// Average chain completion: 7.5 F calls per chain.
///
/// ## Gas Dominance
/// WOTS+ chain computation accounts for ~85% of total verification cost.
///
/// ## Gas Optimizations
/// - `padded_pk_seed` is precomputed once and threaded through.
/// - `tmp.append(node)` replaced with push_back loops to avoid reverse overhead.
/// - `chain` calls thash::f which uses the optimized prefix construction.
///
/// ## References
/// - FIPS 205 Algorithm 5 (chain)
/// - FIPS 205 Algorithm 8 (wots_pkFromSig)
module fips205::wots {
    use fips205::adrs;
    use fips205::thash;
    use fips205::utils;
    use fips205::params::{Self, Params};

    /// Compute WOTS+ public key from signature (FIPS 205 Algorithm 8).
    ///
    /// `sig_wots`: `len * n` flat bytes (chain values).
    /// `msg`:      n bytes (message to verify).
    /// `padded_pk_seed`: precomputed pk_seed || zeros (64 bytes).
    /// `adrs`:     must have type=WOTS_HASH and key pair set.
    ///
    /// Returns the n-byte WOTS+ public key.
    /// NOTE: adrs is modified (type changed to WOTS_PK on return).
    public(package) fun wots_pk_from_sig(
        sig_wots: &vector<u8>,
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
        // Use push_back instead of append to avoid vector::reverse overhead
        let mut tmp = vector[];
        i = 0;
        while (i < len) {
            adrs::set_chain(adrs, (i as u32));
            let sig_i = utils::slice(sig_wots, i * n, (i + 1) * n);
            let start = lengths[i];
            let steps = w - 1 - start;
            let node = chain(&sig_i, start, steps, padded_pk_seed, adrs, p);
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

    /// WOTS+ chain function (FIPS 205 Algorithm 5).
    ///
    /// Starting from value `x` at position `start`, applies F iteratively
    /// `steps` times with hash addresses `start .. start + steps - 1`.
    fun chain(
        x: &vector<u8>,
        start: u64,
        steps: u64,
        padded_pk_seed: &vector<u8>,
        adrs: &mut vector<u8>,
        p: &Params,
    ): vector<u8> {
        let mut tmp = *x;
        let mut j = start;
        while (j < start + steps) {
            adrs::set_hash(adrs, (j as u32));
            tmp = thash::f(padded_pk_seed, adrs, &tmp, p);
            j = j + 1;
        };
        tmp
    }
}
