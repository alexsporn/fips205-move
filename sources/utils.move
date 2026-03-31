/// Byte manipulation utilities for SLH-DSA-SHA2-128s.
///
/// Provides helpers for working with byte vectors as big-endian integers
/// and for extracting base-2^b digit sequences from byte strings.
/// These operations underpin the signature parsing and hash input construction
/// throughout the SLH-DSA verification pipeline.
module fips205::utils {

    /// Extract a sub-range `[start, end)` from a byte vector, returning a new vector.
    ///
    /// Used extensively for parsing flat signature byte arrays into their component
    /// parts (FORS secrets, auth paths, WOTS+ chains, etc.).
    public(package) fun slice(v: &vector<u8>, start: u64, end: u64): vector<u8> {
        let mut result = vector[];
        let mut i = start;
        while (i < end) {
            result.push_back(v[i]);
            i = i + 1;
        };
        result
    }

    /// Interpret bytes `v[start .. start+len]` as a big-endian unsigned integer.
    ///
    /// Used to extract `idx_tree` (7 bytes -> 54 bits) and `idx_leaf` (2 bytes -> 9 bits)
    /// from the H_msg digest during verification. The caller masks the result to the
    /// required bit width after this call.
    ///
    /// Panics if `len > 8` (result would overflow `u64`).
    public(package) fun to_int(v: &vector<u8>, start: u64, len: u64): u64 {
        let mut result: u64 = 0;
        let mut i = 0;
        while (i < len) {
            result = (result << 8) | (v[start + i] as u64);
            i = i + 1;
        };
        result
    }

    /// Convert integer `x` to an `n`-byte big-endian byte string (FIPS 205 `toByte`).
    ///
    /// In this implementation, only called with `n=2` for the WOTS+ checksum encoding.
    /// The checksum (max 480 << 4 = 7680) is converted to 2 bytes before extracting
    /// its base-16 digits.
    public(package) fun to_byte(x: u64, n: u64): vector<u8> {
        let mut result = vector[];
        let mut i = 0;
        while (i < n) {
            let shift = (((n - 1 - i) * 8) as u8);
            result.push_back(((x >> shift) & 0xFF) as u8);
            i = i + 1;
        };
        result
    }

    /// Extract base-2^b digits from a byte string (FIPS 205 `base_2b`).
    ///
    /// Reads bits from `input` MSB-first, extracting `out_len` values of `b` bits each.
    /// Returns a vector of `u64` values, each in `[0, 2^b - 1]`.
    ///
    /// Used in two contexts:
    /// - `b=4, out_len=32`: WOTS+ message-to-nibble conversion (16 bytes -> 32 nibbles)
    /// - `b=4, out_len=3`:  WOTS+ checksum digit extraction (2 bytes -> 3 nibbles)
    /// - `b=12, out_len=14`: FORS leaf index extraction (21 bytes -> 14 twelve-bit indices)
    public(package) fun base_2b(input: &vector<u8>, b: u64, out_len: u64): vector<u64> {
        let mut result = vector[];
        let mut inn: u64 = 0;
        let mut bits: u64 = 0;
        let mut total: u64 = 0;
        let mask = (1u64 << (b as u8)) - 1;
        let mut out = 0;
        while (out < out_len) {
            while (bits < b) {
                total = (total << 8) | (input[inn] as u64);
                inn = inn + 1;
                bits = bits + 8;
            };
            bits = bits - b;
            result.push_back((total >> (bits as u8)) & mask);
            out = out + 1;
        };
        result
    }
}
