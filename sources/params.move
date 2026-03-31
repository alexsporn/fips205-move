/// SLH-DSA parameter set configuration.
///
/// Each SLH-DSA variant (128s, 128f, 192s, etc.) is defined by a set of constants
/// that control tree dimensions, hash chain lengths, and signature layout. This module
/// provides a `Params` struct that bundles all these constants, along with precomputed
/// derived sizes for signature parsing.
///
/// ## Supported Parameter Sets
///
/// | Variant   | n  | h  | d  | h' | a  | k  | m  | Sig bytes | Hash   |
/// |-----------|----|----|----|----|----|----|-----|-----------|--------|
/// | SHA2-128s | 16 | 63 |  7 |  9 | 12 | 14 | 30  |  7,856    | SHA-256 |
/// | SHA2-128f | 16 | 66 | 22 |  3 |  6 | 33 | 34  | 17,088    | SHA-256 |
///
/// ## Future Variants (require SHA-512 native support)
///
/// | Variant   | n  | h  | d  | h' | a  | k  | m  | Sig bytes | Hash   |
/// |-----------|----|----|----|----|----|----|-----|-----------|--------|
/// | SHA2-192s | 24 | 63 |  7 |  9 | 14 | 17 | 39  | 16,224    | SHA-512 |
/// | SHA2-192f | 24 | 66 | 22 |  3 |  8 | 33 | 42  | 35,664    | SHA-512 |
/// | SHA2-256s | 32 | 64 |  8 |  8 | 14 | 22 | 47  | 29,792    | SHA-512 |
/// | SHA2-256f | 32 | 68 | 17 |  4 |  9 | 35 | 49  | 49,856    | SHA-512 |
module fips205::params {

    /// Complete parameter set for an SLH-DSA variant.
    ///
    /// Passed by reference (`&Params`) to all algorithm functions. Includes both
    /// the base FIPS 205 parameters and precomputed derived sizes to avoid
    /// runtime recomputation.
    public struct Params has copy, drop, store {
        // --- Base parameters (FIPS 205 Table 2) ---

        /// Security parameter: hash output and node size in bytes.
        n: u64,
        /// Total hypertree height.
        h: u64,
        /// Number of XMSS tree layers in the hypertree.
        d: u64,
        /// Height of each XMSS tree (h / d).
        hp: u64,
        /// FORS tree height (each tree has 2^a leaves).
        a: u64,
        /// Number of FORS trees.
        k: u64,
        /// Winternitz parameter (base of digit encoding).
        w: u64,
        /// log2(w) -- bits per digit.
        lgw: u64,
        /// Total WOTS+ chain count (len1 + len2).
        len: u64,
        /// WOTS+ message chains (2 * n for lgw=4).
        len1: u64,
        /// WOTS+ checksum chains.
        len2: u64,
        /// Message digest length in bytes (output of H_msg).
        m: u64,

        // --- Precomputed derived sizes ---

        /// Total signature size in bytes: n + k*(1+a)*n + d*(len+hp)*n.
        sig_len: u64,
        /// Public key size in bytes: 2*n.
        pk_len: u64,
        /// FORS signature portion size: k * (1 + a) * n.
        fors_sig_len: u64,
        /// Single XMSS signature size: (len + hp) * n.
        xmss_sig_len: u64,

        // --- Message digest field layout ---

        /// Bytes for FORS message digest: ceil(k * a / 8).
        md_len: u64,
        /// Bytes for tree index: ceil((h - hp) / 8).
        idx_tree_len: u64,
        /// Bytes for leaf index: ceil(hp / 8).
        idx_leaf_len: u64,
        /// Bit width of tree index: h - hp.
        idx_tree_bits: u64,
        /// Bit width of leaf index: hp.
        idx_leaf_bits: u64,
    }

    // --- Accessor functions ---
    // Required because Move struct fields are private outside the defining module.

    public(package) fun n(p: &Params): u64 { p.n }
    public(package) fun h(p: &Params): u64 { p.h }
    public(package) fun d(p: &Params): u64 { p.d }
    public(package) fun hp(p: &Params): u64 { p.hp }
    public(package) fun a(p: &Params): u64 { p.a }
    public(package) fun k(p: &Params): u64 { p.k }
    public(package) fun w(p: &Params): u64 { p.w }
    public(package) fun lgw(p: &Params): u64 { p.lgw }
    public(package) fun len(p: &Params): u64 { p.len }
    public(package) fun len1(p: &Params): u64 { p.len1 }
    public(package) fun len2(p: &Params): u64 { p.len2 }
    public(package) fun m(p: &Params): u64 { p.m }
    public(package) fun sig_len(p: &Params): u64 { p.sig_len }
    public(package) fun pk_len(p: &Params): u64 { p.pk_len }
    public(package) fun fors_sig_len(p: &Params): u64 { p.fors_sig_len }
    public(package) fun xmss_sig_len(p: &Params): u64 { p.xmss_sig_len }
    public(package) fun md_len(p: &Params): u64 { p.md_len }
    public(package) fun idx_tree_len(p: &Params): u64 { p.idx_tree_len }
    public(package) fun idx_leaf_len(p: &Params): u64 { p.idx_leaf_len }
    public(package) fun idx_tree_bits(p: &Params): u64 { p.idx_tree_bits }
    public(package) fun idx_leaf_bits(p: &Params): u64 { p.idx_leaf_bits }

    // --- Parameter set constructors ---

    /// SLH-DSA-SHA2-128s: small signatures, 128-bit security.
    ///
    /// Optimized for on-chain verification: fewest hash calls (~2,100),
    /// smallest signature (7,856 bytes).
    public(package) fun sha2_128s(): Params {
        Params {
            n: 16, h: 63, d: 7, hp: 9, a: 12, k: 14,
            w: 16, lgw: 4, len: 35, len1: 32, len2: 3, m: 30,
            sig_len: 7856,
            pk_len: 32,
            fors_sig_len: 2912,     // 14 * 13 * 16
            xmss_sig_len: 704,      // (35 + 9) * 16
            md_len: 21,             // ceil(14 * 12 / 8)
            idx_tree_len: 7,        // ceil(54 / 8)
            idx_leaf_len: 2,        // ceil(9 / 8)
            idx_tree_bits: 54,      // 63 - 9
            idx_leaf_bits: 9,
        }
    }

    /// SLH-DSA-SHA2-128f: fast signing, 128-bit security.
    ///
    /// Larger signatures (17,088 bytes) and more hash calls (~6,100),
    /// but much faster signing. Best when signature size is not the bottleneck.
    public(package) fun sha2_128f(): Params {
        Params {
            n: 16, h: 66, d: 22, hp: 3, a: 6, k: 33,
            w: 16, lgw: 4, len: 35, len1: 32, len2: 3, m: 34,
            sig_len: 17088,
            pk_len: 32,
            fors_sig_len: 3696,     // 33 * 7 * 16
            xmss_sig_len: 608,      // (35 + 3) * 16
            md_len: 25,             // ceil(33 * 6 / 8)
            idx_tree_len: 8,        // ceil(63 / 8)
            idx_leaf_len: 1,        // ceil(3 / 8)
            idx_tree_bits: 63,      // 66 - 3
            idx_leaf_bits: 3,
        }
    }
}
