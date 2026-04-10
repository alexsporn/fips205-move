/// SLH-DSA-SHA2-128f signature verification entry point.
///
/// Fast variant with larger signatures (17,088 bytes), 128-bit post-quantum security.
/// More hash calls (~6,100) but much faster signing than 128s.
///
/// ## Usage
///
/// ```move
/// use fips205::slh_dsa_sha2_128f;
///
/// let valid: bool = slh_dsa_sha2_128f::verify(&msg, &sig, &pk);
/// // or with a context string for domain separation:
/// let valid: bool = slh_dsa_sha2_128f::verify_with_context(&msg, &sig, &pk, &ctx);
/// ```
module fips205::slh_dsa_sha2_128f {
    use fips205::params;
    use fips205::slh_dsa;

    // === Size constants ===

    /// Public key length: 32 bytes (PK.seed || PK.root).
    public fun pk_len(): u64 { 32 }
    /// Full signature length: 17,088 bytes.
    public fun sig_len(): u64 { 17088 }
    /// Split part 1 length: R(16) || sig_fors(3,696) = 3,712 bytes.
    public fun sig_r_fors_len(): u64 { 3712 }
    /// Split part 2 length: sig_ht = 13,376 bytes.
    public fun sig_ht_len(): u64 { 13376 }

    // === Verification ===

    /// Verify an SLH-DSA-SHA2-128f signature (pure variant, empty context).
    ///
    /// `msg`: arbitrary-length message.
    /// `sig`: 17,088-byte signature.
    /// `pk`:  32-byte public key (PK.seed || PK.root).
    ///
    /// Returns true iff the signature is valid.
    public fun verify(msg: &vector<u8>, sig: &vector<u8>, pk: &vector<u8>): bool {
        slh_dsa::verify(msg, sig, pk, &vector[], &params::sha2_128f())
    }

    /// Verify an SLH-DSA-SHA2-128f signature with a context string.
    ///
    /// `msg`: arbitrary-length message.
    /// `sig`: 17,088-byte signature.
    /// `pk`:  32-byte public key (PK.seed || PK.root).
    /// `ctx`: context string (0-255 bytes) for domain separation.
    ///
    /// Returns true iff the signature is valid.
    public fun verify_with_context(
        msg: &vector<u8>,
        sig: &vector<u8>,
        pk: &vector<u8>,
        ctx: &vector<u8>,
    ): bool {
        slh_dsa::verify(msg, sig, pk, ctx, &params::sha2_128f())
    }

    /// Verify with context, split signature variant.
    ///
    /// Takes the 17,088-byte signature as two parts split at the FORS/HT boundary,
    /// avoiding `vector::append` when the signature exceeds the argument size limit.
    ///
    /// `sig_r_fors`: R(16) || sig_fors(3,696) = 3,712 bytes.
    /// `sig_ht`:     hypertree signature = 13,376 bytes.
    public fun verify_with_context_split(
        msg: &vector<u8>,
        sig_r_fors: &vector<u8>,
        sig_ht: &vector<u8>,
        pk: &vector<u8>,
        ctx: &vector<u8>,
    ): bool {
        slh_dsa::verify_split(msg, sig_r_fors, sig_ht, pk, ctx, &params::sha2_128f())
    }
}
