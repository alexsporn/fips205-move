/// SLH-DSA-SHA2-128s signature verification entry point.
///
/// Small signatures (7,856 bytes), 128-bit post-quantum security.
/// Optimized for on-chain verification with ~2,100 SHA-256 calls.
///
/// ## Usage
///
/// ```move
/// use fips205::slh_dsa_sha2_128s;
///
/// let valid: bool = slh_dsa_sha2_128s::verify(&msg, &sig, &pk);
/// // or with a context string for domain separation:
/// let valid: bool = slh_dsa_sha2_128s::verify_with_context(&msg, &sig, &pk, &ctx);
/// ```
module fips205::slh_dsa_sha2_128s {
    use fips205::params;
    use fips205::slh_dsa;

    /// Verify an SLH-DSA-SHA2-128s signature (pure variant, empty context).
    ///
    /// `msg`: arbitrary-length message.
    /// `sig`: 7,856-byte signature.
    /// `pk`:  32-byte public key (PK.seed || PK.root).
    ///
    /// Returns true iff the signature is valid.
    public fun verify(msg: &vector<u8>, sig: &vector<u8>, pk: &vector<u8>): bool {
        slh_dsa::verify(msg, sig, pk, &vector[], &params::sha2_128s())
    }

    /// Verify an SLH-DSA-SHA2-128s signature with a context string.
    ///
    /// `msg`: arbitrary-length message.
    /// `sig`: 7,856-byte signature.
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
        slh_dsa::verify(msg, sig, pk, ctx, &params::sha2_128s())
    }
}
