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
}
