/// ADRS (Address) structure for FIPS 205 SLH-DSA (Section 4).
///
/// The ADRS is a 32-byte domain separation value included in every tweakable hash
/// call. It ensures that identical inputs in different contexts (different tree
/// positions, different signature layers, different hash purposes) produce distinct
/// outputs, which is critical for the security proof.
///
/// Represented as a `vector<u8>` of length 32 with all fields stored in big-endian.
///
/// ## Full ADRS Layout
///
/// ```
/// Offset  Size  Field
///  0       4    Layer address       (hypertree layer index, 0..d-1)
///  4       4    Padding             (always zero for SHA2-128s)
///  8       4    Tree address high   (upper 32 bits of tree index within layer)
/// 12       4    Tree address low    (lower 32 bits of tree index within layer)
/// 16       4    Type                (hash context: WOTS_HASH, WOTS_PK, TREE, FORS_TREE, FORS_ROOTS)
/// 20       4    Key pair address    (WOTS+ key pair / FORS key pair within XMSS tree)
/// 24       4    Chain / Tree height (WOTS+ chain index, or current Merkle tree level)
/// 28       4    Hash / Tree index   (WOTS+ chain step, or Merkle node position at current level)
/// ```
///
/// ## Compressed Form (22 bytes)
///
/// For SHA-256 tweakable hash inputs, the ADRS is compressed to 22 bytes by keeping
/// only the least significant bytes of small fields (FIPS 205 Algorithm 24).
/// The compression is inlined at each call site for gas efficiency.
module fips205::adrs {

    // --- Address type constants (FIPS 205 Table 2) ---
    const WOTS_HASH: u32 = 0;   // WOTS+ chain hashing
    const WOTS_PK: u32 = 1;     // WOTS+ public key compression
    const TREE: u32 = 2;        // Merkle tree (XMSS) node hashing
    const FORS_TREE: u32 = 3;   // FORS tree leaf/node hashing
    const FORS_ROOTS: u32 = 4;  // FORS root compression

    /// Returns address type constant for WOTS+ chain hashing.
    public(package) fun type_wots_hash(): u32 { WOTS_HASH }
    /// Returns address type constant for WOTS+ public key compression.
    public(package) fun type_wots_pk(): u32 { WOTS_PK }
    /// Returns address type constant for Merkle tree node hashing.
    public(package) fun type_tree(): u32 { TREE }
    /// Returns address type constant for FORS tree hashing.
    public(package) fun type_fors_tree(): u32 { FORS_TREE }
    /// Returns address type constant for FORS root compression.
    public(package) fun type_fors_roots(): u32 { FORS_ROOTS }

    /// Create a new 32-byte ADRS initialized to all zeros.
    public(package) fun new(): vector<u8> {
        let mut v = vector[];
        let mut i = 0;
        while (i < 32) {
            v.push_back(0u8);
            i = i + 1;
        };
        v
    }

    /// Set layer address (bytes 0-3).
    public(package) fun set_layer(adrs: &mut vector<u8>, layer: u32) {
        set_u32(adrs, 0, layer);
    }

    /// Set tree address (bytes 8-15 as big-endian u64, bytes 4-7 zeroed).
    public(package) fun set_tree_address(adrs: &mut vector<u8>, tree: u64) {
        set_u32(adrs, 4, 0);
        set_u32(adrs, 8, ((tree >> 32) as u32));
        set_u32(adrs, 12, ((tree & 0xFFFFFFFF) as u32));
    }

    /// Set type field and clear bytes 20-31 (key pair, chain/height, hash/index).
    ///
    /// Per FIPS 205: when changing the address type, all type-specific fields
    /// (bytes 20-31) must be reset to zero. The layer and tree address (bytes 0-15)
    /// are preserved.
    public(package) fun set_type_and_clear(adrs: &mut vector<u8>, t: u32) {
        set_u32(adrs, 16, t);
        set_u32(adrs, 20, 0);
        set_u32(adrs, 24, 0);
        set_u32(adrs, 28, 0);
    }

    /// Set key pair address (bytes 20-23).
    public(package) fun set_keypair(adrs: &mut vector<u8>, kp: u32) {
        set_u32(adrs, 20, kp);
    }

    /// Set chain address (bytes 24-27).
    public(package) fun set_chain(adrs: &mut vector<u8>, c: u32) {
        set_u32(adrs, 24, c);
    }

    /// Set hash address (bytes 28-31).
    public(package) fun set_hash(adrs: &mut vector<u8>, h: u32) {
        set_u32(adrs, 28, h);
    }

    /// Set tree height (bytes 24-27, same offset as chain).
    public(package) fun set_tree_height(adrs: &mut vector<u8>, h: u32) {
        set_u32(adrs, 24, h);
    }

    /// Set tree index (bytes 28-31, same offset as hash).
    public(package) fun set_tree_index(adrs: &mut vector<u8>, idx: u32) {
        set_u32(adrs, 28, idx);
    }

    /// Get tree index (bytes 28-31).
    public(package) fun get_tree_index(adrs: &vector<u8>): u32 {
        get_u32(adrs, 28)
    }

    /// Get key pair address (bytes 20-23).
    public(package) fun get_keypair(adrs: &vector<u8>): u32 {
        get_u32(adrs, 20)
    }

    // --- Internal helpers ---

    fun set_u32(v: &mut vector<u8>, offset: u64, val: u32) {
        *v.borrow_mut(offset)     = ((val >> 24) as u8);
        *v.borrow_mut(offset + 1) = (((val >> 16) & 0xFF) as u8);
        *v.borrow_mut(offset + 2) = (((val >> 8) & 0xFF) as u8);
        *v.borrow_mut(offset + 3) = ((val & 0xFF) as u8);
    }

    fun get_u32(v: &vector<u8>, offset: u64): u32 {
        ((v[offset] as u32) << 24) |
        ((v[offset + 1] as u32) << 16) |
        ((v[offset + 2] as u32) << 8) |
        (v[offset + 3] as u32)
    }
}
