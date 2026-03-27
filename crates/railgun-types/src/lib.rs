//! Shared domain types for the RAILGUN workspace.

use core::fmt;

use num_bigint::BigUint;

/// Error returned when a domain value fails validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParseDomainError {
    message: &'static str,
}

impl ParseDomainError {
    /// Creates a new parse error with a static message.
    #[must_use]
    pub const fn new(message: &'static str) -> Self {
        Self { message }
    }
}

impl fmt::Display for ParseDomainError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for ParseDomainError {}

/// Typed 32-byte Railgun spending private key.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SpendingPrivateKey([u8; 32]);

impl SpendingPrivateKey {
    /// Length of a spending private key in bytes.
    pub const LENGTH: usize = 32;

    /// Creates a spending private key from raw bytes.
    #[must_use]
    pub const fn new(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    /// Creates a spending private key from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns an error if `bytes` is not exactly 32 bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ParseDomainError> {
        let array: [u8; Self::LENGTH] = bytes
            .try_into()
            .map_err(|_| ParseDomainError::new("spending private key must be exactly 32 bytes"))?;
        Ok(Self::new(array))
    }

    /// Returns the raw private-key bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}

/// Typed `BabyJubJub` spending public key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpendingPublicKey {
    x: BigUint,
    y: BigUint,
}

impl SpendingPublicKey {
    /// Creates a spending public key from `BabyJubJub` coordinates.
    #[must_use]
    pub fn new(x: BigUint, y: BigUint) -> Self {
        Self { x, y }
    }

    /// Returns the x coordinate.
    #[must_use]
    pub const fn x(&self) -> &BigUint {
        &self.x
    }

    /// Returns the y coordinate.
    #[must_use]
    pub const fn y(&self) -> &BigUint {
        &self.y
    }
}

/// Typed Railgun spending keypair.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpendingKeyPair {
    private_key: SpendingPrivateKey,
    public_key: SpendingPublicKey,
}

impl SpendingKeyPair {
    /// Creates a spending keypair from explicit components.
    #[must_use]
    pub const fn new(private_key: SpendingPrivateKey, public_key: SpendingPublicKey) -> Self {
        Self { private_key, public_key }
    }

    /// Returns the spending private key.
    #[must_use]
    pub const fn private_key(&self) -> &SpendingPrivateKey {
        &self.private_key
    }

    /// Returns the spending public key.
    #[must_use]
    pub const fn public_key(&self) -> &SpendingPublicKey {
        &self.public_key
    }
}

/// Typed 32-byte Railgun viewing private key.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ViewingPrivateKey([u8; 32]);

impl ViewingPrivateKey {
    /// Length of a viewing private key in bytes.
    pub const LENGTH: usize = 32;

    /// Creates a viewing private key from raw bytes.
    #[must_use]
    pub const fn new(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    /// Creates a viewing private key from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns an error if `bytes` is not exactly 32 bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ParseDomainError> {
        let array: [u8; Self::LENGTH] = bytes
            .try_into()
            .map_err(|_| ParseDomainError::new("viewing private key must be exactly 32 bytes"))?;
        Ok(Self::new(array))
    }

    /// Returns the raw private-key bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}

/// Typed 32-byte ed25519 viewing public key.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ViewingPublicKey([u8; 32]);

impl ViewingPublicKey {
    /// Length of a viewing public key in bytes.
    pub const LENGTH: usize = 32;

    /// Creates a viewing public key from raw bytes.
    #[must_use]
    pub const fn new(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    /// Creates a viewing public key from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns an error if `bytes` is not exactly 32 bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ParseDomainError> {
        let array: [u8; Self::LENGTH] = bytes
            .try_into()
            .map_err(|_| ParseDomainError::new("viewing public key must be exactly 32 bytes"))?;
        Ok(Self::new(array))
    }

    /// Returns the raw public-key bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}

/// Typed Railgun viewing keypair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ViewingKeyPair {
    private_key: ViewingPrivateKey,
    public_key: ViewingPublicKey,
}

impl ViewingKeyPair {
    /// Creates a viewing keypair from explicit components.
    #[must_use]
    pub const fn new(private_key: ViewingPrivateKey, public_key: ViewingPublicKey) -> Self {
        Self { private_key, public_key }
    }

    /// Returns the viewing private key.
    #[must_use]
    pub const fn private_key(&self) -> &ViewingPrivateKey {
        &self.private_key
    }

    /// Returns the viewing public key.
    #[must_use]
    pub const fn public_key(&self) -> &ViewingPublicKey {
        &self.public_key
    }
}

/// Typed Railgun nullifying key derived from a viewing private key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NullifyingKey(BigUint);

impl NullifyingKey {
    /// Creates a nullifying key from a field-element integer value.
    #[must_use]
    pub const fn new(value: BigUint) -> Self {
        Self(value)
    }

    /// Returns the underlying field-element integer value.
    #[must_use]
    pub const fn value(&self) -> &BigUint {
        &self.0
    }
}

/// Typed Railgun master public key derived from spending and nullifying keys.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MasterPublicKey(BigUint);

impl MasterPublicKey {
    /// Creates a master public key from a field-element integer value.
    #[must_use]
    pub const fn new(value: BigUint) -> Self {
        Self(value)
    }

    /// Returns the underlying field-element integer value.
    #[must_use]
    pub const fn value(&self) -> &BigUint {
        &self.0
    }
}

/// Typed 32-byte packed `BabyJubJub` spending public key.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PackedSpendingPublicKey([u8; 32]);

impl PackedSpendingPublicKey {
    /// Length of a packed spending public key in bytes.
    pub const LENGTH: usize = 32;

    /// Creates a packed spending public key from raw bytes.
    #[must_use]
    pub const fn new(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    /// Creates a packed spending public key from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns an error if `bytes` is not exactly 32 bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ParseDomainError> {
        let array: [u8; Self::LENGTH] = bytes.try_into().map_err(|_| {
            ParseDomainError::new("packed spending public key must be exactly 32 bytes")
        })?;
        Ok(Self::new(array))
    }

    /// Returns the raw packed public-key bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}

/// View-only wallet import/export payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShareableViewingKeyData {
    viewing_private_key: ViewingPrivateKey,
    packed_spending_public_key: PackedSpendingPublicKey,
}

impl ShareableViewingKeyData {
    /// Creates a shareable viewing key payload from explicit components.
    #[must_use]
    pub const fn new(
        viewing_private_key: ViewingPrivateKey,
        packed_spending_public_key: PackedSpendingPublicKey,
    ) -> Self {
        Self { viewing_private_key, packed_spending_public_key }
    }

    /// Returns the viewing private key.
    #[must_use]
    pub const fn viewing_private_key(&self) -> &ViewingPrivateKey {
        &self.viewing_private_key
    }

    /// Returns the packed spending public key.
    #[must_use]
    pub const fn packed_spending_public_key(&self) -> &PackedSpendingPublicKey {
        &self.packed_spending_public_key
    }
}

/// Typed 8-byte Railgun network identifier used inside `0zk` addresses.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct NetworkId([u8; 8]);

impl NetworkId {
    /// Length of an encoded network identifier in bytes.
    pub const LENGTH: usize = 8;

    /// Creates a network identifier from raw bytes.
    #[must_use]
    pub const fn new(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    /// Creates a network identifier from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns an error if `bytes` is not exactly 8 bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ParseDomainError> {
        let array: [u8; Self::LENGTH] = bytes
            .try_into()
            .map_err(|_| ParseDomainError::new("network id must be exactly 8 bytes"))?;
        Ok(Self::new(array))
    }

    /// Returns the raw network identifier bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}

/// Typed Railgun chain-type discriminator.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ChainType(u8);

impl ChainType {
    /// Creates a chain type from its raw numeric value.
    #[must_use]
    pub const fn new(value: u8) -> Self {
        Self(value)
    }

    /// Returns the inner numeric value.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

/// Typed Railgun chain reference packed into a network identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RailgunChain {
    chain_type: ChainType,
    chain_id: u64,
}

impl RailgunChain {
    /// Maximum supported chain identifier width inside a network identifier.
    pub const MAX_CHAIN_ID: u64 = (1_u64 << 56) - 1;

    /// Creates a chain reference from explicit type and identifier values.
    ///
    /// # Errors
    ///
    /// Returns an error if `chain_id` exceeds the supported 56-bit range.
    pub fn new(chain_type: ChainType, chain_id: u64) -> Result<Self, ParseDomainError> {
        if chain_id > Self::MAX_CHAIN_ID {
            return Err(ParseDomainError::new("chain id must fit within 56 bits"));
        }

        Ok(Self { chain_type, chain_id })
    }

    /// Returns the chain type.
    #[must_use]
    pub const fn chain_type(self) -> ChainType {
        self.chain_type
    }

    /// Returns the chain identifier.
    #[must_use]
    pub const fn chain_id(self) -> u64 {
        self.chain_id
    }
}

/// Typed address scope for a specific chain or all chains.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ChainScope {
    /// Address is valid across all supported chains.
    AllChains,
    /// Address is scoped to one chain.
    Chain(RailgunChain),
}

/// Typed encoded `0zk` Railgun address.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RailgunAddress(String);

impl RailgunAddress {
    /// Creates a Railgun address from its encoded string form.
    #[must_use]
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// Returns the encoded address string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Typed decoded `0zk` Railgun address payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RailgunAddressData {
    version: u8,
    master_public_key: MasterPublicKey,
    chain_scope: ChainScope,
    viewing_public_key: ViewingPublicKey,
}

impl RailgunAddressData {
    /// Creates decoded address data from explicit components.
    #[must_use]
    pub const fn new(
        version: u8,
        master_public_key: MasterPublicKey,
        chain_scope: ChainScope,
        viewing_public_key: ViewingPublicKey,
    ) -> Self {
        Self { version, master_public_key, chain_scope, viewing_public_key }
    }

    /// Returns the decoded address version.
    #[must_use]
    pub const fn version(&self) -> u8 {
        self.version
    }

    /// Returns the decoded master public key.
    #[must_use]
    pub const fn master_public_key(&self) -> &MasterPublicKey {
        &self.master_public_key
    }

    /// Returns the decoded chain scope.
    #[must_use]
    pub const fn chain_scope(&self) -> ChainScope {
        self.chain_scope
    }

    /// Returns the decoded viewing public key.
    #[must_use]
    pub const fn viewing_public_key(&self) -> &ViewingPublicKey {
        &self.viewing_public_key
    }
}

/// Typed EVM address.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Address([u8; 20]);

impl Address {
    /// Length of an encoded address in bytes.
    pub const LENGTH: usize = 20;

    /// Creates an address from raw bytes.
    #[must_use]
    pub const fn new(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    /// Creates an address from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns an error if `bytes` is not exactly 20 bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ParseDomainError> {
        let array: [u8; Self::LENGTH] = bytes
            .try_into()
            .map_err(|_| ParseDomainError::new("address must be exactly 20 bytes"))?;
        Ok(Self::new(array))
    }

    /// Returns the raw address bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}

/// Typed chain identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ChainId(u64);

impl ChainId {
    /// Creates a validated chain identifier.
    ///
    /// # Errors
    ///
    /// Returns an error if `value` is zero.
    pub fn new(value: u64) -> Result<Self, ParseDomainError> {
        if value == 0 {
            return Err(ParseDomainError::new("chain id must be non-zero"));
        }

        Ok(Self(value))
    }

    /// Returns the inner numeric value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Typed transaction hash.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TxHash([u8; 32]);

impl TxHash {
    /// Length of a transaction hash in bytes.
    pub const LENGTH: usize = 32;

    /// Creates a transaction hash from raw bytes.
    #[must_use]
    pub const fn new(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    /// Returns the raw transaction hash bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::{ParseDomainError, SpendingPrivateKey, ViewingPrivateKey, ViewingPublicKey};

    #[test]
    fn rejects_invalid_spending_private_key_length() {
        let Err(error) = SpendingPrivateKey::from_slice(&[7_u8; 31]) else {
            panic!("invalid spending private key length should fail");
        };
        assert_eq!(error, ParseDomainError::new("spending private key must be exactly 32 bytes"));
    }

    #[test]
    fn rejects_invalid_viewing_private_key_length() {
        let Err(error) = ViewingPrivateKey::from_slice(&[7_u8; 33]) else {
            panic!("invalid viewing private key length should fail");
        };
        assert_eq!(error, ParseDomainError::new("viewing private key must be exactly 32 bytes"));
    }

    #[test]
    fn rejects_invalid_viewing_public_key_length() {
        let Err(error) = ViewingPublicKey::from_slice(&[7_u8; 31]) else {
            panic!("invalid viewing public key length should fail");
        };
        assert_eq!(error, ParseDomainError::new("viewing public key must be exactly 32 bytes"));
    }
}
