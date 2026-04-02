//! Shared domain types for the RAILGUN workspace.

use core::fmt;

use babyjubjub_rs::{Fr as BabyJubJubField, Point, decompress_point};
use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Bech32m, Hrp};
use ff::{PrimeField as _, PrimeFieldRepr as _};
use num_bigint::BigUint;

/// Canonical BN254 scalar-field modulus encoded as 32 big-endian bytes.
///
/// This is the same field boundary the upstream RAILGUN codebase refers to as
/// `SNARK_PRIME`.
/// Decimal:
/// `21888242871839275222246405745257275088548364400416034343698204186575808495617`
pub const BN254_SCALAR_FIELD_MODULUS_BYTES: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];
const ADDRESS_HRP: &str = "0zk";
const ADDRESS_MAX_LENGTH: usize = 127;
const ADDRESS_VERSION_V1: u8 = 1;
const ADDRESS_PAYLOAD_LENGTH: usize = 73;
const NETWORK_ID_XOR_KEY: [u8; 8] = *b"railgun\0";

/// Returns the canonical BN254 scalar-field modulus as a `BigUint`.
#[must_use]
pub fn bn254_scalar_field_modulus() -> BigUint {
    BigUint::from_bytes_be(&BN254_SCALAR_FIELD_MODULUS_BYTES)
}

fn validate_bn254_scalar(value: &BigUint, label: &'static str) -> Result<(), ParseDomainError> {
    if *value < bn254_scalar_field_modulus() { Ok(()) } else { Err(ParseDomainError::new(label)) }
}

fn biguint_to_babyjubjub_field(value: &BigUint) -> Result<BabyJubJubField, ParseDomainError> {
    let field = BabyJubJubField::from_str(&value.to_string()).ok_or(ParseDomainError::new(
        "spending public key coordinates must fit within the BabyJubJub field",
    ))?;
    let repr = field.into_repr();
    let mut bytes = Vec::with_capacity(core::mem::size_of_val(repr.as_ref()));
    repr.write_be(&mut bytes).map_err(|_| {
        ParseDomainError::new(
            "spending public key coordinates must fit within the BabyJubJub field",
        )
    })?;
    if BigUint::from_bytes_be(&bytes) == *value {
        Ok(field)
    } else {
        Err(ParseDomainError::new(
            "spending public key coordinates must fit within the BabyJubJub field",
        ))
    }
}

fn decode_chain_scope(network_id: NetworkId) -> Result<ChainScope, ParseDomainError> {
    let mut raw = [0_u8; NetworkId::LENGTH];
    for (index, byte) in raw.iter_mut().enumerate() {
        *byte = network_id.as_bytes()[index] ^ NETWORK_ID_XOR_KEY[index];
    }

    let decoded = u64::from_be_bytes(raw);
    if decoded == u64::MAX {
        return Ok(ChainScope::AllChains);
    }

    let chain_type = ChainType::new((decoded >> 56) as u8);
    let chain_id = decoded & RailgunChain::MAX_CHAIN_ID;
    let chain = RailgunChain::new(chain_type, chain_id)
        .map_err(|_| ParseDomainError::new("railgun address contains an invalid network id"))?;
    Ok(ChainScope::Chain(chain))
}

fn validate_railgun_address(value: &str) -> Result<(), ParseDomainError> {
    if value != value.to_ascii_lowercase() {
        return Err(ParseDomainError::new("railgun address must use canonical lowercase encoding"));
    }
    if value.len() > ADDRESS_MAX_LENGTH {
        return Err(ParseDomainError::new("railgun address exceeds the maximum encoded length"));
    }

    let hrp = Hrp::parse(ADDRESS_HRP)
        .map_err(|_| ParseDomainError::new("railgun address must use the 0zk prefix"))?;
    let checked = CheckedHrpstring::new::<Bech32m>(value)
        .map_err(|_| ParseDomainError::new("railgun address must be valid bech32m"))?;
    if checked.hrp() != hrp {
        return Err(ParseDomainError::new("railgun address must use the 0zk prefix"));
    }

    let payload: Vec<u8> = checked.byte_iter().collect();
    if payload.len() != ADDRESS_PAYLOAD_LENGTH {
        return Err(ParseDomainError::new(
            "railgun address payload must match the canonical fixed length",
        ));
    }
    if payload[0] != ADDRESS_VERSION_V1 {
        return Err(ParseDomainError::new("railgun address version is unsupported"));
    }

    let master_public_key = BigUint::from_bytes_be(&payload[1..33]);
    MasterPublicKey::new(master_public_key)
        .map_err(|_| ParseDomainError::new("master public key must fit within 32 bytes"))?;
    let network_id = NetworkId::from_slice(&payload[33..41]).map_err(|_| {
        ParseDomainError::new("railgun address payload must match the canonical fixed length")
    })?;
    decode_chain_scope(network_id)?;
    ViewingPublicKey::from_slice(&payload[41..]).map_err(|_| {
        ParseDomainError::new("railgun address payload must match the canonical fixed length")
    })?;
    Ok(())
}

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
    ///
    /// # Errors
    ///
    /// Returns an error if either coordinate is outside the BabyJubJub field or
    /// if the coordinates do not represent a valid compressible BabyJubJub point.
    pub fn new(x: BigUint, y: BigUint) -> Result<Self, ParseDomainError> {
        let point =
            Point { x: biguint_to_babyjubjub_field(&x)?, y: biguint_to_babyjubjub_field(&y)? };
        let compressed = point.compress();
        let decompressed = decompress_point(compressed).map_err(|_| {
            ParseDomainError::new(
                "spending public key coordinates must form a valid BabyJubJub point",
            )
        })?;
        if decompressed.x == point.x && decompressed.y == point.y {
            Ok(Self { x, y })
        } else {
            Err(ParseDomainError::new(
                "spending public key coordinates must form a valid BabyJubJub point",
            ))
        }
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
    ///
    /// # Errors
    ///
    /// Returns an error if `value` is not a valid BN254 scalar field element.
    pub fn new(value: BigUint) -> Result<Self, ParseDomainError> {
        validate_bn254_scalar(&value, "nullifying key must fit within the BN254 scalar field")?;
        Ok(Self(value))
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
    ///
    /// This constructor validates the canonical 32-byte encoding boundary rather
    /// than BN254 scalar-field membership. Existing canonical address vectors in
    /// the RAILGUN ecosystem include master public key values that fit the fixed
    /// 32-byte payload but are not constrained here to the BN254 modulus.
    ///
    /// # Errors
    ///
    /// Returns an error if `value` does not fit within the canonical 32-byte
    /// master-public-key encoding.
    pub fn new(value: BigUint) -> Result<Self, ParseDomainError> {
        if value.to_bytes_be().len() > 32 {
            return Err(ParseDomainError::new("master public key must fit within 32 bytes"));
        }
        Ok(Self(value))
    }

    /// Returns the underlying field-element integer value.
    #[must_use]
    pub const fn value(&self) -> &BigUint {
        &self.0
    }
}

/// Typed 16-byte note random used in note public key derivation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct NoteRandom([u8; 16]);

impl NoteRandom {
    /// Length of a note random in bytes.
    pub const LENGTH: usize = 16;

    /// Creates a note random from raw bytes.
    #[must_use]
    pub const fn new(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    /// Creates a note random from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns an error if `bytes` is not exactly 16 bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ParseDomainError> {
        let array: [u8; Self::LENGTH] = bytes
            .try_into()
            .map_err(|_| ParseDomainError::new("note random must be exactly 16 bytes"))?;
        Ok(Self::new(array))
    }

    /// Returns the raw note-random bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}

/// Typed Railgun note public key derived from receiver identity and note randomness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotePublicKey(BigUint);

impl NotePublicKey {
    /// Creates a note public key from a field-element integer value.
    ///
    /// # Errors
    ///
    /// Returns an error if `value` is not a valid BN254 scalar field element.
    pub fn new(value: BigUint) -> Result<Self, ParseDomainError> {
        validate_bn254_scalar(&value, "note public key must fit within the BN254 scalar field")?;
        Ok(Self(value))
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
    /// Parses and validates a canonical Railgun address.
    ///
    /// # Errors
    ///
    /// Returns an error if the address is not canonical lowercase bech32m `0zk`
    /// data with a supported version and valid payload semantics.
    pub fn parse(value: &str) -> Result<Self, ParseDomainError> {
        validate_railgun_address(value)?;
        Ok(Self(value.to_owned()))
    }

    /// Returns the encoded address string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for RailgunAddress {
    type Error = ParseDomainError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl TryFrom<String> for RailgunAddress {
    type Error = ParseDomainError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
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

/// Stable Railgun token-type discriminator used in canonical token data.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TokenType {
    /// Fungible ERC20 token.
    ERC20 = 0,
    /// Non-fungible ERC721 token.
    ERC721 = 1,
    /// Semi-fungible ERC1155 token.
    ERC1155 = 2,
}

impl TokenType {
    /// Returns the stable numeric discriminator.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for TokenType {
    type Error = ParseDomainError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::ERC20),
            1 => Ok(Self::ERC721),
            2 => Ok(Self::ERC1155),
            _ => Err(ParseDomainError::new("token type is unsupported")),
        }
    }
}

/// Typed 32-byte token sub-ID used by canonical token data.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TokenSubId([u8; 32]);

impl TokenSubId {
    /// Length of a token sub-ID in bytes.
    pub const LENGTH: usize = 32;

    /// Creates a token sub-ID from raw bytes.
    #[must_use]
    pub const fn new(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    /// Returns the canonical zero sub-ID.
    #[must_use]
    pub const fn zero() -> Self {
        Self([0_u8; Self::LENGTH])
    }

    /// Creates a token sub-ID from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns an error if `bytes` is not exactly 32 bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ParseDomainError> {
        let array: [u8; Self::LENGTH] = bytes
            .try_into()
            .map_err(|_| ParseDomainError::new("token sub id must be exactly 32 bytes"))?;
        Ok(Self::new(array))
    }

    /// Returns whether the sub-ID is the canonical zero value.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0 == [0_u8; Self::LENGTH]
    }

    /// Returns the raw token sub-ID bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}

/// Canonical Railgun token data.
///
/// Protocol serialization pads `token_address` to 32 bytes, encodes
/// `token_type` as a numeric discriminator, and stores `token_sub_id` as 32
/// bytes. ERC20 values must use the zero sub-ID.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TokenData {
    token_address: Address,
    token_type: TokenType,
    token_sub_id: TokenSubId,
}

impl TokenData {
    /// Creates validated canonical token data.
    ///
    /// # Errors
    ///
    /// Returns an error if an ERC20 token uses a non-zero sub-ID.
    pub fn new(
        token_address: Address,
        token_type: TokenType,
        token_sub_id: TokenSubId,
    ) -> Result<Self, ParseDomainError> {
        if token_type == TokenType::ERC20 && !token_sub_id.is_zero() {
            return Err(ParseDomainError::new("erc20 token sub id must be zero"));
        }

        Ok(Self { token_address, token_type, token_sub_id })
    }

    /// Creates canonical ERC20 token data with the required zero sub-ID.
    #[must_use]
    pub const fn erc20(token_address: Address) -> Self {
        Self { token_address, token_type: TokenType::ERC20, token_sub_id: TokenSubId::zero() }
    }

    /// Returns the semantic token address.
    #[must_use]
    pub const fn token_address(&self) -> Address {
        self.token_address
    }

    /// Returns the token type discriminator.
    #[must_use]
    pub const fn token_type(&self) -> TokenType {
        self.token_type
    }

    /// Returns the canonical 32-byte token sub-ID.
    #[must_use]
    pub const fn token_sub_id(&self) -> &TokenSubId {
        &self.token_sub_id
    }
}

/// Typed 32-byte token hash used as the asset identity primitive.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TokenHash([u8; 32]);

impl TokenHash {
    /// Length of a token hash in bytes.
    pub const LENGTH: usize = 32;

    /// Creates a token hash from raw bytes.
    #[must_use]
    pub const fn new(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    /// Creates a token hash from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns an error if `bytes` is not exactly 32 bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ParseDomainError> {
        let array: [u8; Self::LENGTH] = bytes
            .try_into()
            .map_err(|_| ParseDomainError::new("token hash must be exactly 32 bytes"))?;
        Ok(Self::new(array))
    }

    /// Returns the raw token-hash bytes.
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
    use num_bigint::BigUint;

    use super::{
        Address, BN254_SCALAR_FIELD_MODULUS_BYTES, MasterPublicKey, NotePublicKey, NoteRandom,
        NullifyingKey, ParseDomainError, RailgunAddress, SpendingPrivateKey, SpendingPublicKey,
        TokenData, TokenSubId, TokenType, ViewingPrivateKey, ViewingPublicKey,
    };

    const BN254_SCALAR_FIELD_MODULUS_DECIMAL: &str =
        "21888242871839275222246405745257275088548364400416034343698204186575808495617";

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

    #[test]
    fn rejects_invalid_note_random_length() {
        let Err(error) = NoteRandom::from_slice(&[7_u8; 15]) else {
            panic!("invalid note random length should fail");
        };
        assert_eq!(error, ParseDomainError::new("note random must be exactly 16 bytes"));
    }

    #[test]
    fn rejects_invalid_nullifying_key_field_element() {
        let Err(error) = NullifyingKey::new(super::bn254_scalar_field_modulus()) else {
            panic!("invalid nullifying key should fail");
        };
        assert_eq!(
            error,
            ParseDomainError::new("nullifying key must fit within the BN254 scalar field")
        );
    }

    #[test]
    fn bn254_scalar_field_modulus_decimal_matches_bytes() {
        let parsed = BigUint::parse_bytes(BN254_SCALAR_FIELD_MODULUS_DECIMAL.as_bytes(), 10)
            .unwrap_or_else(|| panic!("bn254 scalar modulus decimal should parse"));

        assert_eq!(parsed.to_bytes_be(), BN254_SCALAR_FIELD_MODULUS_BYTES);
    }

    #[test]
    fn rejects_invalid_note_public_key_field_element() {
        let Err(error) = NotePublicKey::new(super::bn254_scalar_field_modulus()) else {
            panic!("invalid note public key should fail");
        };
        assert_eq!(
            error,
            ParseDomainError::new("note public key must fit within the BN254 scalar field")
        );
    }

    #[test]
    fn rejects_master_public_key_larger_than_32_bytes() {
        let Err(error) = MasterPublicKey::new(BigUint::from_bytes_be(&[1_u8; 33])) else {
            panic!("oversized master public key should fail");
        };
        assert_eq!(error, ParseDomainError::new("master public key must fit within 32 bytes"));
    }

    #[test]
    fn rejects_invalid_spending_public_key_point() {
        let Err(error) = SpendingPublicKey::new(BigUint::from(1_u8), BigUint::from(1_u8)) else {
            panic!("invalid spending public key should fail");
        };
        assert_eq!(
            error,
            ParseDomainError::new(
                "spending public key coordinates must form a valid BabyJubJub point"
            )
        );
    }

    #[test]
    fn parses_valid_railgun_address() {
        let Ok(address) = RailgunAddress::parse(
            "0zk1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqunpd9kxwatwqyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqhshkca",
        ) else {
            panic!("canonical address should parse");
        };

        assert!(address.as_str().starts_with("0zk1"));
    }

    #[test]
    fn rejects_noncanonical_railgun_address() {
        let Err(error) = RailgunAddress::parse(
            "RGANY1PNJ7U66VWQHCQUXGMH4PEWUTPA4Y55VTWLAG60UMDPSHKEJ92RN47EY76GES3T3ENN",
        ) else {
            panic!("invalid address should fail");
        };

        assert_eq!(
            error,
            ParseDomainError::new("railgun address must use canonical lowercase encoding")
        );
    }

    #[test]
    fn rejects_invalid_address_length() {
        let Err(error) = Address::from_slice(&[7_u8; 19]) else {
            panic!("invalid address length should fail");
        };

        assert_eq!(error, ParseDomainError::new("address must be exactly 20 bytes"));
    }

    #[test]
    fn rejects_invalid_token_sub_id_length() {
        let Err(error) = TokenSubId::from_slice(&[9_u8; 31]) else {
            panic!("invalid token sub id length should fail");
        };

        assert_eq!(error, ParseDomainError::new("token sub id must be exactly 32 bytes"));
    }

    #[test]
    fn rejects_unsupported_token_type() {
        let Err(error) = TokenType::try_from(9_u8) else {
            panic!("unsupported token type should fail");
        };

        assert_eq!(error, ParseDomainError::new("token type is unsupported"));
    }

    #[test]
    fn rejects_non_zero_erc20_token_sub_id() {
        let address = Address::new([1_u8; Address::LENGTH]);
        let mut sub_id_bytes = [0_u8; TokenSubId::LENGTH];
        sub_id_bytes[31] = 1;

        let Err(error) = TokenData::new(address, TokenType::ERC20, TokenSubId::new(sub_id_bytes))
        else {
            panic!("erc20 token data with non-zero sub id should fail");
        };

        assert_eq!(error, ParseDomainError::new("erc20 token sub id must be zero"));
    }

    #[test]
    fn creates_erc20_token_data_with_zero_sub_id() {
        let address = Address::new([2_u8; Address::LENGTH]);
        let token_data = TokenData::erc20(address);

        assert_eq!(token_data.token_address(), address);
        assert_eq!(token_data.token_type(), TokenType::ERC20);
        assert!(token_data.token_sub_id().is_zero());
    }
}
