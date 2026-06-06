use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Bech32m, Hrp};

use crate::{MasterPublicKey, ParseDomainError, ViewingPublicKey};

const ADDRESS_HRP: &str = "0zk";
const ADDRESS_MAX_LENGTH: usize = 127;
const ADDRESS_VERSION_V1: u8 = 1;
const ADDRESS_PAYLOAD_LENGTH: usize = 73;
const NETWORK_ID_XOR_KEY: [u8; 8] = *b"railgun\0";

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

    let master_public_key = num_bigint::BigUint::from_bytes_be(&payload[1..33]);
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

#[cfg(test)]
mod tests {
    use super::RailgunAddress;
    use crate::ParseDomainError;

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
}
