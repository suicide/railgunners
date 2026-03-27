//! Canonical `0zk` Railgun address encoding and decoding.

use core::fmt;

use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Bech32m, Hrp};
use num_bigint::BigUint;
use railgun_types::{
    ChainScope, MasterPublicKey, NetworkId, RailgunAddress, RailgunAddressData, ViewingPublicKey,
};

use crate::network_id::{NetworkIdError, decode_network_id, encode_network_id};

const ADDRESS_VERSION_V1: u8 = 1;
const ADDRESS_HRP: &str = "0zk";
const ADDRESS_MAX_LENGTH: usize = 127;
const MASTER_PUBLIC_KEY_LENGTH: usize = 32;
const VIEWING_PUBLIC_KEY_LENGTH: usize = 32;
const ADDRESS_PAYLOAD_LENGTH: usize =
    1 + MASTER_PUBLIC_KEY_LENGTH + NetworkId::LENGTH + VIEWING_PUBLIC_KEY_LENGTH;
const MASTER_PUBLIC_KEY_OFFSET: usize = 1;
const NETWORK_ID_OFFSET: usize = MASTER_PUBLIC_KEY_OFFSET + MASTER_PUBLIC_KEY_LENGTH;
const VIEWING_PUBLIC_KEY_OFFSET: usize = NETWORK_ID_OFFSET + NetworkId::LENGTH;

/// Error returned when Railgun address encoding fails.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AddressEncodingError {
    /// Address version is not supported by this implementation.
    UnsupportedVersion(u8),
    /// Master public key does not fit the canonical 32-byte payload field.
    InvalidMasterPublicKey,
    /// Bech32m encoding failed unexpectedly.
    InvalidBech32mEncoding,
    /// Encoded address exceeds the supported maximum length.
    EncodedLengthExceeded(usize),
    /// The chain encoding collides with the reserved all-chains sentinel.
    ReservedNetworkId,
}

impl fmt::Display for AddressEncodingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported address version: {version}")
            }
            Self::InvalidMasterPublicKey => {
                formatter.write_str("master public key must fit within 32 bytes")
            }
            Self::InvalidBech32mEncoding => {
                formatter.write_str("invalid `bech32m` encoding operation")
            }
            Self::EncodedLengthExceeded(length) => {
                write!(formatter, "encoded address length exceeds 127 characters: {length}")
            }
            Self::ReservedNetworkId => formatter
                .write_str("chain encoding collides with the reserved all-chains network id"),
        }
    }
}

impl std::error::Error for AddressEncodingError {}

/// Error returned when Railgun address decoding fails.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AddressDecodingError {
    /// Encoded address exceeds the supported maximum length.
    EncodedLengthExceeded(usize),
    /// Address contains uppercase characters and is not in canonical lowercase form.
    NonCanonicalCase,
    /// Address is not valid bech32m.
    InvalidBech32m,
    /// Address uses an unexpected human-readable prefix.
    InvalidPrefix,
    /// Address payload length does not match the canonical fixed-width layout.
    InvalidPayloadLength(usize),
    /// Address version is not supported by this implementation.
    UnsupportedVersion(u8),
    /// Network identifier cannot be decoded into a supported chain scope.
    InvalidNetworkId,
}

impl fmt::Display for AddressDecodingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EncodedLengthExceeded(length) => {
                write!(formatter, "encoded address length exceeds 127 characters: {length}")
            }
            Self::NonCanonicalCase => {
                formatter.write_str("address must use canonical lowercase encoding")
            }
            Self::InvalidBech32m => formatter.write_str("invalid bech32m address"),
            Self::InvalidPrefix => formatter.write_str("invalid address prefix"),
            Self::InvalidPayloadLength(length) => {
                write!(formatter, "invalid address payload length: {length}")
            }
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported address version: {version}")
            }
            Self::InvalidNetworkId => formatter.write_str("invalid network id"),
        }
    }
}

impl std::error::Error for AddressDecodingError {}

fn master_public_key_to_bytes(
    master_public_key: &MasterPublicKey,
) -> Result<[u8; MASTER_PUBLIC_KEY_LENGTH], AddressEncodingError> {
    let bytes = master_public_key.value().to_bytes_be();
    if bytes.len() > MASTER_PUBLIC_KEY_LENGTH {
        return Err(AddressEncodingError::InvalidMasterPublicKey);
    }

    let mut padded = [0_u8; MASTER_PUBLIC_KEY_LENGTH];
    let offset = MASTER_PUBLIC_KEY_LENGTH - bytes.len();
    padded[offset..].copy_from_slice(&bytes);
    Ok(padded)
}

impl From<NetworkIdError> for AddressEncodingError {
    fn from(error: NetworkIdError) -> Self {
        match error {
            NetworkIdError::ReservedNetworkId => Self::ReservedNetworkId,
            NetworkIdError::InvalidNetworkId => Self::InvalidBech32mEncoding,
        }
    }
}

impl From<NetworkIdError> for AddressDecodingError {
    fn from(error: NetworkIdError) -> Self {
        match error {
            NetworkIdError::ReservedNetworkId | NetworkIdError::InvalidNetworkId => {
                Self::InvalidNetworkId
            }
        }
    }
}

/// Encodes a canonical `0zk` Railgun address.
///
/// # Errors
///
/// Returns an error if `version` is unsupported, if `master_public_key` does
/// not fit the canonical 32-byte payload field, or if `bech32m` encoding fails.
pub fn encode_railgun_address(
    version: u8,
    master_public_key: &MasterPublicKey,
    chain_scope: ChainScope,
    viewing_public_key: &ViewingPublicKey,
) -> Result<RailgunAddress, AddressEncodingError> {
    if version != ADDRESS_VERSION_V1 {
        return Err(AddressEncodingError::UnsupportedVersion(version));
    }

    let master_public_key = master_public_key_to_bytes(master_public_key)?;
    let network_id = encode_network_id(chain_scope)?;
    let mut payload = Vec::with_capacity(ADDRESS_PAYLOAD_LENGTH);
    payload.push(version);
    payload.extend_from_slice(&master_public_key);
    payload.extend_from_slice(network_id.as_bytes());
    payload.extend_from_slice(viewing_public_key.as_bytes());

    let hrp = Hrp::parse(ADDRESS_HRP).map_err(|_| AddressEncodingError::InvalidBech32mEncoding)?;
    let address = bech32::encode::<Bech32m>(hrp, &payload)
        .map_err(|_| AddressEncodingError::InvalidBech32mEncoding)?;

    if address.len() > ADDRESS_MAX_LENGTH {
        return Err(AddressEncodingError::EncodedLengthExceeded(address.len()));
    }

    Ok(RailgunAddress::new(address))
}

/// Decodes and validates a canonical `0zk` Railgun address.
///
/// # Errors
///
/// Returns an error if the address is not canonical lowercase `bech32m`, does
/// not use the `0zk` prefix, has an unsupported payload length or version, or
/// contains an invalid network identifier.
pub fn decode_railgun_address(address: &str) -> Result<RailgunAddressData, AddressDecodingError> {
    if address != address.to_ascii_lowercase() {
        return Err(AddressDecodingError::NonCanonicalCase);
    }
    if address.len() > ADDRESS_MAX_LENGTH {
        return Err(AddressDecodingError::EncodedLengthExceeded(address.len()));
    }

    let hrp = Hrp::parse(ADDRESS_HRP).map_err(|_| AddressDecodingError::InvalidPrefix)?;
    let checked = CheckedHrpstring::new::<Bech32m>(address)
        .map_err(|_| AddressDecodingError::InvalidBech32m)?;
    if checked.hrp() != hrp {
        return Err(AddressDecodingError::InvalidPrefix);
    }
    let payload: Vec<u8> = checked.byte_iter().collect();
    if payload.len() != ADDRESS_PAYLOAD_LENGTH {
        return Err(AddressDecodingError::InvalidPayloadLength(payload.len()));
    }

    let version = payload[0];
    if version != ADDRESS_VERSION_V1 {
        return Err(AddressDecodingError::UnsupportedVersion(version));
    }

    let master_public_key = MasterPublicKey::new(BigUint::from_bytes_be(
        &payload[MASTER_PUBLIC_KEY_OFFSET..NETWORK_ID_OFFSET],
    ));
    let network_id = NetworkId::from_slice(&payload[NETWORK_ID_OFFSET..VIEWING_PUBLIC_KEY_OFFSET])
        .map_err(|_| AddressDecodingError::InvalidPayloadLength(payload.len()))?;
    let chain_scope = decode_network_id(network_id)?;
    let viewing_public_key = ViewingPublicKey::from_slice(&payload[VIEWING_PUBLIC_KEY_OFFSET..])
        .map_err(|_| AddressDecodingError::InvalidPayloadLength(payload.len()))?;

    Ok(RailgunAddressData::new(version, master_public_key, chain_scope, viewing_public_key))
}

#[cfg(test)]
mod tests {
    use bech32::{Bech32m, Hrp};
    use num_bigint::BigUint;
    use railgun_types::{ChainScope, ChainType, MasterPublicKey, RailgunChain, ViewingPublicKey};

    use super::{
        ADDRESS_MAX_LENGTH, ADDRESS_PAYLOAD_LENGTH, ADDRESS_VERSION_V1, AddressDecodingError,
        AddressEncodingError, decode_railgun_address, encode_railgun_address,
    };

    #[test]
    fn encodes_address_vector_one() {
        let master_public_key = MasterPublicKey::new(padded_hex_biguint("00000000"));
        let viewing_public_key = ViewingPublicKey::new(padded_hex_array::<32>("00000000"));
        let chain = RailgunChain::new(ChainType::new(0), 1)
            .unwrap_or_else(|_| panic!("test chain should be valid"));
        let address = encode_railgun_address(
            1,
            &master_public_key,
            ChainScope::Chain(chain),
            &viewing_public_key,
        )
        .unwrap_or_else(|_| panic!("address encoding should succeed"));

        assert_eq!(
            address.as_str(),
            "0zk1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqunpd9kxwatwqyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqhshkca"
        );
        assert!(address.as_str().starts_with("0zk1"));
        assert_eq!(address.as_str().len(), ADDRESS_MAX_LENGTH);
    }

    #[test]
    fn decodes_canonical_valid_vector() {
        let decoded = decode_railgun_address(
            "0zk1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqunpd9kxwatwqyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqhshkca",
        )
        .unwrap_or_else(|_| panic!("address decoding should succeed"));

        let expected_chain = RailgunChain::new(ChainType::new(0), 1)
            .unwrap_or_else(|_| panic!("test chain should be valid"));
        assert_eq!(decoded.version(), 1);
        assert_eq!(decoded.master_public_key().value(), &BigUint::from(0_u8));
        assert_eq!(decoded.chain_scope(), ChainScope::Chain(expected_chain));
        assert_eq!(hex_encode(decoded.viewing_public_key().as_bytes()), hex_encode(&[0_u8; 32]));
    }

    #[test]
    fn encodes_address_vector_two() {
        let master_public_key = MasterPublicKey::new(padded_hex_biguint(
            "01bfd5681c0479be9a8ef8dd8baadd97115899a9af30b3d2455843afb41b",
        ));
        let viewing_public_key = ViewingPublicKey::new(padded_hex_array::<32>(
            "01bfd5681c0479be9a8ef8dd8baadd97115899a9af30b3d2455843afb41b",
        ));
        let chain = RailgunChain::new(ChainType::new(0), 56)
            .unwrap_or_else(|_| panic!("test chain should be valid"));
        let address = encode_railgun_address(
            1,
            &master_public_key,
            ChainScope::Chain(chain),
            &viewing_public_key,
        )
        .unwrap_or_else(|_| panic!("address encoding should succeed"));

        assert_eq!(
            address.as_str(),
            "0zk1qyqqqqdl645pcpreh6dga7xa3w4dm9c3tzv6ntesk0fy2kzr476pkunpd9kxwatw8qqqqqdl645pcpreh6dga7xa3w4dm9c3tzv6ntesk0fy2kzr476pkcsu8tp"
        );
    }

    #[test]
    fn decodes_address_vector_two() {
        let decoded = decode_railgun_address(
            "0zk1qyqqqqdl645pcpreh6dga7xa3w4dm9c3tzv6ntesk0fy2kzr476pkunpd9kxwatw8qqqqqdl645pcpreh6dga7xa3w4dm9c3tzv6ntesk0fy2kzr476pkcsu8tp",
        )
        .unwrap_or_else(|_| panic!("address decoding should succeed"));

        let expected_chain = RailgunChain::new(ChainType::new(0), 56)
            .unwrap_or_else(|_| panic!("test chain should be valid"));
        assert_eq!(decoded.version(), 1);
        assert_eq!(
            hex_encode(&decoded.master_public_key().value().to_bytes_be()),
            "01bfd5681c0479be9a8ef8dd8baadd97115899a9af30b3d2455843afb41b"
        );
        assert_eq!(decoded.chain_scope(), ChainScope::Chain(expected_chain));
        assert_eq!(
            hex_encode(decoded.viewing_public_key().as_bytes()),
            "000001bfd5681c0479be9a8ef8dd8baadd97115899a9af30b3d2455843afb41b"
        );
    }

    #[test]
    fn encodes_address_vector_three() {
        let master_public_key = MasterPublicKey::new(padded_hex_biguint(
            "ee6b4c702f8070c8ddea1cbb8b0f6a4a518b77fa8d3f9b68617b664550e75f64",
        ));
        let viewing_public_key = ViewingPublicKey::new(padded_hex_array::<32>(
            "ee6b4c702f8070c8ddea1cbb8b0f6a4a518b77fa8d3f9b68617b664550e75f64",
        ));
        let address = encode_railgun_address(
            1,
            &master_public_key,
            ChainScope::AllChains,
            &viewing_public_key,
        )
        .unwrap_or_else(|_| panic!("address encoding should succeed"));

        assert_eq!(
            address.as_str(),
            "0zk1q8hxknrs97q8pjxaagwthzc0df99rzmhl2xnlxmgv9akv32sua0kfrv7j6fe3z53llhxknrs97q8pjxaagwthzc0df99rzmhl2xnlxmgv9akv32sua0kg0zpzts"
        );
    }

    #[test]
    fn decodes_address_vector_three() {
        let decoded = decode_railgun_address(
            "0zk1q8hxknrs97q8pjxaagwthzc0df99rzmhl2xnlxmgv9akv32sua0kfrv7j6fe3z53llhxknrs97q8pjxaagwthzc0df99rzmhl2xnlxmgv9akv32sua0kg0zpzts",
        )
        .unwrap_or_else(|_| panic!("address decoding should succeed"));

        assert_eq!(decoded.version(), 1);
        assert_eq!(decoded.chain_scope(), ChainScope::AllChains);
        assert_eq!(
            hex_encode(&decoded.master_public_key().value().to_bytes_be()),
            "ee6b4c702f8070c8ddea1cbb8b0f6a4a518b77fa8d3f9b68617b664550e75f64"
        );
        assert_eq!(
            hex_encode(decoded.viewing_public_key().as_bytes()),
            "ee6b4c702f8070c8ddea1cbb8b0f6a4a518b77fa8d3f9b68617b664550e75f64"
        );
    }

    #[test]
    fn round_trips_chain_scoped_address() {
        let master_public_key = MasterPublicKey::new(padded_hex_biguint("1234"));
        let viewing_public_key = ViewingPublicKey::new(padded_hex_array::<32>("5678"));
        let chain = RailgunChain::new(ChainType::new(2), 137)
            .unwrap_or_else(|_| panic!("test chain should be valid"));

        let address = encode_railgun_address(
            ADDRESS_VERSION_V1,
            &master_public_key,
            ChainScope::Chain(chain),
            &viewing_public_key,
        )
        .unwrap_or_else(|_| panic!("address encoding should succeed"));
        let decoded = decode_railgun_address(address.as_str())
            .unwrap_or_else(|_| panic!("address decoding should succeed"));

        assert_eq!(decoded.version(), ADDRESS_VERSION_V1);
        assert_eq!(decoded.master_public_key(), &master_public_key);
        assert_eq!(decoded.chain_scope(), ChainScope::Chain(chain));
        assert_eq!(decoded.viewing_public_key(), &viewing_public_key);
    }

    #[test]
    fn round_trips_all_chains_address() {
        let master_public_key = MasterPublicKey::new(padded_hex_biguint("abcd"));
        let viewing_public_key = ViewingPublicKey::new(padded_hex_array::<32>("dcba"));

        let address = encode_railgun_address(
            ADDRESS_VERSION_V1,
            &master_public_key,
            ChainScope::AllChains,
            &viewing_public_key,
        )
        .unwrap_or_else(|_| panic!("address encoding should succeed"));
        let decoded = decode_railgun_address(address.as_str())
            .unwrap_or_else(|_| panic!("address decoding should succeed"));

        assert_eq!(decoded.version(), ADDRESS_VERSION_V1);
        assert_eq!(decoded.master_public_key(), &master_public_key);
        assert_eq!(decoded.chain_scope(), ChainScope::AllChains);
        assert_eq!(decoded.viewing_public_key(), &viewing_public_key);
    }

    #[test]
    fn rejects_invalid_checksum_vector() {
        let error = expect_err(
            decode_railgun_address(
                "rgany1pnj7u66vwqhcquxgmh4pewutpa4y55vtwlag60umdpshkej92rn47ey76ges3t3enn",
            ),
            "invalid checksum should fail",
        );

        assert_eq!(error, AddressDecodingError::InvalidBech32m);
    }

    #[test]
    fn rejects_invalid_prefix_vector() {
        let error = expect_err(
            decode_railgun_address(
                "rg1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqunpd9kxwatwqyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqsfhuuw",
            ),
            "invalid prefix should fail",
        );

        assert_eq!(error, AddressDecodingError::InvalidPrefix);
    }

    #[test]
    fn rejects_uppercase_address_as_noncanonical() {
        let address = encode_railgun_address(
            1,
            &MasterPublicKey::new(BigUint::from(0_u8)),
            ChainScope::AllChains,
            &ViewingPublicKey::new([0_u8; 32]),
        )
        .unwrap_or_else(|_| panic!("address encoding should succeed"));
        let error = expect_err(
            decode_railgun_address(&address.as_str().to_ascii_uppercase()),
            "uppercase address should fail",
        );

        assert_eq!(error, AddressDecodingError::NonCanonicalCase);
    }

    #[test]
    fn rejects_unsupported_address_version() {
        let error = expect_err(
            encode_railgun_address(
                2,
                &MasterPublicKey::new(BigUint::from(0_u8)),
                ChainScope::AllChains,
                &ViewingPublicKey::new([0_u8; 32]),
            ),
            "unsupported version should fail",
        );

        assert_eq!(error, AddressEncodingError::UnsupportedVersion(2));
    }

    #[test]
    fn rejects_unsupported_decoded_address_version() {
        let invalid_address = bech32_address_from_payload(
            [vec![2_u8], vec![0_u8; 32], hex_decode("7261696c67756e01"), vec![0_u8; 32]].concat(),
        );

        let error = expect_err(
            decode_railgun_address(&invalid_address),
            "unsupported decoded version should fail",
        );

        assert_eq!(error, AddressDecodingError::UnsupportedVersion(2));
    }

    #[test]
    fn rejects_master_public_key_longer_than_32_bytes() {
        let error = expect_err(
            encode_railgun_address(
                1,
                &MasterPublicKey::new(BigUint::from_bytes_be(&[1_u8; 33])),
                ChainScope::AllChains,
                &ViewingPublicKey::new([0_u8; 32]),
            ),
            "oversized master public key should fail",
        );

        assert_eq!(error, AddressEncodingError::InvalidMasterPublicKey);
    }

    #[test]
    fn rejects_wrong_payload_length() {
        let invalid_address = bech32_address_from_payload(vec![0_u8; ADDRESS_PAYLOAD_LENGTH - 1]);

        let error =
            expect_err(decode_railgun_address(&invalid_address), "short payload should fail");

        assert_eq!(error, AddressDecodingError::InvalidPayloadLength(ADDRESS_PAYLOAD_LENGTH - 1));
    }

    #[test]
    fn rejects_non_bech32m_checksum() {
        let invalid_address =
            bech32_address_from_payload_bech32(vec![0_u8; ADDRESS_PAYLOAD_LENGTH]);

        let error =
            expect_err(decode_railgun_address(&invalid_address), "bech32 checksum should fail");

        assert_eq!(error, AddressDecodingError::InvalidBech32m);
    }

    #[test]
    fn rejects_chain_id_larger_than_56_bits() {
        let error = RailgunChain::new(ChainType::new(0), 1_u64 << 56)
            .err()
            .unwrap_or_else(|| panic!("oversized chain id should fail"));

        assert_eq!(error.to_string(), "chain id must fit within 56 bits");
    }

    fn bech32_address_from_payload(payload: Vec<u8>) -> String {
        let hrp = Hrp::parse("0zk").unwrap_or_else(|_| panic!("test hrp should be valid"));
        bech32::encode::<Bech32m>(hrp, &payload)
            .unwrap_or_else(|_| panic!("test bech32m encoding should succeed"))
    }

    fn bech32_address_from_payload_bech32(payload: Vec<u8>) -> String {
        let hrp = Hrp::parse("0zk").unwrap_or_else(|_| panic!("test hrp should be valid"));
        bech32::encode::<bech32::Bech32>(hrp, &payload)
            .unwrap_or_else(|_| panic!("test bech32 encoding should succeed"))
    }

    fn padded_hex_biguint(hex: &str) -> BigUint {
        BigUint::from_bytes_be(&padded_hex_bytes::<32>(hex))
    }

    fn padded_hex_array<const N: usize>(hex: &str) -> [u8; N] {
        padded_hex_bytes::<N>(hex)
            .try_into()
            .unwrap_or_else(|_| panic!("test vector should match requested length"))
    }

    fn padded_hex_bytes<const N: usize>(hex: &str) -> Vec<u8> {
        let mut bytes = hex_decode(hex);
        assert!(bytes.len() <= N, "test hex should fit requested width");

        let mut padded = vec![0_u8; N - bytes.len()];
        padded.append(&mut bytes);
        padded
    }

    fn hex_decode(hex: &str) -> Vec<u8> {
        let bytes = hex.as_bytes();
        let mut decoded = Vec::with_capacity(bytes.len() / 2);
        for pair in bytes.chunks_exact(2) {
            let high = char::from(pair[0])
                .to_digit(16)
                .unwrap_or_else(|| panic!("test hex should be valid"));
            let low = char::from(pair[1])
                .to_digit(16)
                .unwrap_or_else(|| panic!("test hex should be valid"));
            decoded.push(
                u8::try_from((high << 4) | low)
                    .unwrap_or_else(|_| panic!("test hex should fit in a byte")),
            );
        }
        decoded
    }

    fn hex_encode(bytes: &[u8]) -> String {
        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            let high = byte >> 4;
            let low = byte & 0x0F;
            encoded.push(char::from(if high < 10 { b'0' + high } else { b'a' + (high - 10) }));
            encoded.push(char::from(if low < 10 { b'0' + low } else { b'a' + (low - 10) }));
        }
        encoded
    }

    fn expect_err<T, E>(result: Result<T, E>, message: &str) -> E {
        match result {
            Ok(_) => panic!("{message}"),
            Err(error) => error,
        }
    }
}
