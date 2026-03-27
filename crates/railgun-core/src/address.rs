//! Canonical `0zk` Railgun address encoding.

use core::fmt;

use bech32::{Bech32m, Hrp};
use railgun_types::{ChainScope, MasterPublicKey, NetworkId, RailgunAddress, ViewingPublicKey};

const ADDRESS_VERSION_V1: u8 = 1;
const ADDRESS_HRP: &str = "0zk";
const ADDRESS_MAX_LENGTH: usize = 127;
const MASTER_PUBLIC_KEY_LENGTH: usize = 32;
const NETWORK_ID_XOR_MASK: [u8; NetworkId::LENGTH] = *b"railgun\x00";
const ALL_CHAINS_RAW_NETWORK_ID: [u8; NetworkId::LENGTH] = [0xFF; NetworkId::LENGTH];

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
        }
    }
}

impl std::error::Error for AddressEncodingError {}

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

fn xor_network_id(bytes: [u8; NetworkId::LENGTH]) -> [u8; NetworkId::LENGTH] {
    let mut encoded = [0_u8; NetworkId::LENGTH];
    for (index, byte) in bytes.iter().enumerate() {
        encoded[index] = *byte ^ NETWORK_ID_XOR_MASK[index];
    }
    encoded
}

fn encode_network_id(scope: ChainScope) -> NetworkId {
    let raw = match scope {
        ChainScope::AllChains => ALL_CHAINS_RAW_NETWORK_ID,
        ChainScope::Chain(chain) => {
            let packed = (u64::from(chain.chain_type().get()) << 56) | chain.chain_id();
            packed.to_be_bytes()
        }
    };

    NetworkId::new(xor_network_id(raw))
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
    let network_id = encode_network_id(chain_scope);
    let mut payload = Vec::with_capacity(
        1 + MASTER_PUBLIC_KEY_LENGTH + NetworkId::LENGTH + ViewingPublicKey::LENGTH,
    );
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

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;
    use railgun_types::{ChainScope, ChainType, MasterPublicKey, RailgunChain, ViewingPublicKey};

    use super::{
        ADDRESS_MAX_LENGTH, AddressEncodingError, encode_network_id, encode_railgun_address,
    };

    #[test]
    fn encodes_network_id_vector_one() {
        let chain = RailgunChain::new(ChainType::new(0), 1)
            .unwrap_or_else(|_| panic!("test chain should be valid"));

        assert_eq!(
            hex_encode(encode_network_id(ChainScope::Chain(chain)).as_bytes()),
            "7261696c67756e01"
        );
    }

    #[test]
    fn encodes_network_id_vector_two() {
        let chain = RailgunChain::new(ChainType::new(1), 56)
            .unwrap_or_else(|_| panic!("test chain should be valid"));

        assert_eq!(
            hex_encode(encode_network_id(ChainScope::Chain(chain)).as_bytes()),
            "7361696c67756e38"
        );
    }

    #[test]
    fn encodes_network_id_all_chains_vector() {
        assert_eq!(
            hex_encode(encode_network_id(ChainScope::AllChains).as_bytes()),
            "8d9e9693988a91ff"
        );
    }

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
    fn rejects_chain_id_larger_than_56_bits() {
        let error = RailgunChain::new(ChainType::new(0), 1_u64 << 56)
            .err()
            .unwrap_or_else(|| panic!("oversized chain id should fail"));

        assert_eq!(error.to_string(), "chain id must fit within 56 bits");
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
