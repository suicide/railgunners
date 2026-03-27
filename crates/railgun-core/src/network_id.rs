//! Railgun network ID packing and decoding.

use core::fmt;

use railgun_types::{ChainScope, ChainType, NetworkId, RailgunChain};

const NETWORK_ID_XOR_MASK: [u8; NetworkId::LENGTH] = *b"railgun\x00";
const ALL_CHAINS_RAW_NETWORK_ID: [u8; NetworkId::LENGTH] = [0xFF; NetworkId::LENGTH];

/// Error returned when Railgun network ID encoding or decoding fails.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NetworkIdError {
    /// The chain encoding collides with the reserved all-chains sentinel.
    ReservedNetworkId,
    /// Network identifier cannot be decoded into a supported chain scope.
    InvalidNetworkId,
}

impl fmt::Display for NetworkIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReservedNetworkId => formatter
                .write_str("chain encoding collides with the reserved all-chains network id"),
            Self::InvalidNetworkId => formatter.write_str("invalid network id"),
        }
    }
}

impl std::error::Error for NetworkIdError {}

fn xor_network_id(bytes: [u8; NetworkId::LENGTH]) -> [u8; NetworkId::LENGTH] {
    let mut encoded = [0_u8; NetworkId::LENGTH];
    for (index, byte) in bytes.iter().enumerate() {
        encoded[index] = *byte ^ NETWORK_ID_XOR_MASK[index];
    }
    encoded
}

/// Encodes a chain scope into the canonical 8-byte Railgun network ID.
///
/// # Errors
///
/// Returns an error if the provided chain scope collides with the reserved
/// all-chains sentinel value.
pub fn encode_network_id(scope: ChainScope) -> Result<NetworkId, NetworkIdError> {
    let raw = match scope {
        ChainScope::AllChains => ALL_CHAINS_RAW_NETWORK_ID,
        ChainScope::Chain(chain) => {
            if chain.chain_type().get() == u8::MAX && chain.chain_id() == RailgunChain::MAX_CHAIN_ID
            {
                return Err(NetworkIdError::ReservedNetworkId);
            }

            let packed = (u64::from(chain.chain_type().get()) << 56) | chain.chain_id();
            packed.to_be_bytes()
        }
    };

    Ok(NetworkId::new(xor_network_id(raw)))
}

/// Decodes a canonical 8-byte Railgun network ID into a chain scope.
///
/// # Errors
///
/// Returns an error if the network ID cannot be decoded into a supported chain
/// scope.
pub fn decode_network_id(network_id: NetworkId) -> Result<ChainScope, NetworkIdError> {
    let raw = xor_network_id(*network_id.as_bytes());
    if raw == ALL_CHAINS_RAW_NETWORK_ID {
        return Ok(ChainScope::AllChains);
    }

    let packed = u64::from_be_bytes(raw);
    let chain_type =
        ChainType::new(u8::try_from(packed >> 56).map_err(|_| NetworkIdError::InvalidNetworkId)?);
    let chain_id = packed & RailgunChain::MAX_CHAIN_ID;
    let chain =
        RailgunChain::new(chain_type, chain_id).map_err(|_| NetworkIdError::InvalidNetworkId)?;
    Ok(ChainScope::Chain(chain))
}

#[cfg(test)]
mod tests {
    use railgun_types::{ChainScope, ChainType, NetworkId, RailgunChain};

    use super::{NetworkIdError, decode_network_id, encode_network_id};

    #[test]
    fn encodes_network_id_vector_one() {
        let chain = RailgunChain::new(ChainType::new(0), 1)
            .unwrap_or_else(|_| panic!("test chain should be valid"));

        assert_eq!(
            hex_encode(
                encode_network_id(ChainScope::Chain(chain))
                    .unwrap_or_else(|_| panic!("network id encoding should succeed"))
                    .as_bytes(),
            ),
            "7261696c67756e01"
        );
    }

    #[test]
    fn decodes_network_id_vector_one() {
        let chain = RailgunChain::new(ChainType::new(0), 1)
            .unwrap_or_else(|_| panic!("test chain should be valid"));

        assert_eq!(
            decode_network_id(network_id_from_hex("7261696c67756e01"))
                .unwrap_or_else(|_| panic!("network id decoding should succeed")),
            ChainScope::Chain(chain)
        );
    }

    #[test]
    fn encodes_network_id_vector_two() {
        let chain = RailgunChain::new(ChainType::new(1), 56)
            .unwrap_or_else(|_| panic!("test chain should be valid"));

        assert_eq!(
            hex_encode(
                encode_network_id(ChainScope::Chain(chain))
                    .unwrap_or_else(|_| panic!("network id encoding should succeed"))
                    .as_bytes(),
            ),
            "7361696c67756e38"
        );
    }

    #[test]
    fn decodes_network_id_vector_two() {
        let chain = RailgunChain::new(ChainType::new(1), 56)
            .unwrap_or_else(|_| panic!("test chain should be valid"));

        assert_eq!(
            decode_network_id(network_id_from_hex("7361696c67756e38"))
                .unwrap_or_else(|_| panic!("network id decoding should succeed")),
            ChainScope::Chain(chain)
        );
    }

    #[test]
    fn encodes_network_id_all_chains_vector() {
        assert_eq!(
            hex_encode(
                encode_network_id(ChainScope::AllChains)
                    .unwrap_or_else(|_| panic!("network id encoding should succeed"))
                    .as_bytes(),
            ),
            "8d9e9693988a91ff"
        );
    }

    #[test]
    fn decodes_network_id_all_chains_vector() {
        assert_eq!(
            decode_network_id(network_id_from_hex("8d9e9693988a91ff"))
                .unwrap_or_else(|_| panic!("network id decoding should succeed")),
            ChainScope::AllChains
        );
    }

    #[test]
    fn rejects_reserved_network_id_collision_during_encoding() {
        let chain = RailgunChain::new(ChainType::new(u8::MAX), RailgunChain::MAX_CHAIN_ID)
            .unwrap_or_else(|_| panic!("collision chain should still be a valid raw chain"));

        let error = expect_err(
            encode_network_id(ChainScope::Chain(chain)),
            "reserved network id collision should fail",
        );

        assert_eq!(error, NetworkIdError::ReservedNetworkId);
    }

    fn network_id_from_hex(hex: &str) -> NetworkId {
        NetworkId::from_slice(&hex_decode(hex))
            .unwrap_or_else(|_| panic!("test network id should be valid"))
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
