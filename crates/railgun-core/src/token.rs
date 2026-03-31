//! Canonical token data encoding and token hash derivation.

use num_bigint::BigUint;
use railgun_types::{Address, TokenData, TokenHash, TokenType};
use sha3::{Digest, Keccak256};

const PADDED_TOKEN_FIELD_LENGTH: usize = 32;
const BN254_SCALAR_FIELD_MODULUS_BYTES: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x47,
];

fn bn254_scalar_field_modulus() -> BigUint {
    BigUint::from_bytes_be(&BN254_SCALAR_FIELD_MODULUS_BYTES)
}

fn padded_token_address(address: Address) -> [u8; PADDED_TOKEN_FIELD_LENGTH] {
    let mut padded = [0_u8; PADDED_TOKEN_FIELD_LENGTH];
    padded[(PADDED_TOKEN_FIELD_LENGTH - Address::LENGTH)..].copy_from_slice(address.as_bytes());
    padded
}

fn token_type_bytes(token_type: TokenType) -> [u8; PADDED_TOKEN_FIELD_LENGTH] {
    let mut bytes = [0_u8; PADDED_TOKEN_FIELD_LENGTH];
    bytes[PADDED_TOKEN_FIELD_LENGTH - 1] = token_type.as_u8();
    bytes
}

fn biguint_to_32_bytes(value: &BigUint) -> [u8; PADDED_TOKEN_FIELD_LENGTH] {
    let bytes = value.to_bytes_be();
    let mut padded = [0_u8; PADDED_TOKEN_FIELD_LENGTH];
    let start = PADDED_TOKEN_FIELD_LENGTH - bytes.len();
    padded[start..].copy_from_slice(&bytes);
    padded
}

/// Canonical encoded token data used by note and transaction primitives.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalTokenData {
    token_address: [u8; PADDED_TOKEN_FIELD_LENGTH],
    token_type: TokenType,
    token_sub_id: [u8; PADDED_TOKEN_FIELD_LENGTH],
}

impl CanonicalTokenData {
    /// Returns the canonical 32-byte padded token address.
    #[must_use]
    pub const fn token_address(&self) -> &[u8; PADDED_TOKEN_FIELD_LENGTH] {
        &self.token_address
    }

    /// Returns the stable token type discriminator.
    #[must_use]
    pub const fn token_type(&self) -> TokenType {
        self.token_type
    }

    /// Returns the canonical 32-byte token sub-ID.
    #[must_use]
    pub const fn token_sub_id(&self) -> &[u8; PADDED_TOKEN_FIELD_LENGTH] {
        &self.token_sub_id
    }
}

/// Encodes validated token data into its canonical field layout.
#[must_use]
pub fn encode_token_data(token_data: &TokenData) -> CanonicalTokenData {
    CanonicalTokenData {
        token_address: padded_token_address(token_data.token_address()),
        token_type: token_data.token_type(),
        token_sub_id: *token_data.token_sub_id().as_bytes(),
    }
}

/// Derives the canonical token hash for validated token data.
#[must_use]
pub fn derive_token_hash(token_data: &TokenData) -> TokenHash {
    let encoded = encode_token_data(token_data);

    match encoded.token_type() {
        TokenType::ERC20 => TokenHash::new(*encoded.token_address()),
        TokenType::ERC721 | TokenType::ERC1155 => {
            let digest = Keccak256::new()
                .chain_update(token_type_bytes(encoded.token_type()))
                .chain_update(encoded.token_address())
                .chain_update(encoded.token_sub_id())
                .finalize();
            let reduced = BigUint::from_bytes_be(&digest) % bn254_scalar_field_modulus();
            TokenHash::new(biguint_to_32_bytes(&reduced))
        }
    }
}

#[cfg(test)]
mod tests {
    use railgun_types::{Address, TokenData, TokenSubId, TokenType};

    use super::{CanonicalTokenData, derive_token_hash, encode_token_data};

    fn decode_hex<const N: usize>(value: &str) -> [u8; N] {
        let trimmed = value.strip_prefix("0x").unwrap_or(value);
        assert_eq!(trimmed.len(), N * 2, "hex input has unexpected length");

        let mut bytes = [0_u8; N];
        for (index, chunk) in trimmed.as_bytes().chunks_exact(2).enumerate() {
            let high = (chunk[0] as char)
                .to_digit(16)
                .unwrap_or_else(|| panic!("invalid hex nibble at index {}", index * 2));
            let low = (chunk[1] as char)
                .to_digit(16)
                .unwrap_or_else(|| panic!("invalid hex nibble at index {}", index * 2 + 1));
            bytes[index] = ((high << 4) | low) as u8;
        }
        bytes
    }

    fn address(value: &str) -> Address {
        Address::from_slice(&decode_hex::<20>(value)).unwrap_or_else(|error| {
            panic!("expected valid address bytes: {error}");
        })
    }

    fn token_sub_id(value: &str) -> TokenSubId {
        TokenSubId::from_slice(&decode_hex::<32>(value)).unwrap_or_else(|error| {
            panic!("expected valid token sub id bytes: {error}");
        })
    }

    fn assert_canonical_token_data(
        encoded: CanonicalTokenData,
        token_address: &str,
        token_type: TokenType,
        token_sub_id: &str,
    ) {
        assert_eq!(encoded.token_address(), &decode_hex::<32>(token_address));
        assert_eq!(encoded.token_type(), token_type);
        assert_eq!(encoded.token_sub_id(), &decode_hex::<32>(token_sub_id));
    }

    #[test]
    fn encodes_erc20_token_data_shape() {
        let token_data = TokenData::erc20(address("0x9fe46736679d2d9a65f0992f2272de9f3c7fa6e0"));

        assert_canonical_token_data(
            encode_token_data(&token_data),
            "0000000000000000000000009fe46736679d2d9a65f0992f2272de9f3c7fa6e0",
            TokenType::ERC20,
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
    }

    #[test]
    fn derives_erc20_token_hash_from_padded_address() {
        let token_data = TokenData::erc20(address("0x7f4925cdf66ddf5b88016df1fe915e68eff8f192"));

        assert_eq!(
            derive_token_hash(&token_data).as_bytes(),
            &decode_hex::<32>("0000000000000000000000007f4925cdf66ddf5b88016df1fe915e68eff8f192")
        );
    }

    #[test]
    fn nft_token_hash_depends_on_token_type() {
        let erc721 = TokenData::new(
            address("0x1234567890123456789012345678901234567890"),
            TokenType::ERC721,
            token_sub_id("0000000000000000000000000000000000000000000000000000000000000001"),
        )
        .unwrap_or_else(|error| panic!("expected valid token data: {error}"));
        let erc1155 = TokenData::new(
            address("0x1234567890123456789012345678901234567890"),
            TokenType::ERC1155,
            token_sub_id("0000000000000000000000000000000000000000000000000000000000000001"),
        )
        .unwrap_or_else(|error| panic!("expected valid token data: {error}"));

        let erc721_hash = derive_token_hash(&erc721);
        let erc1155_hash = derive_token_hash(&erc1155);

        assert_ne!(erc721_hash, erc1155_hash);
        assert_ne!(erc721_hash.as_bytes(), encode_token_data(&erc721).token_address());
    }

    #[test]
    fn nft_token_hash_depends_on_token_sub_id() {
        let token_data_one = TokenData::new(
            address("0x1234567890123456789012345678901234567890"),
            TokenType::ERC721,
            token_sub_id("0000000000000000000000000000000000000000000000000000000000000001"),
        )
        .unwrap_or_else(|error| panic!("expected valid token data: {error}"));
        let token_data_two = TokenData::new(
            address("0x1234567890123456789012345678901234567890"),
            TokenType::ERC721,
            token_sub_id("0000000000000000000000000000000000000000000000000000000000000002"),
        )
        .unwrap_or_else(|error| panic!("expected valid token data: {error}"));

        assert_ne!(derive_token_hash(&token_data_one), derive_token_hash(&token_data_two));
    }
}
