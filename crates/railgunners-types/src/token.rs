use core::fmt;

use sha3::{Digest, Keccak256};

use crate::ParseDomainError;

fn decode_hex_nibble(value: u8) -> Result<u8, ParseDomainError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(ParseDomainError::new("address must be valid hex")),
    }
}

fn encode_lower_hex(bytes: &[u8]) -> [u8; Address::LENGTH * 2] {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut encoded = [0_u8; Address::LENGTH * 2];
    for (index, byte) in bytes.iter().copied().enumerate() {
        encoded[index * 2] = HEX[usize::from(byte >> 4)];
        encoded[index * 2 + 1] = HEX[usize::from(byte & 0x0f)];
    }
    encoded
}

fn checksum_encoded_address(address: &Address) -> [u8; Address::LENGTH * 2] {
    let lowercase = encode_lower_hex(address.as_bytes());
    let hash = Keccak256::digest(lowercase);
    let mut encoded = lowercase;

    for (index, byte) in encoded.iter_mut().enumerate() {
        if byte.is_ascii_hexdigit() && byte.is_ascii_lowercase() {
            let nibble = if index % 2 == 0 { hash[index / 2] >> 4 } else { hash[index / 2] & 0x0f };
            if nibble >= 8 {
                *byte = byte.to_ascii_uppercase();
            }
        }
    }

    encoded
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

    /// Parses an EVM address from a `0x`-prefixed hex string.
    ///
    /// Parsing is case-insensitive. Serialization remains canonical EIP-55.
    ///
    /// # Errors
    ///
    /// Returns an error if `value` is not a `0x`-prefixed 20-byte hex string.
    pub fn parse(value: &str) -> Result<Self, ParseDomainError> {
        let trimmed =
            value.strip_prefix("0x").ok_or(ParseDomainError::new("address must start with 0x"))?;
        if trimmed.len() != Self::LENGTH * 2 {
            return Err(ParseDomainError::new("address must be exactly 20 bytes"));
        }

        let bytes = trimmed.as_bytes();
        let mut decoded = [0_u8; Self::LENGTH];
        for index in 0..Self::LENGTH {
            let high = decode_hex_nibble(bytes[index * 2])?;
            let low = decode_hex_nibble(bytes[index * 2 + 1])?;
            decoded[index] = (high << 4) | low;
        }

        Ok(Self::new(decoded))
    }

    /// Returns the raw address bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }

    /// Returns the canonical EIP-55 checksum string.
    #[must_use]
    pub fn to_checksum_string(&self) -> String {
        let encoded = checksum_encoded_address(self);
        let mut output = String::with_capacity(2 + encoded.len());
        output.push_str("0x");
        for byte in encoded {
            output.push(char::from(byte));
        }
        output
    }
}

impl fmt::Display for Address {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_checksum_string())
    }
}

impl TryFrom<&str> for Address {
    type Error = ParseDomainError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl TryFrom<String> for Address {
    type Error = ParseDomainError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
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
    address: Address,
    kind: TokenType,
    sub_id: TokenSubId,
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

        Ok(Self { address: token_address, kind: token_type, sub_id: token_sub_id })
    }

    /// Creates canonical ERC20 token data with the required zero sub-ID.
    #[must_use]
    pub const fn erc20(token_address: Address) -> Self {
        Self { address: token_address, kind: TokenType::ERC20, sub_id: TokenSubId::zero() }
    }

    /// Returns the semantic token address.
    #[must_use]
    pub const fn token_address(&self) -> Address {
        self.address
    }

    /// Returns the token type discriminator.
    #[must_use]
    pub const fn token_type(&self) -> TokenType {
        self.kind
    }

    /// Returns the canonical 32-byte token sub-ID.
    #[must_use]
    pub const fn token_sub_id(&self) -> &TokenSubId {
        &self.sub_id
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
    use super::{Address, ParseDomainError, TokenData, TokenSubId, TokenType};

    #[test]
    fn parses_lowercase_address_and_serializes_to_checksum() {
        let address = Address::parse("0xac9f360ae85469b27aeddeafc579ef2d052ad405")
            .unwrap_or_else(|error| panic!("address should parse: {error}"));

        assert_eq!(address.to_string(), "0xAc9f360Ae85469B27aEDdEaFC579Ef2d052aD405");
    }

    #[test]
    fn parses_checksum_address() {
        let address = Address::parse("0xAc9f360Ae85469B27aEDdEaFC579Ef2d052aD405")
            .unwrap_or_else(|error| panic!("address should parse: {error}"));

        assert_eq!(address.to_string(), "0xAc9f360Ae85469B27aEDdEaFC579Ef2d052aD405");
    }

    #[test]
    fn rejects_invalid_address_length() {
        let Err(error) = Address::from_slice(&[7_u8; 19]) else {
            panic!("invalid address length should fail");
        };

        assert_eq!(error, ParseDomainError::new("address must be exactly 20 bytes"));
    }

    #[test]
    fn rejects_address_without_prefix() {
        let Err(error) = Address::parse("ac9f360ae85469b27aeddeafc579ef2d052ad405") else {
            panic!("missing 0x prefix should fail");
        };

        assert_eq!(error, ParseDomainError::new("address must start with 0x"));
    }

    #[test]
    fn rejects_invalid_address_hex() {
        let Err(error) = Address::parse("0xzz9f360ae85469b27aeddeafc579ef2d052ad405") else {
            panic!("invalid hex should fail");
        };

        assert_eq!(error, ParseDomainError::new("address must be valid hex"));
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
