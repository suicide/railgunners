//! Shared domain types for the RAILGUN workspace.

use core::fmt;

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
