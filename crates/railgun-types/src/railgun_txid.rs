use num_bigint::BigUint;

use crate::{ParseDomainError, validate_bn254_scalar};

/// Canonical fixed input width used by Railgun txid hashing.
pub const RAILGUN_TXID_INPUTS_LENGTH: usize = 13;

/// Typed Railgun transaction identifier derived inside the BN254 scalar field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RailgunTxid(BigUint);

impl RailgunTxid {
    /// Creates a Railgun txid from a field-element integer value.
    ///
    /// # Errors
    ///
    /// Returns an error if `value` is not a valid BN254 scalar field element.
    pub fn new(value: BigUint) -> Result<Self, ParseDomainError> {
        validate_bn254_scalar(&value, "railgun txid must fit within the BN254 scalar field")?;
        Ok(Self(value))
    }

    /// Returns the underlying field-element integer value.
    #[must_use]
    pub const fn value(&self) -> &BigUint {
        &self.0
    }
}

/// Typed 32-byte verification hash used for transaction-chain validation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct VerificationHash([u8; 32]);

impl VerificationHash {
    /// Length of a verification hash in bytes.
    pub const LENGTH: usize = 32;

    /// Creates a verification hash from raw bytes.
    #[must_use]
    pub const fn new(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    /// Creates a verification hash from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns an error if `bytes` is not exactly 32 bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ParseDomainError> {
        let array: [u8; Self::LENGTH] = bytes
            .try_into()
            .map_err(|_| ParseDomainError::new("verification hash must be exactly 32 bytes"))?;
        Ok(Self::new(array))
    }

    /// Returns the raw verification-hash bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;

    use super::{RAILGUN_TXID_INPUTS_LENGTH, RailgunTxid, VerificationHash};
    use crate::{BN254_SCALAR_FIELD_MODULUS_BYTES, ParseDomainError};

    #[test]
    fn railgun_txid_input_length_matches_protocol_constant() {
        assert_eq!(RAILGUN_TXID_INPUTS_LENGTH, 13);
    }

    #[test]
    fn preserves_valid_railgun_txid_value() {
        let value = BigUint::from(42_u8);
        let txid = RailgunTxid::new(value.clone())
            .unwrap_or_else(|error| panic!("valid railgun txid should construct: {error}"));

        assert_eq!(txid.value(), &value);
    }

    #[test]
    fn rejects_out_of_field_railgun_txid_value() {
        let modulus = BigUint::from_bytes_be(&BN254_SCALAR_FIELD_MODULUS_BYTES);
        let Err(error) = RailgunTxid::new(modulus) else {
            panic!("out-of-field railgun txid should fail");
        };

        assert_eq!(
            error,
            ParseDomainError::new("railgun txid must fit within the BN254 scalar field")
        );
    }

    #[test]
    fn verification_hash_round_trips_from_slice() {
        let bytes = [7_u8; VerificationHash::LENGTH];
        let hash = VerificationHash::from_slice(&bytes)
            .unwrap_or_else(|error| panic!("verification hash bytes should parse: {error}"));

        assert_eq!(hash.as_bytes(), &bytes);
    }

    #[test]
    fn verification_hash_rejects_invalid_length() {
        let Err(error) = VerificationHash::from_slice(&[7_u8; 31]) else {
            panic!("invalid verification hash length should fail");
        };

        assert_eq!(error, ParseDomainError::new("verification hash must be exactly 32 bytes"));
    }
}
