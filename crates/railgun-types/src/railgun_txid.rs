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

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;

    use super::{RAILGUN_TXID_INPUTS_LENGTH, RailgunTxid};
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
}
