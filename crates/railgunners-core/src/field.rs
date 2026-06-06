//! Shared field-element parsing helpers.

use num_bigint::BigUint;

use crate::{RailgunError, crypto::poseidon};

/// Parses canonical 32-byte BN254 scalar field bytes into a field integer.
///
/// # Errors
///
/// Returns an error when `bytes` do not encode a canonical BN254 scalar field
/// element.
pub fn parse_canonical_field_bytes(bytes: &[u8; 32]) -> Result<BigUint, RailgunError> {
    poseidon::field_from_canonical_bytes(bytes)
        .map(poseidon::field_to_biguint)
        .map_err(|_| RailgunError::InvalidInput("bytes must encode a canonical BN254 scalar"))
}

#[cfg(test)]
mod tests {
    use railgunners_types::BN254_SCALAR_FIELD_MODULUS_BYTES;

    use crate::RailgunError;

    use super::parse_canonical_field_bytes;

    #[test]
    fn parses_canonical_zero_field_bytes() {
        let value = parse_canonical_field_bytes(&[0_u8; 32])
            .unwrap_or_else(|error| panic!("zero field bytes should parse: {error}"));

        assert_eq!(value, 0_u8.into());
    }

    #[test]
    fn rejects_non_canonical_field_bytes() {
        let error = parse_canonical_field_bytes(&BN254_SCALAR_FIELD_MODULUS_BYTES);
        let Err(error) = error else {
            panic!("field modulus bytes should be rejected as non-canonical");
        };

        assert_eq!(error, RailgunError::InvalidInput("bytes must encode a canonical BN254 scalar"));
    }
}
