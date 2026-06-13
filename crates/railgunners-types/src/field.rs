use std::sync::OnceLock;

use num_bigint::BigUint;

use crate::ParseDomainError;

/// Canonical BN254 scalar-field modulus encoded as 32 big-endian bytes.
///
/// This is the same field boundary the upstream RAILGUN codebase refers to as
/// `SNARK_PRIME`.
/// Decimal:
/// `21888242871839275222246405745257275088548364400416034343698204186575808495617`
pub const BN254_SCALAR_FIELD_MODULUS_BYTES: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

static BN254_SCALAR_FIELD_MODULUS: OnceLock<BigUint> = OnceLock::new();

/// Returns a clone of the canonical BN254 scalar-field modulus.
#[must_use]
pub fn bn254_scalar_field_modulus() -> BigUint {
    BN254_SCALAR_FIELD_MODULUS
        .get_or_init(|| BigUint::from_bytes_be(&BN254_SCALAR_FIELD_MODULUS_BYTES))
        .clone()
}

pub(crate) fn validate_bn254_scalar(
    value: &BigUint,
    label: &'static str,
) -> Result<(), ParseDomainError> {
    if *value < bn254_scalar_field_modulus() { Ok(()) } else { Err(ParseDomainError::new(label)) }
}

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;

    use super::BN254_SCALAR_FIELD_MODULUS_BYTES;

    const BN254_SCALAR_FIELD_MODULUS_DECIMAL: &str =
        "21888242871839275222246405745257275088548364400416034343698204186575808495617";

    #[test]
    fn bn254_scalar_field_modulus_decimal_matches_bytes() {
        let parsed = BigUint::parse_bytes(BN254_SCALAR_FIELD_MODULUS_DECIMAL.as_bytes(), 10)
            .unwrap_or_else(|| panic!("bn254 scalar modulus decimal should parse"));

        assert_eq!(parsed.to_bytes_be(), BN254_SCALAR_FIELD_MODULUS_BYTES);
    }
}
