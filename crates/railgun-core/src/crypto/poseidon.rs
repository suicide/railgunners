use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonHasher};
use num_bigint::BigUint;

use super::CryptoError;

pub(crate) fn field_from_biguint(value: &BigUint) -> Result<Fr, CryptoError> {
    let bytes = value.to_bytes_be();
    let field = Fr::from_be_bytes_mod_order(&bytes);
    let roundtrip = BigUint::from_bytes_be(&field.into_bigint().to_bytes_be());

    if roundtrip == *value { Ok(field) } else { Err(CryptoError::InvalidFieldElement) }
}

pub(crate) fn field_from_canonical_bytes(bytes: &[u8; 32]) -> Result<Fr, CryptoError> {
    let value = BigUint::from_bytes_be(bytes);
    let field = Fr::from_be_bytes_mod_order(bytes);
    let roundtrip = BigUint::from_bytes_be(&field.into_bigint().to_bytes_be());

    if roundtrip == value { Ok(field) } else { Err(CryptoError::InvalidFieldElement) }
}

pub(crate) fn field_from_bytes_mod_order(bytes: &[u8]) -> Fr {
    Fr::from_be_bytes_mod_order(bytes)
}

pub(crate) fn field_to_biguint(field: Fr) -> BigUint {
    BigUint::from_bytes_be(&field.into_bigint().to_bytes_be())
}

pub(crate) fn field_to_canonical_bytes(field: Fr) -> [u8; 32] {
    let bytes = field.into_bigint().to_bytes_be();
    let mut padded = [0_u8; 32];
    let start = 32 - bytes.len();
    padded[start..].copy_from_slice(&bytes);
    padded
}

pub(crate) fn hash_fields(inputs: &[Fr]) -> Result<Fr, CryptoError> {
    let mut poseidon =
        Poseidon::<Fr>::new_circom(inputs.len()).map_err(|_| CryptoError::DerivationFailure)?;
    poseidon.hash(inputs).map_err(|_| CryptoError::DerivationFailure)
}

#[cfg(test)]
mod tests {
    use super::{field_from_biguint, hash_fields};
    use num_bigint::BigUint;

    #[test]
    fn poseidon_hash_rejects_unsupported_thirteen_input_backend() {
        let inputs = (1_u8..=13)
            .map(BigUint::from)
            .map(|value| {
                field_from_biguint(&value)
                    .unwrap_or_else(|_| panic!("small test field element should validate"))
            })
            .collect::<Vec<_>>();

        assert!(hash_fields(&inputs).is_err(), "current backend should reject unsupported arity");
    }
}
