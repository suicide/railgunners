use babyjubjub_rs::{
    Fr as BabyJubJubField, Point, PrivateKey as BabyJubJubPrivateKey, decompress_point,
};
use ff::{PrimeField as _, PrimeFieldRepr as _};
use num_bigint::BigUint;
use railgun_types::{PackedSpendingPublicKey, SpendingPrivateKey, SpendingPublicKey};

use super::CryptoError;

fn parse_coordinate(value: &BabyJubJubField) -> Result<BigUint, CryptoError> {
    let repr = value.into_repr();
    let mut bytes = Vec::with_capacity(core::mem::size_of_val(repr.as_ref()));
    repr.write_be(&mut bytes).map_err(|_| CryptoError::DerivationFailure)?;
    Ok(BigUint::from_bytes_be(&bytes))
}

fn biguint_to_babyjubjub_field(value: &BigUint) -> Result<BabyJubJubField, CryptoError> {
    let field = BabyJubJubField::from_str(&value.to_string())
        .ok_or(CryptoError::InvalidSpendingPublicKey)?;
    let roundtrip = parse_coordinate(&field)?;

    if roundtrip == *value { Ok(field) } else { Err(CryptoError::InvalidSpendingPublicKey) }
}

pub(crate) fn derive_spending_public_key(
    private_key: &SpendingPrivateKey,
) -> Result<SpendingPublicKey, CryptoError> {
    let private_key = BabyJubJubPrivateKey::import(private_key.as_bytes().to_vec())
        .map_err(|_| CryptoError::DerivationFailure)?;
    let public_key = private_key.public();
    let x = parse_coordinate(&public_key.x)?;
    let y = parse_coordinate(&public_key.y)?;
    SpendingPublicKey::new(x, y).map_err(|_| CryptoError::DerivationFailure)
}

pub(crate) fn validate_spending_public_key(
    spending_public_key: &SpendingPublicKey,
) -> Result<(), CryptoError> {
    let point = Point {
        x: biguint_to_babyjubjub_field(spending_public_key.x())?,
        y: biguint_to_babyjubjub_field(spending_public_key.y())?,
    };
    let decompressed =
        decompress_point(point.compress()).map_err(|_| CryptoError::InvalidSpendingPublicKey)?;

    if decompressed.x == point.x && decompressed.y == point.y {
        Ok(())
    } else {
        Err(CryptoError::InvalidSpendingPublicKey)
    }
}

pub(crate) fn pack_spending_public_key(
    spending_public_key: &SpendingPublicKey,
) -> Result<PackedSpendingPublicKey, CryptoError> {
    validate_spending_public_key(spending_public_key)?;
    let point = Point {
        x: biguint_to_babyjubjub_field(spending_public_key.x())?,
        y: biguint_to_babyjubjub_field(spending_public_key.y())?,
    };

    Ok(PackedSpendingPublicKey::new(point.compress()))
}

pub(crate) fn unpack_spending_public_key(
    packed_spending_public_key: &PackedSpendingPublicKey,
) -> Result<SpendingPublicKey, CryptoError> {
    let point = decompress_point(*packed_spending_public_key.as_bytes())
        .map_err(|_| CryptoError::InvalidPackedSpendingPublicKey)?;
    let public_key =
        SpendingPublicKey::new(parse_coordinate(&point.x)?, parse_coordinate(&point.y)?)
            .map_err(|_| CryptoError::InvalidPackedSpendingPublicKey)?;
    validate_spending_public_key(&public_key)
        .map_err(|_| CryptoError::InvalidPackedSpendingPublicKey)?;
    Ok(public_key)
}
