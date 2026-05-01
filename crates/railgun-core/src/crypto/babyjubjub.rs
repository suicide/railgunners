use ark_bn254::Fr;
use ark_ff::{BigInteger, Field, PrimeField};
use blake_hash::Digest;
use num_bigint::BigUint;
use railgun_types::{
    PackedSpendingPublicKey, SpendingPrivateKey, SpendingPublicKey, bn254_scalar_field_modulus,
};
use std::sync::OnceLock;

use super::CryptoError;

const COMPRESSED_POINT_LENGTH: usize = 32;

// circomlib-compatible BabyJubJub generator coordinates:
// https://github.com/iden3/circomlibjs/blob/main/src/babyjub.js#L14-L18
// OpenZeppelin independently validates that `Base8 = 8 * Generator`:
// https://github.com/OpenZeppelin/rust-contracts-stylus/blob/main/lib/crypto/src/curve/te/instance/baby_jubjub.rs#L137-L151
#[cfg(test)]
const GENERATOR_X: &str =
    "995203441582195749578291179787384436505546430278305826713579947235728471134";
#[cfg(test)]
const GENERATOR_Y: &str =
    "5472060717959818805561601436314318772137091100104008585924551046643952123905";

// circomlib-compatible BabyJubJub Base8 coordinates:
// https://github.com/iden3/circomlibjs/blob/main/src/babyjub.js#L19-L24
// Kohaku uses the same constants in upstream Rust:
// https://github.com/ethereum/kohaku/blob/master/crates/crypto/src/babyjubjub.rs#L11-L16
const B8_X: &str = "5299619240641551281634865583518297030282874472190772894086521144482721001553";
const B8_Y: &str = "16950150798460657717958625567821834550301663161624707787222815936182638968203";

// circomlib-compatible BabyJubJub subgroup order:
// https://github.com/iden3/circomlibjs/blob/main/src/babyjub.js#L23-L24
// OpenZeppelin validates Base8 order against the same value:
// https://github.com/OpenZeppelin/rust-contracts-stylus/blob/main/lib/crypto/src/curve/te/instance/baby_jubjub.rs#L153-L167
#[cfg(test)]
const SUBGROUP_ORDER: &str =
    "2736030358979909402780800718157159386076813972158567259200215660948447373041";

static D_CONSTANT: OnceLock<Fr> = OnceLock::new();
static A_CONSTANT: OnceLock<Fr> = OnceLock::new();

fn field_constant(value: &str) -> Fr {
    Fr::from_be_bytes_mod_order(
        &BigUint::parse_bytes(value.as_bytes(), 10)
            .unwrap_or_else(|| panic!("babyjubjub constant should parse"))
            .to_bytes_be(),
    )
}

fn half_modulus() -> BigUint {
    bn254_scalar_field_modulus() >> 1
}

fn field_to_biguint(value: Fr) -> BigUint {
    BigUint::from_bytes_be(&value.into_bigint().to_bytes_be())
}

fn biguint_to_field(value: &BigUint) -> Result<Fr, CryptoError> {
    let bytes = value.to_bytes_be();
    let field = Fr::from_be_bytes_mod_order(&bytes);

    if field_to_biguint(field) == *value {
        Ok(field)
    } else {
        Err(CryptoError::InvalidSpendingPublicKey)
    }
}

// circomlib-compatible BabyJubJub twisted Edwards `d` coefficient in the
// equation `a*x^2 + y^2 = 1 + d*x^2*y^2`:
// https://github.com/iden3/circomlibjs/blob/main/src/babyjub.js#L23-L26
// OpenZeppelin uses the same value as `COEFF_D`:
// https://github.com/OpenZeppelin/rust-contracts-stylus/blob/main/lib/crypto/src/curve/te/instance/baby_jubjub.rs#L65-L76
fn d_constant() -> Fr {
    *D_CONSTANT.get_or_init(|| field_constant("168696"))
}

// circomlib-compatible BabyJubJub twisted Edwards `a` coefficient in the
// equation `a*x^2 + y^2 = 1 + d*x^2*y^2`:
// https://github.com/iden3/circomlibjs/blob/main/src/babyjub.js#L23-L26
// OpenZeppelin uses the same value as `COEFF_A`:
// https://github.com/OpenZeppelin/rust-contracts-stylus/blob/main/lib/crypto/src/curve/te/instance/baby_jubjub.rs#L65-L76
fn a_constant() -> Fr {
    *A_CONSTANT.get_or_init(|| field_constant("168700"))
}

#[cfg(test)]
fn generator_point() -> Point {
    Point { x: field_constant(GENERATOR_X), y: field_constant(GENERATOR_Y) }
}

fn b8_point() -> Point {
    // P6: If key-derivation profiling shows this matters, cache Base8 as well.
    Point { x: field_constant(B8_X), y: field_constant(B8_Y) }
}

fn scalar_from_private_key(private_key: &SpendingPrivateKey) -> BigUint {
    let hash = blake_hash::Blake512::digest(private_key.as_bytes());
    let mut h = hash[..COMPRESSED_POINT_LENGTH].to_vec();

    h[0] &= 0xF8;
    h[COMPRESSED_POINT_LENGTH - 1] &= 0x7F;
    h[COMPRESSED_POINT_LENGTH - 1] |= 0x40;

    BigUint::from_bytes_le(&h) >> 3
}

fn test_bit(bytes: &[u8], index: usize) -> bool {
    (bytes[index / 8] & (1 << (index % 8))) != 0
}

fn is_on_curve(point: Point) -> bool {
    let x_squared = point.x.square();
    let y_squared = point.y.square();
    let lhs = (a_constant() * x_squared) + y_squared;
    let rhs = Fr::ONE + (d_constant() * x_squared * y_squared);

    lhs == rhs
}

#[cfg(test)]
fn is_identity(point: Point) -> bool {
    point.x == Fr::from(0_u8) && point.y == Fr::ONE
}

#[derive(Clone, Copy)]
struct PointProjective {
    x: Fr,
    y: Fr,
    z: Fr,
}

impl PointProjective {
    fn affine(self) -> Point {
        if self.z == Fr::from(0_u8) {
            return Point { x: Fr::from(0_u8), y: Fr::from(0_u8) };
        }

        let z_inverse =
            self.z.inverse().unwrap_or_else(|| panic!("non-zero projective z should invert"));
        Point { x: self.x * z_inverse, y: self.y * z_inverse }
    }

    fn add(self, other: Self) -> Self {
        let z_product = self.z * other.z;
        let z_product_squared = z_product.square();
        let x_product = self.x * other.x;
        let y_product = self.y * other.y;
        let d_term = d_constant() * x_product * y_product;
        let left_factor = z_product_squared - d_term;
        let right_factor = z_product_squared + d_term;
        let mixed_sum = ((self.x + self.y) * (other.x + other.y)) - x_product - y_product;
        let x = z_product * left_factor * mixed_sum;
        let y = z_product * right_factor * (y_product - (a_constant() * x_product));
        let z = left_factor * right_factor;

        Self { x, y, z }
    }
}

#[derive(Clone, Copy)]
struct Point {
    x: Fr,
    y: Fr,
}

impl Point {
    fn projective(self) -> PointProjective {
        PointProjective { x: self.x, y: self.y, z: Fr::ONE }
    }

    fn mul_scalar(self, scalar: &BigUint) -> Self {
        let mut result = PointProjective { x: Fr::from(0_u8), y: Fr::ONE, z: Fr::ONE };
        let mut accumulator = self.projective();
        let bytes = scalar.to_bytes_le();
        let bit_count =
            usize::try_from(scalar.bits()).unwrap_or_else(|_| panic!("bit count should fit usize"));

        for index in 0..bit_count {
            if test_bit(&bytes, index) {
                result = result.add(accumulator);
            }
            accumulator = accumulator.add(accumulator);
        }

        result.affine()
    }
}

fn point_from_spending_public_key(
    spending_public_key: &SpendingPublicKey,
) -> Result<Point, CryptoError> {
    let point = Point {
        x: biguint_to_field(spending_public_key.x())?,
        y: biguint_to_field(spending_public_key.y())?,
    };

    if is_on_curve(point) { Ok(point) } else { Err(CryptoError::InvalidSpendingPublicKey) }
}

fn compress_point(point: Point) -> PackedSpendingPublicKey {
    let mut compressed = [0_u8; COMPRESSED_POINT_LENGTH];
    let y_bytes = field_to_biguint(point.y).to_bytes_le();
    let len = y_bytes.len().min(compressed.len());
    compressed[..len].copy_from_slice(&y_bytes[..len]);

    if field_to_biguint(point.x) > half_modulus() {
        compressed[COMPRESSED_POINT_LENGTH - 1] |= 0x80;
    }

    PackedSpendingPublicKey::new(compressed)
}

fn decompress_point(bytes: &[u8; COMPRESSED_POINT_LENGTH]) -> Result<Point, CryptoError> {
    let mut y_bytes = *bytes;
    let negative = (y_bytes[COMPRESSED_POINT_LENGTH - 1] & 0x80) != 0;
    y_bytes[COMPRESSED_POINT_LENGTH - 1] &= 0x7F;

    let y = BigUint::from_bytes_le(&y_bytes);
    if y >= bn254_scalar_field_modulus() {
        return Err(CryptoError::InvalidPackedSpendingPublicKey);
    }

    let y_field = Fr::from_le_bytes_mod_order(&y_bytes);
    let y_squared = y_field.square();
    let numerator = Fr::ONE - y_squared;
    let denominator = a_constant() - (d_constant() * y_squared);
    let x_squared =
        denominator.inverse().ok_or(CryptoError::InvalidPackedSpendingPublicKey)? * numerator;
    let mut x_field = x_squared.sqrt().ok_or(CryptoError::InvalidPackedSpendingPublicKey)?;

    if negative != (field_to_biguint(x_field) > half_modulus()) {
        x_field = -x_field;
    }

    let point = Point { x: x_field, y: y_field };

    if is_on_curve(point) { Ok(point) } else { Err(CryptoError::InvalidPackedSpendingPublicKey) }
}

pub(crate) fn derive_spending_public_key(
    private_key: &SpendingPrivateKey,
) -> Result<SpendingPublicKey, CryptoError> {
    let public_key = b8_point().mul_scalar(&scalar_from_private_key(private_key));

    SpendingPublicKey::new(field_to_biguint(public_key.x), field_to_biguint(public_key.y))
        .map_err(|_| CryptoError::DerivationFailure)
}

pub(crate) fn validate_spending_public_key(
    spending_public_key: &SpendingPublicKey,
) -> Result<(), CryptoError> {
    let point = point_from_spending_public_key(spending_public_key)?;
    let decompressed = decompress_point(pack_spending_public_key(spending_public_key)?.as_bytes())
        .map_err(|_| CryptoError::InvalidSpendingPublicKey)?;

    if decompressed.x == point.x && decompressed.y == point.y {
        Ok(())
    } else {
        Err(CryptoError::InvalidSpendingPublicKey)
    }
}

pub(crate) fn pack_spending_public_key(
    spending_public_key: &SpendingPublicKey,
) -> Result<PackedSpendingPublicKey, CryptoError> {
    let point = point_from_spending_public_key(spending_public_key)?;
    let packed = compress_point(point);
    let unpacked = unpack_spending_public_key(&packed)?;

    if unpacked == *spending_public_key {
        Ok(packed)
    } else {
        Err(CryptoError::InvalidSpendingPublicKey)
    }
}

pub(crate) fn unpack_spending_public_key(
    packed_spending_public_key: &PackedSpendingPublicKey,
) -> Result<SpendingPublicKey, CryptoError> {
    let point = decompress_point(packed_spending_public_key.as_bytes())?;

    SpendingPublicKey::new(field_to_biguint(point.x), field_to_biguint(point.y))
        .map_err(|_| CryptoError::InvalidPackedSpendingPublicKey)
}

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;
    use railgun_types::{PackedSpendingPublicKey, SpendingPrivateKey};

    use super::{
        SUBGROUP_ORDER, a_constant, b8_point, compress_point, d_constant, decompress_point,
        derive_spending_public_key, field_to_biguint, generator_point, is_identity, is_on_curve,
        pack_spending_public_key, unpack_spending_public_key,
    };

    #[test]
    fn base8_point_is_on_curve() {
        assert!(is_on_curve(b8_point()));
    }

    #[test]
    fn generator_point_is_on_curve() {
        assert!(is_on_curve(generator_point()));
    }

    #[test]
    fn base8_matches_generator_times_eight() {
        let generator_times_eight = generator_point().mul_scalar(&8_u8.into());

        assert_eq!(generator_times_eight.x, b8_point().x);
        assert_eq!(generator_times_eight.y, b8_point().y);
    }

    #[test]
    fn base8_has_expected_subgroup_order() {
        let subgroup_order = BigUint::parse_bytes(SUBGROUP_ORDER.as_bytes(), 10)
            .unwrap_or_else(|| panic!("subgroup order should parse"));
        let result = b8_point().mul_scalar(&subgroup_order);

        assert!(is_identity(result));
    }

    #[test]
    fn a_and_d_match_canonical_source_values() {
        let expected_a =
            BigUint::parse_bytes(b"168700", 10).unwrap_or_else(|| panic!("a should parse"));
        let expected_d =
            BigUint::parse_bytes(b"168696", 10).unwrap_or_else(|| panic!("d should parse"));

        assert_eq!(field_to_biguint(a_constant()), expected_a);
        assert_eq!(field_to_biguint(d_constant()), expected_d);
    }

    #[test]
    fn derives_issue_vector_public_key() {
        let private_key = SpendingPrivateKey::new(hex_array::<32>(
            "67d7d19d00e6e3b3517fe68ac46505dd207df6e8fe3aa06ba3face352e7599ef",
        ));
        let public_key = derive_spending_public_key(&private_key)
            .unwrap_or_else(|_| panic!("spending public key derivation should succeed"));

        assert_eq!(
            public_key.x().to_string(),
            "1700559105542139805112168139351320601853033442476682590258553412078471731431"
        );
        assert_eq!(
            public_key.y().to_string(),
            "20772987336827599306927277921643441679141423747083423413320022373456048866305"
        );
    }

    #[test]
    fn rejects_invalid_packed_point() {
        let invalid = PackedSpendingPublicKey::new([0xFF_u8; 32]);
        assert!(unpack_spending_public_key(&invalid).is_err());
    }

    #[test]
    fn round_trips_packed_public_key() {
        let private_key = SpendingPrivateKey::new(hex_array::<32>(
            "3428cfc939320328501174a4e76e869197ffc894b58dbf4d0e953c484d66cb5e",
        ));
        let public_key = derive_spending_public_key(&private_key)
            .unwrap_or_else(|_| panic!("spending public key derivation should succeed"));
        let packed = pack_spending_public_key(&public_key)
            .unwrap_or_else(|_| panic!("packed spending public key should succeed"));
        let unpacked = unpack_spending_public_key(&packed)
            .unwrap_or_else(|_| panic!("unpacked spending public key should succeed"));

        assert_eq!(unpacked, public_key);
    }

    #[test]
    fn round_trips_negative_x_point() {
        let mut negative = generator_point();
        negative.x = -negative.x;

        assert!(is_on_curve(negative));

        let packed = compress_point(negative);
        let unpacked = decompress_point(packed.as_bytes())
            .unwrap_or_else(|_| panic!("negative-x point should unpack successfully"));

        assert_eq!(unpacked.x, negative.x);
        assert_eq!(unpacked.y, negative.y);
    }

    fn hex_array<const N: usize>(value: &str) -> [u8; N] {
        let bytes = hex_decode(value);
        let mut array = [0_u8; N];
        array.copy_from_slice(&bytes);
        array
    }

    fn hex_decode(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0, "hex input must be even-length");
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|chunk| {
                let text = core::str::from_utf8(chunk)
                    .unwrap_or_else(|_| panic!("test hex should be utf-8"));
                u8::from_str_radix(text, 16).unwrap_or_else(|_| panic!("test hex should be valid"))
            })
            .collect()
    }
}
