use babyjubjub_rs::{Fr as BabyJubJubField, Point, decompress_point};
use ff::{PrimeField as _, PrimeFieldRepr as _};
use num_bigint::BigUint;

use crate::{ParseDomainError, validate_bn254_scalar};

fn biguint_to_babyjubjub_field(value: &BigUint) -> Result<BabyJubJubField, ParseDomainError> {
    let field = BabyJubJubField::from_str(&value.to_string()).ok_or(ParseDomainError::new(
        "spending public key coordinates must fit within the BabyJubJub field",
    ))?;
    let repr = field.into_repr();
    let mut bytes = Vec::with_capacity(core::mem::size_of_val(repr.as_ref()));
    repr.write_be(&mut bytes).map_err(|_| {
        ParseDomainError::new(
            "spending public key coordinates must fit within the BabyJubJub field",
        )
    })?;
    if BigUint::from_bytes_be(&bytes) == *value {
        Ok(field)
    } else {
        Err(ParseDomainError::new(
            "spending public key coordinates must fit within the BabyJubJub field",
        ))
    }
}

/// Typed 32-byte Railgun spending private key.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SpendingPrivateKey([u8; 32]);

impl SpendingPrivateKey {
    /// Length of a spending private key in bytes.
    pub const LENGTH: usize = 32;

    /// Creates a spending private key from raw bytes.
    #[must_use]
    pub const fn new(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    /// Creates a spending private key from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns an error if `bytes` is not exactly 32 bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ParseDomainError> {
        let array: [u8; Self::LENGTH] = bytes
            .try_into()
            .map_err(|_| ParseDomainError::new("spending private key must be exactly 32 bytes"))?;
        Ok(Self::new(array))
    }

    /// Returns the raw private-key bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}

/// Typed `BabyJubJub` spending public key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpendingPublicKey {
    x: BigUint,
    y: BigUint,
}

impl SpendingPublicKey {
    /// Creates a spending public key from `BabyJubJub` coordinates.
    ///
    /// # Errors
    ///
    /// Returns an error if either coordinate is outside the `BabyJubJub` field or
    /// if the coordinates do not represent a valid compressible `BabyJubJub` point.
    pub fn new(x: BigUint, y: BigUint) -> Result<Self, ParseDomainError> {
        let point =
            Point { x: biguint_to_babyjubjub_field(&x)?, y: biguint_to_babyjubjub_field(&y)? };
        let compressed = point.compress();
        let decompressed = decompress_point(compressed).map_err(|_| {
            ParseDomainError::new(
                "spending public key coordinates must form a valid BabyJubJub point",
            )
        })?;
        if decompressed.x == point.x && decompressed.y == point.y {
            Ok(Self { x, y })
        } else {
            Err(ParseDomainError::new(
                "spending public key coordinates must form a valid BabyJubJub point",
            ))
        }
    }

    /// Returns the x coordinate.
    #[must_use]
    pub const fn x(&self) -> &BigUint {
        &self.x
    }

    /// Returns the y coordinate.
    #[must_use]
    pub const fn y(&self) -> &BigUint {
        &self.y
    }
}

/// Typed Railgun spending keypair.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpendingKeyPair {
    private_key: SpendingPrivateKey,
    public_key: SpendingPublicKey,
}

impl SpendingKeyPair {
    /// Creates a spending keypair from explicit components.
    #[must_use]
    pub const fn new(private_key: SpendingPrivateKey, public_key: SpendingPublicKey) -> Self {
        Self { private_key, public_key }
    }

    /// Returns the spending private key.
    #[must_use]
    pub const fn private_key(&self) -> &SpendingPrivateKey {
        &self.private_key
    }

    /// Returns the spending public key.
    #[must_use]
    pub const fn public_key(&self) -> &SpendingPublicKey {
        &self.public_key
    }
}

/// Typed 32-byte Railgun viewing private key.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ViewingPrivateKey([u8; 32]);

impl ViewingPrivateKey {
    /// Length of a viewing private key in bytes.
    pub const LENGTH: usize = 32;

    /// Creates a viewing private key from raw bytes.
    #[must_use]
    pub const fn new(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    /// Creates a viewing private key from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns an error if `bytes` is not exactly 32 bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ParseDomainError> {
        let array: [u8; Self::LENGTH] = bytes
            .try_into()
            .map_err(|_| ParseDomainError::new("viewing private key must be exactly 32 bytes"))?;
        Ok(Self::new(array))
    }

    /// Returns the raw private-key bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}

/// Typed 32-byte ed25519 viewing public key.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ViewingPublicKey([u8; 32]);

impl ViewingPublicKey {
    /// Length of a viewing public key in bytes.
    pub const LENGTH: usize = 32;

    /// Creates a viewing public key from raw bytes.
    #[must_use]
    pub const fn new(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    /// Creates a viewing public key from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns an error if `bytes` is not exactly 32 bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ParseDomainError> {
        let array: [u8; Self::LENGTH] = bytes
            .try_into()
            .map_err(|_| ParseDomainError::new("viewing public key must be exactly 32 bytes"))?;
        Ok(Self::new(array))
    }

    /// Returns the raw public-key bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}

/// Typed 32-byte blinded ed25519 viewing public key used in note encryption.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BlindedViewingPublicKey([u8; 32]);

impl BlindedViewingPublicKey {
    /// Length of a blinded viewing public key in bytes.
    pub const LENGTH: usize = 32;

    /// Creates a blinded viewing public key from raw bytes.
    #[must_use]
    pub const fn new(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    /// Creates a blinded viewing public key from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns an error if `bytes` is not exactly 32 bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ParseDomainError> {
        let array: [u8; Self::LENGTH] = bytes.try_into().map_err(|_| {
            ParseDomainError::new("blinded viewing public key must be exactly 32 bytes")
        })?;
        Ok(Self::new(array))
    }

    /// Returns the raw blinded public-key bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}

/// Typed 32-byte shared symmetric key used for note encryption and decryption.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SharedSymmetricKey([u8; 32]);

impl SharedSymmetricKey {
    /// Length of a shared symmetric key in bytes.
    pub const LENGTH: usize = 32;

    /// Creates a shared symmetric key from raw bytes.
    #[must_use]
    pub const fn new(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    /// Creates a shared symmetric key from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns an error if `bytes` is not exactly 32 bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ParseDomainError> {
        let array: [u8; Self::LENGTH] = bytes
            .try_into()
            .map_err(|_| ParseDomainError::new("shared symmetric key must be exactly 32 bytes"))?;
        Ok(Self::new(array))
    }

    /// Returns the raw shared-key bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}

/// Typed Railgun viewing keypair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ViewingKeyPair {
    private_key: ViewingPrivateKey,
    public_key: ViewingPublicKey,
}

impl ViewingKeyPair {
    /// Creates a viewing keypair from explicit components.
    #[must_use]
    pub const fn new(private_key: ViewingPrivateKey, public_key: ViewingPublicKey) -> Self {
        Self { private_key, public_key }
    }

    /// Returns the viewing private key.
    #[must_use]
    pub const fn private_key(&self) -> &ViewingPrivateKey {
        &self.private_key
    }

    /// Returns the viewing public key.
    #[must_use]
    pub const fn public_key(&self) -> &ViewingPublicKey {
        &self.public_key
    }
}

/// Typed Railgun nullifying key derived from a viewing private key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NullifyingKey(BigUint);

impl NullifyingKey {
    /// Creates a nullifying key from a field-element integer value.
    ///
    /// # Errors
    ///
    /// Returns an error if `value` is not a valid BN254 scalar field element.
    pub fn new(value: BigUint) -> Result<Self, ParseDomainError> {
        validate_bn254_scalar(&value, "nullifying key must fit within the BN254 scalar field")?;
        Ok(Self(value))
    }

    /// Returns the underlying field-element integer value.
    #[must_use]
    pub const fn value(&self) -> &BigUint {
        &self.0
    }
}

/// Typed Railgun master public key derived from spending and nullifying keys.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MasterPublicKey(BigUint);

impl MasterPublicKey {
    /// Creates a master public key from a field-element integer value.
    ///
    /// This constructor validates the canonical 32-byte encoding boundary rather
    /// than BN254 scalar-field membership. Existing canonical address vectors in
    /// the RAILGUN ecosystem include master public key values that fit the fixed
    /// 32-byte payload but are not constrained here to the BN254 modulus.
    ///
    /// # Errors
    ///
    /// Returns an error if `value` does not fit within the canonical 32-byte
    /// master-public-key encoding.
    pub fn new(value: BigUint) -> Result<Self, ParseDomainError> {
        if value.to_bytes_be().len() > 32 {
            return Err(ParseDomainError::new("master public key must fit within 32 bytes"));
        }
        Ok(Self(value))
    }

    /// Returns the underlying field-element integer value.
    #[must_use]
    pub const fn value(&self) -> &BigUint {
        &self.0
    }

    /// Returns the canonical 32-byte big-endian encoding.
    #[must_use]
    pub fn to_be_bytes(&self) -> [u8; 32] {
        let bytes = self.0.to_bytes_be();
        let mut padded = [0_u8; 32];
        let start = 32 - bytes.len();
        padded[start..].copy_from_slice(&bytes);
        padded
    }
}

/// Typed 32-byte packed `BabyJubJub` spending public key.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PackedSpendingPublicKey([u8; 32]);

impl PackedSpendingPublicKey {
    /// Length of a packed spending public key in bytes.
    pub const LENGTH: usize = 32;

    /// Creates a packed spending public key from raw bytes.
    #[must_use]
    pub const fn new(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    /// Creates a packed spending public key from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns an error if `bytes` is not exactly 32 bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ParseDomainError> {
        let array: [u8; Self::LENGTH] = bytes.try_into().map_err(|_| {
            ParseDomainError::new("packed spending public key must be exactly 32 bytes")
        })?;
        Ok(Self::new(array))
    }

    /// Returns the raw packed public-key bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}

/// View-only wallet import/export payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShareableViewingKeyData {
    viewing_private_key: ViewingPrivateKey,
    packed_spending_public_key: PackedSpendingPublicKey,
}

impl ShareableViewingKeyData {
    /// Creates a shareable viewing key payload from explicit components.
    #[must_use]
    pub const fn new(
        viewing_private_key: ViewingPrivateKey,
        packed_spending_public_key: PackedSpendingPublicKey,
    ) -> Self {
        Self { viewing_private_key, packed_spending_public_key }
    }

    /// Returns the viewing private key.
    #[must_use]
    pub const fn viewing_private_key(&self) -> &ViewingPrivateKey {
        &self.viewing_private_key
    }

    /// Returns the packed spending public key.
    #[must_use]
    pub const fn packed_spending_public_key(&self) -> &PackedSpendingPublicKey {
        &self.packed_spending_public_key
    }
}

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;

    use super::{
        BlindedViewingPublicKey, MasterPublicKey, NullifyingKey, PackedSpendingPublicKey,
        SharedSymmetricKey, SpendingPrivateKey, SpendingPublicKey, ViewingPrivateKey,
        ViewingPublicKey,
    };
    use crate::{ParseDomainError, bn254_scalar_field_modulus};

    #[test]
    fn rejects_invalid_spending_private_key_length() {
        let Err(error) = SpendingPrivateKey::from_slice(&[7_u8; 31]) else {
            panic!("invalid spending private key length should fail");
        };
        assert_eq!(error, ParseDomainError::new("spending private key must be exactly 32 bytes"));
    }

    #[test]
    fn rejects_invalid_viewing_private_key_length() {
        let Err(error) = ViewingPrivateKey::from_slice(&[7_u8; 33]) else {
            panic!("invalid viewing private key length should fail");
        };
        assert_eq!(error, ParseDomainError::new("viewing private key must be exactly 32 bytes"));
    }

    #[test]
    fn rejects_invalid_viewing_public_key_length() {
        let Err(error) = ViewingPublicKey::from_slice(&[7_u8; 31]) else {
            panic!("invalid viewing public key length should fail");
        };
        assert_eq!(error, ParseDomainError::new("viewing public key must be exactly 32 bytes"));
    }

    #[test]
    fn rejects_invalid_blinded_viewing_public_key_length() {
        let Err(error) = BlindedViewingPublicKey::from_slice(&[7_u8; 31]) else {
            panic!("invalid blinded viewing public key length should fail");
        };
        assert_eq!(
            error,
            ParseDomainError::new("blinded viewing public key must be exactly 32 bytes")
        );
    }

    #[test]
    fn rejects_invalid_shared_symmetric_key_length() {
        let Err(error) = SharedSymmetricKey::from_slice(&[7_u8; 31]) else {
            panic!("invalid shared symmetric key length should fail");
        };
        assert_eq!(error, ParseDomainError::new("shared symmetric key must be exactly 32 bytes"));
    }

    #[test]
    fn rejects_invalid_nullifying_key_field_element() {
        let Err(error) = NullifyingKey::new(bn254_scalar_field_modulus()) else {
            panic!("invalid nullifying key should fail");
        };
        assert_eq!(
            error,
            ParseDomainError::new("nullifying key must fit within the BN254 scalar field")
        );
    }

    #[test]
    fn rejects_master_public_key_larger_than_32_bytes() {
        let Err(error) = MasterPublicKey::new(BigUint::from_bytes_be(&[1_u8; 33])) else {
            panic!("oversized master public key should fail");
        };
        assert_eq!(error, ParseDomainError::new("master public key must fit within 32 bytes"));
    }

    #[test]
    fn rejects_invalid_spending_public_key_point() {
        let Err(error) = SpendingPublicKey::new(BigUint::from(1_u8), BigUint::from(1_u8)) else {
            panic!("invalid spending public key should fail");
        };
        assert_eq!(
            error,
            ParseDomainError::new(
                "spending public key coordinates must form a valid BabyJubJub point"
            )
        );
    }

    #[test]
    fn rejects_invalid_packed_spending_public_key_length() {
        let Err(error) = PackedSpendingPublicKey::from_slice(&[7_u8; 31]) else {
            panic!("invalid packed spending public key should fail");
        };
        assert_eq!(
            error,
            ParseDomainError::new("packed spending public key must be exactly 32 bytes")
        );
    }
}
