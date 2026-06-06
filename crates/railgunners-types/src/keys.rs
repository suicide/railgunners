use num_bigint::BigUint;

use crate::{ParseDomainError, validate_bn254_scalar};

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
    /// Creates a spending public key from canonical coordinate integers.
    ///
    /// # Errors
    ///
    /// Returns an error if either coordinate is not a valid BN254 scalar-field
    /// element. Curve-point validation belongs in `railgun-core`, where the crypto
    /// backend is selected.
    pub fn new(x: BigUint, y: BigUint) -> Result<Self, ParseDomainError> {
        validate_bn254_scalar(
            &x,
            "spending public key x coordinate must fit within the BN254 scalar field",
        )?;
        validate_bn254_scalar(
            &y,
            "spending public key y coordinate must fit within the BN254 scalar field",
        )?;
        Ok(Self { x, y })
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

/// Canonical wallet scan-key bundle for note ownership and spent-note checks.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::struct_field_names)]
pub struct WalletScanKeyBundle {
    viewing_private_key: ViewingPrivateKey,
    viewing_public_key: ViewingPublicKey,
    nullifying_key: NullifyingKey,
    master_public_key: MasterPublicKey,
}

impl WalletScanKeyBundle {
    /// Creates a scan-key bundle from explicit components.
    #[must_use]
    pub const fn new(
        viewing_private_key: ViewingPrivateKey,
        viewing_public_key: ViewingPublicKey,
        nullifying_key: NullifyingKey,
        master_public_key: MasterPublicKey,
    ) -> Self {
        Self { viewing_private_key, viewing_public_key, nullifying_key, master_public_key }
    }

    /// Returns the viewing private key.
    #[must_use]
    pub const fn viewing_private_key(&self) -> &ViewingPrivateKey {
        &self.viewing_private_key
    }

    /// Returns the viewing public key.
    #[must_use]
    pub const fn viewing_public_key(&self) -> &ViewingPublicKey {
        &self.viewing_public_key
    }

    /// Returns the nullifying key.
    #[must_use]
    pub const fn nullifying_key(&self) -> &NullifyingKey {
        &self.nullifying_key
    }

    /// Returns the master public key.
    #[must_use]
    pub const fn master_public_key(&self) -> &MasterPublicKey {
        &self.master_public_key
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
        ViewingPublicKey, WalletScanKeyBundle,
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
    fn wallet_scan_key_bundle_preserves_components() {
        let viewing_private_key = ViewingPrivateKey::new([1_u8; 32]);
        let viewing_public_key = ViewingPublicKey::new([2_u8; 32]);
        let nullifying_key = NullifyingKey::new(3_u8.into())
            .unwrap_or_else(|error| panic!("nullifying key should validate: {error}"));
        let master_public_key = MasterPublicKey::new(4_u8.into())
            .unwrap_or_else(|error| panic!("master public key should validate: {error}"));

        let bundle = WalletScanKeyBundle::new(
            viewing_private_key,
            viewing_public_key,
            nullifying_key.clone(),
            master_public_key.clone(),
        );

        assert_eq!(bundle.viewing_private_key(), &viewing_private_key);
        assert_eq!(bundle.viewing_public_key(), &viewing_public_key);
        assert_eq!(bundle.nullifying_key(), &nullifying_key);
        assert_eq!(bundle.master_public_key(), &master_public_key);
    }

    #[test]
    fn rejects_master_public_key_larger_than_32_bytes() {
        let Err(error) = MasterPublicKey::new(BigUint::from_bytes_be(&[1_u8; 33])) else {
            panic!("oversized master public key should fail");
        };
        assert_eq!(error, ParseDomainError::new("master public key must fit within 32 bytes"));
    }

    #[test]
    fn rejects_invalid_spending_public_key_x_coordinate() {
        let Err(error) = SpendingPublicKey::new(bn254_scalar_field_modulus(), BigUint::from(1_u8))
        else {
            panic!("invalid spending public key should fail");
        };
        assert_eq!(
            error,
            ParseDomainError::new(
                "spending public key x coordinate must fit within the BN254 scalar field"
            )
        );
    }

    #[test]
    fn rejects_invalid_spending_public_key_y_coordinate() {
        let Err(error) = SpendingPublicKey::new(BigUint::from(1_u8), bn254_scalar_field_modulus())
        else {
            panic!("invalid spending public key should fail");
        };
        assert_eq!(
            error,
            ParseDomainError::new(
                "spending public key y coordinate must fit within the BN254 scalar field"
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
