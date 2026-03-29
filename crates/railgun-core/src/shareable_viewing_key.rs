//! Shareable Railgun viewing key import/export.

use core::fmt;

use babyjubjub_rs::{Fr as BabyJubJubField, Point, decompress_point};
use ff::{PrimeField as _, PrimeFieldRepr as _};
use num_bigint::BigUint;
use railgun_types::{
    ChainScope, PackedSpendingPublicKey, RailgunAddress, ShareableViewingKeyData,
    SpendingPublicKey, ViewingPublicKey,
};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::{
    AddressEncodingError, derive_master_public_key, derive_nullifying_key,
    derive_viewing_public_key, encode_railgun_address,
};

/// Fully inspected shareable viewing key data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShareableViewingKeyInspection {
    payload: ShareableViewingKeyData,
    spending_public_key: SpendingPublicKey,
    viewing_public_key: ViewingPublicKey,
    nullifying_key: railgun_types::NullifyingKey,
    master_public_key: railgun_types::MasterPublicKey,
    address: RailgunAddress,
}

impl ShareableViewingKeyInspection {
    /// Creates an inspection result from explicit components.
    #[must_use]
    pub const fn new(
        payload: ShareableViewingKeyData,
        spending_public_key: SpendingPublicKey,
        viewing_public_key: ViewingPublicKey,
        nullifying_key: railgun_types::NullifyingKey,
        master_public_key: railgun_types::MasterPublicKey,
        address: RailgunAddress,
    ) -> Self {
        Self {
            payload,
            spending_public_key,
            viewing_public_key,
            nullifying_key,
            master_public_key,
            address,
        }
    }

    /// Returns the decoded shareable viewing key payload.
    #[must_use]
    pub const fn payload(&self) -> &ShareableViewingKeyData {
        &self.payload
    }

    /// Returns the unpacked spending public key.
    #[must_use]
    pub const fn spending_public_key(&self) -> &SpendingPublicKey {
        &self.spending_public_key
    }

    /// Returns the viewing public key derived from `vpriv`.
    #[must_use]
    pub const fn viewing_public_key(&self) -> &ViewingPublicKey {
        &self.viewing_public_key
    }

    /// Returns the nullifying key derived from `vpriv`.
    #[must_use]
    pub const fn nullifying_key(&self) -> &railgun_types::NullifyingKey {
        &self.nullifying_key
    }

    /// Returns the master public key derived from `spub` and the nullifying key.
    #[must_use]
    pub const fn master_public_key(&self) -> &railgun_types::MasterPublicKey {
        &self.master_public_key
    }

    /// Returns the derived Railgun address.
    #[must_use]
    pub const fn address(&self) -> &RailgunAddress {
        &self.address
    }
}

/// Error returned when shareable viewing key inspection fails.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ShareableViewingKeyInspectionError {
    /// The encoded payload is malformed.
    ShareableViewingKey(ShareableViewingKeyError),
    /// The nullifying or master public key could not be derived.
    KeyDerivation,
    /// Address encoding failed.
    AddressEncoding(AddressEncodingError),
}

impl fmt::Display for ShareableViewingKeyInspectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShareableViewingKey(error) => write!(formatter, "{error}"),
            Self::KeyDerivation => formatter.write_str("failed to derive view-only key material"),
            Self::AddressEncoding(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for ShareableViewingKeyInspectionError {}

impl From<ShareableViewingKeyError> for ShareableViewingKeyInspectionError {
    fn from(value: ShareableViewingKeyError) -> Self {
        Self::ShareableViewingKey(value)
    }
}

impl From<AddressEncodingError> for ShareableViewingKeyInspectionError {
    fn from(value: AddressEncodingError) -> Self {
        Self::AddressEncoding(value)
    }
}

/// Error returned when a shareable viewing key payload is malformed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ShareableViewingKeyError {
    /// The payload is not valid hexadecimal.
    InvalidHex,
    /// The payload is not valid `MessagePack` for the canonical schema.
    InvalidMessagePack,
    /// The viewing private key field is not exactly 32 bytes long.
    InvalidViewingPrivateKeyLength(usize),
    /// The packed spending public key field is not exactly 32 bytes long.
    InvalidPackedSpendingPublicKeyLength(usize),
    /// The packed spending public key does not decode to a valid `BabyJubJub` point.
    InvalidPackedSpendingPublicKey,
    /// The spending public key cannot be represented as a valid `BabyJubJub` point.
    InvalidSpendingPublicKey,
}

impl fmt::Display for ShareableViewingKeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHex => formatter.write_str("invalid shareable viewing key hex payload"),
            Self::InvalidMessagePack => {
                formatter.write_str("invalid shareable viewing key MessagePack payload")
            }
            Self::InvalidViewingPrivateKeyLength(length) => write!(
                formatter,
                "invalid viewing private key length: expected 32 bytes, got {length}"
            ),
            Self::InvalidPackedSpendingPublicKeyLength(length) => write!(
                formatter,
                "invalid packed spending public key length: expected 32 bytes, got {length}"
            ),
            Self::InvalidPackedSpendingPublicKey => {
                formatter.write_str("invalid packed spending public key")
            }
            Self::InvalidSpendingPublicKey => {
                formatter.write_str("invalid spending public key coordinates")
            }
        }
    }
}

impl std::error::Error for ShareableViewingKeyError {}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ShareableViewingKeyPayload {
    #[serde(rename = "vpriv")]
    viewing_private_key: ByteBuf,
    #[serde(rename = "spub")]
    packed_spending_public_key: ByteBuf,
}

fn parse_coordinate(value: &BabyJubJubField) -> Result<BigUint, ShareableViewingKeyError> {
    let repr = value.into_repr();
    let mut bytes = Vec::with_capacity(core::mem::size_of_val(repr.as_ref()));
    repr.write_be(&mut bytes)
        .map_err(|_| ShareableViewingKeyError::InvalidPackedSpendingPublicKey)?;
    Ok(BigUint::from_bytes_be(&bytes))
}

fn biguint_to_babyjubjub_field(
    value: &BigUint,
) -> Result<BabyJubJubField, ShareableViewingKeyError> {
    let field = BabyJubJubField::from_str(&value.to_string())
        .ok_or(ShareableViewingKeyError::InvalidSpendingPublicKey)?;
    let roundtrip = parse_coordinate(&field)?;

    if roundtrip == *value {
        Ok(field)
    } else {
        Err(ShareableViewingKeyError::InvalidSpendingPublicKey)
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let high = byte >> 4;
        let low = byte & 0x0F;
        encoded.push(char::from(if high < 10 { b'0' + high } else { b'a' + (high - 10) }));
        encoded.push(char::from(if low < 10 { b'0' + low } else { b'a' + (low - 10) }));
    }
    encoded
}

fn decode_hex(value: &str) -> Result<Vec<u8>, ShareableViewingKeyError> {
    let bytes = value.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err(ShareableViewingKeyError::InvalidHex);
    }

    let mut decoded = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let high = char::from(pair[0]).to_digit(16).ok_or(ShareableViewingKeyError::InvalidHex)?;
        let low = char::from(pair[1]).to_digit(16).ok_or(ShareableViewingKeyError::InvalidHex)?;
        decoded.push(
            u8::try_from((high << 4) | low).map_err(|_| ShareableViewingKeyError::InvalidHex)?,
        );
    }

    Ok(decoded)
}

/// Packs a spending public key into its canonical 32-byte `BabyJubJub` encoding.
///
/// # Errors
///
/// Returns an error if the public-key coordinates are not valid `BabyJubJub` field
/// elements.
pub fn pack_spending_public_key(
    spending_public_key: &SpendingPublicKey,
) -> Result<PackedSpendingPublicKey, ShareableViewingKeyError> {
    let point = Point {
        x: biguint_to_babyjubjub_field(spending_public_key.x())?,
        y: biguint_to_babyjubjub_field(spending_public_key.y())?,
    };

    Ok(PackedSpendingPublicKey::new(point.compress()))
}

/// Unpacks a canonical 32-byte `BabyJubJub` spending public key.
///
/// # Errors
///
/// Returns an error if the packed point is invalid.
pub fn unpack_spending_public_key(
    packed_spending_public_key: &PackedSpendingPublicKey,
) -> Result<SpendingPublicKey, ShareableViewingKeyError> {
    let point = decompress_point(*packed_spending_public_key.as_bytes())
        .map_err(|_| ShareableViewingKeyError::InvalidPackedSpendingPublicKey)?;

    Ok(SpendingPublicKey::new(parse_coordinate(&point.x)?, parse_coordinate(&point.y)?))
}

/// Encodes a shareable viewing key payload as lowercase hexadecimal `MessagePack`.
///
/// # Errors
///
/// Returns an error if `MessagePack` serialization fails unexpectedly.
pub fn encode_shareable_viewing_key(
    payload: &ShareableViewingKeyData,
) -> Result<String, ShareableViewingKeyError> {
    let payload = ShareableViewingKeyPayload {
        viewing_private_key: ByteBuf::from(payload.viewing_private_key().as_bytes().to_vec()),
        packed_spending_public_key: ByteBuf::from(
            payload.packed_spending_public_key().as_bytes().to_vec(),
        ),
    };
    let bytes = rmp_serde::to_vec_named(&payload)
        .map_err(|_| ShareableViewingKeyError::InvalidMessagePack)?;
    Ok(encode_hex(&bytes))
}

/// Decodes a shareable viewing key payload from lowercase hexadecimal `MessagePack`.
///
/// # Errors
///
/// Returns an error if the payload is not valid hex, `MessagePack`, or contains an
/// invalid packed spending public key.
pub fn decode_shareable_viewing_key(
    payload: &str,
) -> Result<ShareableViewingKeyData, ShareableViewingKeyError> {
    let bytes = decode_hex(payload)?;
    let payload: ShareableViewingKeyPayload =
        rmp_serde::from_slice(&bytes).map_err(|_| ShareableViewingKeyError::InvalidMessagePack)?;
    let viewing_private_key = railgun_types::ViewingPrivateKey::from_slice(
        &payload.viewing_private_key,
    )
    .map_err(|_| {
        ShareableViewingKeyError::InvalidViewingPrivateKeyLength(payload.viewing_private_key.len())
    })?;
    let packed_spending_public_key =
        PackedSpendingPublicKey::from_slice(&payload.packed_spending_public_key).map_err(|_| {
            ShareableViewingKeyError::InvalidPackedSpendingPublicKeyLength(
                payload.packed_spending_public_key.len(),
            )
        })?;
    unpack_spending_public_key(&packed_spending_public_key)?;

    Ok(ShareableViewingKeyData::new(viewing_private_key, packed_spending_public_key))
}

/// Decodes and inspects a shareable viewing key, deriving public-facing values.
///
/// # Errors
///
/// Returns an error if decoding fails, if view-only key derivation fails, or if
/// the derived address cannot be encoded.
pub fn inspect_shareable_viewing_key(
    payload: &str,
    chain_scope: ChainScope,
) -> Result<ShareableViewingKeyInspection, ShareableViewingKeyInspectionError> {
    let payload = decode_shareable_viewing_key(payload)?;
    let spending_public_key = unpack_spending_public_key(payload.packed_spending_public_key())?;
    let viewing_public_key = derive_viewing_public_key(payload.viewing_private_key());
    let nullifying_key = derive_nullifying_key(payload.viewing_private_key())
        .map_err(|_| ShareableViewingKeyInspectionError::KeyDerivation)?;
    let master_public_key = derive_master_public_key(&spending_public_key, &nullifying_key)
        .map_err(|_| ShareableViewingKeyInspectionError::KeyDerivation)?;
    let address = encode_railgun_address(1, &master_public_key, chain_scope, &viewing_public_key)?;

    Ok(ShareableViewingKeyInspection::new(
        payload,
        spending_public_key,
        viewing_public_key,
        nullifying_key,
        master_public_key,
        address,
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        ShareableViewingKeyError, ShareableViewingKeyPayload, decode_shareable_viewing_key,
        encode_shareable_viewing_key, inspect_shareable_viewing_key, pack_spending_public_key,
        unpack_spending_public_key,
    };
    use crate::{derive_master_public_key, derive_nullifying_key, derive_spending_public_key};
    use railgun_types::ChainScope;
    use railgun_types::{ShareableViewingKeyData, SpendingPrivateKey, ViewingPrivateKey};
    use serde::Serialize;
    use serde_bytes::ByteBuf;

    #[test]
    fn round_trips_shareable_viewing_key_payload() {
        let viewing_private_key = ViewingPrivateKey::new(hex_array::<32>(
            "67d7d19d00e6e3b3517fe68ac46505dd207df6e8fe3aa06ba3face352e7599ef",
        ));
        let spending_public_key = derive_spending_public_key(&SpendingPrivateKey::new(
            hex_array::<32>("67d7d19d00e6e3b3517fe68ac46505dd207df6e8fe3aa06ba3face352e7599ef"),
        ))
        .unwrap_or_else(|_| panic!("spending public key derivation should succeed"));
        let packed_spending_public_key = pack_spending_public_key(&spending_public_key)
            .unwrap_or_else(|_| panic!("spending public key packing should succeed"));
        let payload = ShareableViewingKeyData::new(viewing_private_key, packed_spending_public_key);
        let encoded = encode_shareable_viewing_key(&payload)
            .unwrap_or_else(|_| panic!("shareable viewing key encoding should succeed"));
        let decoded = decode_shareable_viewing_key(&encoded)
            .unwrap_or_else(|_| panic!("shareable viewing key decoding should succeed"));

        assert_eq!(decoded, payload);
        assert_eq!(encoded, encoded.to_lowercase());
    }

    #[test]
    fn rejects_payload_with_renamed_fields() {
        #[derive(Serialize)]
        struct RenamedPayload {
            #[serde(rename = "viewingPrivateKey")]
            viewing_private_key: ByteBuf,
            #[serde(rename = "spendingPublicKey")]
            spending_public_key: ByteBuf,
        }

        let bytes = rmp_serde::to_vec_named(&RenamedPayload {
            viewing_private_key: ByteBuf::from(vec![7_u8; 32]),
            spending_public_key: ByteBuf::from(vec![8_u8; 32]),
        })
        .unwrap_or_else(|_| panic!("renamed payload serialization should succeed"));

        let error = expect_err(
            decode_shareable_viewing_key(&hex_encode(&bytes)),
            "renamed payload should fail",
        );

        assert_eq!(error, ShareableViewingKeyError::InvalidMessagePack);
    }

    #[test]
    fn rejects_invalid_hex_payload() {
        let error = expect_err(decode_shareable_viewing_key("not-hex"), "invalid hex should fail");

        assert_eq!(error, ShareableViewingKeyError::InvalidHex);
    }

    #[test]
    fn rejects_invalid_packed_spending_public_key() {
        let payload = ShareableViewingKeyPayload {
            viewing_private_key: ByteBuf::from(vec![7_u8; 32]),
            packed_spending_public_key: ByteBuf::from(vec![0xFF_u8; 32]),
        };
        let encoded = hex_encode(
            &rmp_serde::to_vec_named(&payload)
                .unwrap_or_else(|_| panic!("invalid-point payload serialization should succeed")),
        );
        let error =
            expect_err(decode_shareable_viewing_key(&encoded), "invalid packed key should fail");

        assert_eq!(error, ShareableViewingKeyError::InvalidPackedSpendingPublicKey);
    }

    #[test]
    fn rejects_malformed_messagepack_payload() {
        let error =
            expect_err(decode_shareable_viewing_key("c1"), "malformed MessagePack should fail");

        assert_eq!(error, ShareableViewingKeyError::InvalidMessagePack);
    }

    #[test]
    fn unpacked_payload_can_feed_view_only_derivations() {
        let viewing_private_key = ViewingPrivateKey::new(hex_array::<32>(
            "67d7d19d00e6e3b3517fe68ac46505dd207df6e8fe3aa06ba3face352e7599ef",
        ));
        let spending_public_key = derive_spending_public_key(&SpendingPrivateKey::new(
            hex_array::<32>("67d7d19d00e6e3b3517fe68ac46505dd207df6e8fe3aa06ba3face352e7599ef"),
        ))
        .unwrap_or_else(|_| panic!("spending public key derivation should succeed"));
        let packed_spending_public_key = pack_spending_public_key(&spending_public_key)
            .unwrap_or_else(|_| panic!("spending public key packing should succeed"));
        let payload = ShareableViewingKeyData::new(viewing_private_key, packed_spending_public_key);
        let decoded = decode_shareable_viewing_key(
            &encode_shareable_viewing_key(&payload)
                .unwrap_or_else(|_| panic!("shareable viewing key encoding should succeed")),
        )
        .unwrap_or_else(|_| panic!("shareable viewing key decoding should succeed"));
        let unpacked_spending_public_key =
            unpack_spending_public_key(decoded.packed_spending_public_key())
                .unwrap_or_else(|_| panic!("spending public key unpacking should succeed"));
        let nullifying_key = derive_nullifying_key(decoded.viewing_private_key())
            .unwrap_or_else(|_| panic!("nullifying key derivation should succeed"));
        let master_public_key =
            derive_master_public_key(&unpacked_spending_public_key, &nullifying_key)
                .unwrap_or_else(|_| panic!("master public key derivation should succeed"));

        assert_eq!(unpacked_spending_public_key, spending_public_key);
        assert_eq!(
            master_public_key.value().to_string(),
            "15607618471549356314064749634364841401625982784343012680230632021308514635691"
        );
    }

    #[test]
    fn inspects_shareable_viewing_key_and_derives_all_chains_address() {
        let viewing_private_key = ViewingPrivateKey::new(hex_array::<32>(
            "67d7d19d00e6e3b3517fe68ac46505dd207df6e8fe3aa06ba3face352e7599ef",
        ));
        let spending_public_key = derive_spending_public_key(&SpendingPrivateKey::new(
            hex_array::<32>("67d7d19d00e6e3b3517fe68ac46505dd207df6e8fe3aa06ba3face352e7599ef"),
        ))
        .unwrap_or_else(|_| panic!("spending public key derivation should succeed"));
        let packed_spending_public_key = pack_spending_public_key(&spending_public_key)
            .unwrap_or_else(|_| panic!("spending public key packing should succeed"));
        let payload = ShareableViewingKeyData::new(viewing_private_key, packed_spending_public_key);
        let encoded = encode_shareable_viewing_key(&payload)
            .unwrap_or_else(|_| panic!("shareable viewing key encoding should succeed"));
        let inspection = inspect_shareable_viewing_key(&encoded, ChainScope::AllChains)
            .unwrap_or_else(|_| panic!("shareable viewing key inspection should succeed"));

        assert_eq!(inspection.payload(), &payload);
        assert_eq!(inspection.spending_public_key(), &spending_public_key);
        assert_eq!(
            inspection.master_public_key().value().to_string(),
            "15607618471549356314064749634364841401625982784343012680230632021308514635691"
        );
        assert!(inspection.address().as_str().starts_with("0zk1"));
    }

    #[test]
    fn packed_spending_public_key_round_trips() {
        let spending_public_key = derive_spending_public_key(&SpendingPrivateKey::new(
            hex_array::<32>("3428cfc939320328501174a4e76e869197ffc894b58dbf4d0e953c484d66cb5e"),
        ))
        .unwrap_or_else(|_| panic!("spending public key derivation should succeed"));
        let packed = pack_spending_public_key(&spending_public_key)
            .unwrap_or_else(|_| panic!("spending public key packing should succeed"));
        let unpacked = unpack_spending_public_key(&packed)
            .unwrap_or_else(|_| panic!("spending public key unpacking should succeed"));

        assert_eq!(unpacked, spending_public_key);
    }

    #[test]
    fn rejects_invalid_packed_spending_public_key_length() {
        let payload = ShareableViewingKeyPayload {
            viewing_private_key: ByteBuf::from(vec![7_u8; 32]),
            packed_spending_public_key: ByteBuf::from(vec![8_u8; 31]),
        };
        let encoded = hex_encode(
            &rmp_serde::to_vec_named(&payload)
                .unwrap_or_else(|_| panic!("invalid-length payload serialization should succeed")),
        );
        let error = expect_err(
            decode_shareable_viewing_key(&encoded),
            "invalid packed key length should fail",
        );

        assert_eq!(error, ShareableViewingKeyError::InvalidPackedSpendingPublicKeyLength(31));
    }

    fn hex_array<const N: usize>(hex: &str) -> [u8; N] {
        let bytes = hex_decode(hex);
        bytes.try_into().unwrap_or_else(|_| panic!("test vector should match requested length"))
    }

    fn hex_decode(hex: &str) -> Vec<u8> {
        super::decode_hex(hex).unwrap_or_else(|_| panic!("test hex should be valid"))
    }

    fn hex_encode(bytes: &[u8]) -> String {
        super::encode_hex(bytes)
    }

    fn expect_err<T, E>(result: Result<T, E>, message: &str) -> E {
        match result {
            Ok(_) => panic!("{message}"),
            Err(error) => error,
        }
    }
}
