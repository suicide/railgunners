//! Shared symmetric key derivation for note encryption.

use core::fmt;

use curve25519_dalek::{edwards::CompressedEdwardsY, scalar::Scalar};
use railgun_types::{BlindedViewingPublicKey, SharedSymmetricKey, ViewingPrivateKey};
use sha2::{Digest, Sha256, Sha512};

/// Error returned when shared symmetric key derivation input is invalid.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SharedKeyError {
    /// The private key is not exactly 32 bytes long.
    InvalidPrivateKeyLength(usize),
    /// The blinded viewing public key bytes are not a valid ed25519 point.
    InvalidBlindedPublicKey,
}

impl fmt::Display for SharedKeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPrivateKeyLength(length) => {
                write!(formatter, "invalid private key length: expected 32 bytes, got {length}")
            }
            Self::InvalidBlindedPublicKey => {
                formatter.write_str("invalid blinded viewing public key")
            }
        }
    }
}

impl std::error::Error for SharedKeyError {}

fn ed25519_private_scalar(viewing_private_key: &ViewingPrivateKey) -> Scalar {
    // Shared-key derivation uses the canonical ed25519 SHA-512 head and clamp
    // rules, not the raw 32-byte viewing private key interpreted directly.
    let hash = Sha512::digest(viewing_private_key.as_bytes());
    let mut head = [0_u8; 32];
    head.copy_from_slice(&hash[..32]);
    // Ed25519 interprets this 32-byte value as little-endian, so clamping the
    // first byte clears the scalar's lowest 3 bits, while clamping the last
    // byte clears bit 255 and sets bit 254.
    head[0] &= 0b1111_1000;
    head[31] &= 0b0111_1111;
    head[31] |= 0b0100_0000;
    Scalar::from_bytes_mod_order(head)
}

/// Derives the canonical shared symmetric key from a viewing private key and a
/// blinded viewing public key.
///
/// The shared-key preimage is the compressed ed25519 point resulting from
/// `blinded_public_key * private_scalar`, hashed with SHA-256.
///
/// # Errors
///
/// Returns an error if `blinded_public_key` does not decode to a valid ed25519
/// point.
pub fn derive_shared_symmetric_key(
    viewing_private_key: &ViewingPrivateKey,
    blinded_public_key: &BlindedViewingPublicKey,
) -> Result<SharedSymmetricKey, SharedKeyError> {
    let point = CompressedEdwardsY(*blinded_public_key.as_bytes())
        .decompress()
        .ok_or(SharedKeyError::InvalidBlindedPublicKey)?;
    let shared_point = (point * ed25519_private_scalar(viewing_private_key)).compress().to_bytes();
    let digest = Sha256::digest(shared_point);
    let mut shared_key = [0_u8; SharedSymmetricKey::LENGTH];
    shared_key.copy_from_slice(&digest[..SharedSymmetricKey::LENGTH]);
    Ok(SharedSymmetricKey::new(shared_key))
}

/// Derives the canonical shared symmetric key from raw private-key and blinded
/// public-key bytes.
///
/// # Errors
///
/// Returns an error if `viewing_private_key` is not exactly 32 bytes long or if
/// `blinded_public_key` does not decode to a valid ed25519 point.
pub fn derive_shared_symmetric_key_from_bytes(
    viewing_private_key: &[u8],
    blinded_public_key: &[u8],
) -> Result<SharedSymmetricKey, SharedKeyError> {
    let viewing_private_key: [u8; ViewingPrivateKey::LENGTH] = viewing_private_key
        .try_into()
        .map_err(|_| SharedKeyError::InvalidPrivateKeyLength(viewing_private_key.len()))?;
    let blinded_public_key = BlindedViewingPublicKey::from_slice(blinded_public_key)
        .map_err(|_| SharedKeyError::InvalidBlindedPublicKey)?;

    derive_shared_symmetric_key(&ViewingPrivateKey::new(viewing_private_key), &blinded_public_key)
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::{edwards::CompressedEdwardsY, scalar::Scalar};
    use railgun_types::{BlindedViewingPublicKey, ViewingPrivateKey};

    use super::{
        SharedKeyError, derive_shared_symmetric_key, derive_shared_symmetric_key_from_bytes,
    };
    use crate::derive_viewing_public_key;

    fn decode_hex<const N: usize>(value: &str) -> [u8; N] {
        let trimmed = value.strip_prefix("0x").unwrap_or(value);
        assert_eq!(trimmed.len(), N * 2, "hex input has unexpected length");

        let mut bytes = [0_u8; N];
        for (index, chunk) in trimmed.as_bytes().chunks_exact(2).enumerate() {
            let high = (chunk[0] as char)
                .to_digit(16)
                .unwrap_or_else(|| panic!("invalid hex nibble at index {}", index * 2));
            let low = (chunk[1] as char)
                .to_digit(16)
                .unwrap_or_else(|| panic!("invalid hex nibble at index {}", index * 2 + 1));
            bytes[index] = u8::try_from((high << 4) | low)
                .unwrap_or_else(|_| panic!("hex byte should fit into u8"));
        }
        bytes
    }

    fn invalid_blinded_public_key_bytes() -> [u8; 32] {
        for first in u8::MIN..=u8::MAX {
            for second in u8::MIN..=u8::MAX {
                let mut candidate = [0_u8; 32];
                candidate[0] = first;
                candidate[1] = second;

                if CompressedEdwardsY(candidate).decompress().is_none() {
                    return candidate;
                }
            }
        }

        panic!("expected at least one invalid compressed ed25519 point encoding");
    }

    #[test]
    fn derives_shared_key_from_upstream_fixed_vector() {
        let viewing_private_key = ViewingPrivateKey::new(decode_hex(
            "0123456789012345678901234567890123456789012345678901234567891234",
        ));
        let blinded_public_key = BlindedViewingPublicKey::new(decode_hex(
            "0987654321098765432109876543210987654321098765432109876543210987",
        ));

        let shared_key = derive_shared_symmetric_key(&viewing_private_key, &blinded_public_key)
            .unwrap_or_else(|error| panic!("shared key derivation should succeed: {error}"));

        assert_eq!(
            hex_encode(shared_key.as_bytes()),
            "fbb71adfede43b8a756939500c810d85b16cfbead66d126065639c0cec1fea56"
        );
    }

    #[test]
    fn shared_key_matches_for_sender_and_receiver_blinded_points() {
        let sender = ViewingPrivateKey::new(decode_hex(
            "67d7d19d00e6e3b3517fe68ac46505dd207df6e8fe3aa06ba3face352e7599ef",
        ));
        let receiver = ViewingPrivateKey::new(decode_hex(
            "3428cfc939320328501174a4e76e869197ffc894b58dbf4d0e953c484d66cb5e",
        ));
        let sender_point = CompressedEdwardsY(*derive_viewing_public_key(&sender).as_bytes())
            .decompress()
            .unwrap_or_else(|| panic!("sender viewing public key should decompress"));
        let receiver_point = CompressedEdwardsY(*derive_viewing_public_key(&receiver).as_bytes())
            .decompress()
            .unwrap_or_else(|| panic!("receiver viewing public key should decompress"));
        let blinding_scalar = Scalar::from(7_u64);
        let blinded_sender =
            BlindedViewingPublicKey::new((sender_point * blinding_scalar).compress().to_bytes());
        let blinded_receiver =
            BlindedViewingPublicKey::new((receiver_point * blinding_scalar).compress().to_bytes());

        let receiver_shared_key = derive_shared_symmetric_key(&receiver, &blinded_sender)
            .unwrap_or_else(|error| panic!("receiver shared key should derive: {error}"));
        let sender_shared_key = derive_shared_symmetric_key(&sender, &blinded_receiver)
            .unwrap_or_else(|error| panic!("sender shared key should derive: {error}"));

        assert_eq!(receiver_shared_key, sender_shared_key);
    }

    #[test]
    fn rejects_invalid_blinded_public_key() {
        let viewing_private_key = ViewingPrivateKey::new([7_u8; 32]);
        let blinded_public_key = BlindedViewingPublicKey::new(invalid_blinded_public_key_bytes());

        let Err(error) = derive_shared_symmetric_key(&viewing_private_key, &blinded_public_key)
        else {
            panic!("invalid blinded public key should fail");
        };

        assert_eq!(error, SharedKeyError::InvalidBlindedPublicKey);
    }

    #[test]
    fn rejects_invalid_private_key_length_from_bytes() {
        let Err(error) = derive_shared_symmetric_key_from_bytes(&[7_u8; 31], &[9_u8; 32]) else {
            panic!("invalid private key length should fail");
        };

        assert_eq!(error, SharedKeyError::InvalidPrivateKeyLength(31));
    }

    fn hex_encode(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(bytes.len() * 2);
        for &byte in bytes {
            encoded.push(HEX[usize::from(byte >> 4)] as char);
            encoded.push(HEX[usize::from(byte & 0x0f)] as char);
        }
        encoded
    }
}
