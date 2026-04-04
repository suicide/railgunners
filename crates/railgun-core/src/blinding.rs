//! Note blinding and unblinding helpers for note encryption.

use core::fmt;

use curve25519_dalek::{edwards::CompressedEdwardsY, scalar::Scalar};
use num_bigint::BigUint;
use railgun_types::{BlindedViewingPublicKey, SenderRandom, SharedRandom, ViewingPublicKey};
use sha2::{Digest, Sha512};

/// Standard Ed25519 subgroup order `l = 2^252 + 27742317777372353535851937790883648493`
/// encoded as 32-byte big-endian bytes.
const ED25519_GROUP_ORDER_BYTES: [u8; 32] = [
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x14, 0xde, 0xf9, 0xde, 0xa2, 0xf7, 0x9c, 0xd6, 0x58, 0x12, 0x63, 0x1a, 0x5c, 0xf5, 0xd3, 0xed,
];

/// Error returned when note blinding or unblinding inputs are invalid.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlindingError {
    /// The viewing public key bytes are not a valid ed25519 point.
    InvalidViewingPublicKey,
    /// The blinded viewing public key bytes are not a valid ed25519 point.
    InvalidBlindedViewingPublicKey,
}

impl fmt::Display for BlindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidViewingPublicKey => formatter.write_str("invalid viewing public key"),
            Self::InvalidBlindedViewingPublicKey => {
                formatter.write_str("invalid blinded viewing public key")
            }
        }
    }
}

impl std::error::Error for BlindingError {}

fn build_blinding_seed(shared_random: &SharedRandom, sender_random: &SenderRandom) -> [u8; 32] {
    let mut shared = [0_u8; 32];
    shared[16..].copy_from_slice(shared_random.as_bytes());

    let mut sender = [0_u8; 32];
    // Upstream places the 15-byte sender random one byte later than the shared
    // random so both values preserve their canonical big-endian alignment.
    sender[17..].copy_from_slice(sender_random.as_bytes());

    core::array::from_fn(|index| shared[index] ^ sender[index])
}

fn seed_to_scalar(seed: &[u8; 32]) -> Scalar {
    // Note blinding uses the upstream seed-to-scalar reduction, which differs
    // from the ed25519 private-scalar clamping used for shared-key derivation.
    let digest = Sha512::digest(seed);
    let group_order = BigUint::from_bytes_be(&ED25519_GROUP_ORDER_BYTES);
    let mut scalar = BigUint::from_bytes_be(&digest) % group_order;
    if scalar == BigUint::from(0_u8) {
        scalar = BigUint::from(1_u8);
    }

    let scalar_bytes = scalar.to_bytes_le();
    let mut little_endian = [0_u8; 32];
    little_endian[..scalar_bytes.len()].copy_from_slice(&scalar_bytes);
    Scalar::from_bytes_mod_order(little_endian)
}

fn blinding_scalar(shared_random: &SharedRandom, sender_random: &SenderRandom) -> Scalar {
    seed_to_scalar(&build_blinding_seed(shared_random, sender_random))
}

/// Derives the canonical blinded sender and receiver viewing public keys.
///
/// # Errors
///
/// Returns an error if either viewing public key does not decode to a valid
/// ed25519 point.
pub fn derive_note_blinding_keys(
    sender_viewing_public_key: &ViewingPublicKey,
    receiver_viewing_public_key: &ViewingPublicKey,
    shared_random: &SharedRandom,
    sender_random: &SenderRandom,
) -> Result<(BlindedViewingPublicKey, BlindedViewingPublicKey), BlindingError> {
    let scalar = blinding_scalar(shared_random, sender_random);
    let sender_point = CompressedEdwardsY(*sender_viewing_public_key.as_bytes())
        .decompress()
        .ok_or(BlindingError::InvalidViewingPublicKey)?;
    let receiver_point = CompressedEdwardsY(*receiver_viewing_public_key.as_bytes())
        .decompress()
        .ok_or(BlindingError::InvalidViewingPublicKey)?;

    Ok((
        BlindedViewingPublicKey::new((sender_point * scalar).compress().to_bytes()),
        BlindedViewingPublicKey::new((receiver_point * scalar).compress().to_bytes()),
    ))
}

/// Unblinds a blinded viewing key back into the original viewing public key.
///
/// # Errors
///
/// Returns an error if `blinded_viewing_key` does not decode to a valid ed25519
/// point.
pub fn unblind_note_key(
    blinded_viewing_key: &BlindedViewingPublicKey,
    shared_random: &SharedRandom,
    sender_random: &SenderRandom,
) -> Result<ViewingPublicKey, BlindingError> {
    let point = CompressedEdwardsY(*blinded_viewing_key.as_bytes())
        .decompress()
        .ok_or(BlindingError::InvalidBlindedViewingPublicKey)?;
    let inverse = blinding_scalar(shared_random, sender_random).invert();

    Ok(ViewingPublicKey::new((point * inverse).compress().to_bytes()))
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::edwards::CompressedEdwardsY;
    use num_bigint::BigUint;
    use railgun_types::{BlindedViewingPublicKey, SenderRandom, SharedRandom, ViewingPrivateKey};

    use super::{
        BlindingError, ED25519_GROUP_ORDER_BYTES, build_blinding_seed, derive_note_blinding_keys,
        unblind_note_key,
    };
    use crate::{derive_shared_symmetric_key, derive_viewing_public_key};

    const ED25519_GROUP_ORDER_OFFSET_DECIMAL: &str = "27742317777372353535851937790883648493";

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
            bytes[index] = ((high << 4) | low) as u8;
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

    fn ed25519_group_order_from_formula() -> BigUint {
        let parsed_offset = BigUint::parse_bytes(ED25519_GROUP_ORDER_OFFSET_DECIMAL.as_bytes(), 10)
            .unwrap_or_else(|| panic!("ed25519 group order offset decimal should parse"));
        // The Ed25519 subgroup order is l = 2^252 + 27742317777372353535851937790883648493.
        // In code, `(BigUint::from(1_u8) << 252_u32)` computes the `2^252` term,
        // and `parsed_offset` is the decimal offset term added to it.
        (BigUint::from(1_u8) << 252_u32) + parsed_offset
    }

    #[test]
    fn ed25519_group_order_formula_matches_bytes() {
        assert_eq!(ed25519_group_order_from_formula().to_bytes_be(), ED25519_GROUP_ORDER_BYTES);
    }

    #[test]
    fn ed25519_group_order_little_endian_bytes_match_canonical_encoding() {
        let little_endian = ed25519_group_order_from_formula().to_bytes_le();

        assert_eq!(
            little_endian,
            vec![
                0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
                0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x10,
            ]
        );
    }

    #[test]
    fn blinding_seed_uses_canonical_random_byte_layout() {
        let shared_random = SharedRandom::new([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ]);
        let sender_random = SenderRandom::new([
            0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae,
            0xaf,
        ]);

        assert_eq!(
            build_blinding_seed(&shared_random, &sender_random),
            [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x01, 0xa3, 0xa1, 0xa7, 0xa1, 0xa3, 0xa1, 0xaf, 0xa1, 0xa3, 0xa1, 0xa7,
                0xa1, 0xa3, 0xa1, 0xbf,
            ]
        );
    }

    #[test]
    fn null_sender_random_round_trips_sender_and_receiver_keys() {
        let sender = ViewingPrivateKey::new(decode_hex(
            "67d7d19d00e6e3b3517fe68ac46505dd207df6e8fe3aa06ba3face352e7599ef",
        ));
        let receiver = ViewingPrivateKey::new(decode_hex(
            "3428cfc939320328501174a4e76e869197ffc894b58dbf4d0e953c484d66cb5e",
        ));
        let shared_random = SharedRandom::new(decode_hex("85b08a7cd73ee433072f1d410aeb4801"));
        let sender_random = SenderRandom::null_sentinel();
        let sender_public_key = derive_viewing_public_key(&sender);
        let receiver_public_key = derive_viewing_public_key(&receiver);

        let (blinded_sender_key, blinded_receiver_key) = derive_note_blinding_keys(
            &sender_public_key,
            &receiver_public_key,
            &shared_random,
            &sender_random,
        )
        .unwrap_or_else(|error| panic!("blinding should succeed: {error}"));

        let unblinded_sender =
            unblind_note_key(&blinded_sender_key, &shared_random, &sender_random)
                .unwrap_or_else(|error| panic!("sender unblinding should succeed: {error}"));
        let unblinded_receiver =
            unblind_note_key(&blinded_receiver_key, &shared_random, &sender_random)
                .unwrap_or_else(|error| panic!("receiver unblinding should succeed: {error}"));

        assert_eq!(unblinded_sender, sender_public_key);
        assert_eq!(unblinded_receiver, receiver_public_key);
    }

    #[test]
    fn non_null_sender_random_requires_matching_unblinding_input() {
        let sender = ViewingPrivateKey::new(decode_hex(
            "67d7d19d00e6e3b3517fe68ac46505dd207df6e8fe3aa06ba3face352e7599ef",
        ));
        let receiver = ViewingPrivateKey::new(decode_hex(
            "3428cfc939320328501174a4e76e869197ffc894b58dbf4d0e953c484d66cb5e",
        ));
        let shared_random = SharedRandom::new(decode_hex("85b08a7cd73ee433072f1d410aeb4801"));
        let sender_random = SenderRandom::new(decode_hex("86727859e3fe7c0d81e27dfafaf0d9"));
        let sender_public_key = derive_viewing_public_key(&sender);
        let receiver_public_key = derive_viewing_public_key(&receiver);

        let (blinded_sender_key, blinded_receiver_key) = derive_note_blinding_keys(
            &sender_public_key,
            &receiver_public_key,
            &shared_random,
            &sender_random,
        )
        .unwrap_or_else(|error| panic!("blinding should succeed: {error}"));

        assert_eq!(
            unblind_note_key(&blinded_sender_key, &shared_random, &sender_random)
                .unwrap_or_else(|error| panic!("sender unblinding should succeed: {error}")),
            sender_public_key
        );
        assert_eq!(
            unblind_note_key(&blinded_receiver_key, &shared_random, &sender_random)
                .unwrap_or_else(|error| panic!("receiver unblinding should succeed: {error}")),
            receiver_public_key
        );

        assert_ne!(
            unblind_note_key(&blinded_sender_key, &shared_random, &SenderRandom::null_sentinel())
                .unwrap_or_else(|error| panic!(
                    "wrong sender random still yields a point: {error}"
                )),
            sender_public_key
        );
        assert_ne!(
            unblind_note_key(
                &blinded_receiver_key,
                &shared_random,
                &SenderRandom::null_sentinel(),
            )
            .unwrap_or_else(|error| panic!("wrong sender random still yields a point: {error}")),
            receiver_public_key
        );
    }

    #[test]
    fn blinded_keys_preserve_sender_receiver_shared_key_symmetry() {
        let sender = ViewingPrivateKey::new(decode_hex(
            "67d7d19d00e6e3b3517fe68ac46505dd207df6e8fe3aa06ba3face352e7599ef",
        ));
        let receiver = ViewingPrivateKey::new(decode_hex(
            "3428cfc939320328501174a4e76e869197ffc894b58dbf4d0e953c484d66cb5e",
        ));
        let shared_random = SharedRandom::new(decode_hex("85b08a7cd73ee433072f1d410aeb4801"));
        let sender_random = SenderRandom::new(decode_hex("86727859e3fe7c0d81e27dfafaf0d9"));
        let sender_public_key = derive_viewing_public_key(&sender);
        let receiver_public_key = derive_viewing_public_key(&receiver);

        let (blinded_sender_key, blinded_receiver_key) = derive_note_blinding_keys(
            &sender_public_key,
            &receiver_public_key,
            &shared_random,
            &sender_random,
        )
        .unwrap_or_else(|error| panic!("blinding should succeed: {error}"));

        let receiver_shared_key = derive_shared_symmetric_key(&receiver, &blinded_sender_key)
            .unwrap_or_else(|error| panic!("receiver shared key should derive: {error}"));
        let sender_shared_key = derive_shared_symmetric_key(&sender, &blinded_receiver_key)
            .unwrap_or_else(|error| panic!("sender shared key should derive: {error}"));

        assert_eq!(receiver_shared_key, sender_shared_key);
    }

    #[test]
    fn rejects_invalid_blinded_viewing_key_during_unblinding() {
        let blinded_viewing_key = BlindedViewingPublicKey::new(invalid_blinded_public_key_bytes());
        let shared_random = SharedRandom::new([7_u8; 16]);
        let sender_random = SenderRandom::null_sentinel();

        let Err(error) = unblind_note_key(&blinded_viewing_key, &shared_random, &sender_random)
        else {
            panic!("invalid blinded viewing key should fail");
        };

        assert_eq!(error, BlindingError::InvalidBlindedViewingPublicKey);
    }
}
