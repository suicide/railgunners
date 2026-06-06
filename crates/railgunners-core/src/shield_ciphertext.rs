//! Parsing helpers and random decryption for shield ciphertexts.

use core::fmt;

use aes_gcm::{
    AesGcm,
    aead::{AeadInPlace, KeyInit, generic_array::GenericArray},
    aes::Aes256,
};
use curve25519_dalek::{edwards::CompressedEdwardsY, scalar::Scalar};
use railgunners_types::{
    NoteRandom, SharedSymmetricKey, ShieldCiphertext, ShieldCiphertextBlock, ViewingPrivateKey,
    ViewingPublicKey,
};
use sha2::{Digest, Sha256, Sha512};

type Aes256Gcm16 = AesGcm<Aes256, aes_gcm::aead::consts::U16>;

const ENCRYPTED_BUNDLE_COUNT: usize = 3;
const IV_TAG_LENGTH: usize = 32;
const IV_LENGTH: usize = 16;
const TAG_LENGTH: usize = 16;
const ENCRYPTED_RANDOM_LENGTH: usize = 16;

/// Error returned when shield ciphertext parsing or random decryption fails.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ShieldCiphertextError {
    /// Shield ciphertext must contain exactly three serialized bundle elements.
    InvalidEncryptedBundleLength(usize),
    /// Shield key was not a valid 32-byte viewing public key.
    InvalidShieldKey,
    /// The first bundle element must contain a packed `iv | tag` block.
    InvalidIvTagLength(usize),
    /// The second bundle element must begin with a 16-byte encrypted random chunk.
    InvalidEncryptedRandomChunkLength(usize),
    /// Shared-key derivation failed because the shield key was not a valid ed25519 point.
    SharedKeyDerivationFailed,
    /// AES-GCM authentication failed while decrypting the shield random.
    AuthenticationFailed,
    /// The decrypted shield random was not the canonical 16-byte note random.
    InvalidRandomLength(usize),
}

impl fmt::Display for ShieldCiphertextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEncryptedBundleLength(length) => write!(
                formatter,
                "invalid shield encrypted bundle length: expected 3, got {length}"
            ),
            Self::InvalidShieldKey => formatter.write_str("invalid shield key"),
            Self::InvalidIvTagLength(length) => {
                write!(formatter, "invalid shield iv|tag length: expected 32 bytes, got {length}")
            }
            Self::InvalidEncryptedRandomChunkLength(length) => write!(
                formatter,
                "invalid shield encrypted random chunk length: expected at least 16 bytes, got {length}"
            ),
            Self::SharedKeyDerivationFailed => {
                formatter.write_str("failed to derive shared key for shield ciphertext")
            }
            Self::AuthenticationFailed => {
                formatter.write_str("failed to authenticate shield ciphertext")
            }
            Self::InvalidRandomLength(length) => {
                write!(formatter, "invalid shield random length: expected 16 bytes, got {length}")
            }
        }
    }
}

impl std::error::Error for ShieldCiphertextError {}

fn ed25519_private_scalar(viewing_private_key: &ViewingPrivateKey) -> Scalar {
    let hash = Sha512::digest(viewing_private_key.as_bytes());
    let mut head = [0_u8; 32];
    head.copy_from_slice(&hash[..32]);
    head[0] &= 0b1111_1000;
    head[31] &= 0b0111_1111;
    head[31] |= 0b0100_0000;
    Scalar::from_bytes_mod_order(head)
}

fn derive_shield_shared_symmetric_key(
    viewing_private_key: &ViewingPrivateKey,
    shield_key: &ViewingPublicKey,
) -> Result<SharedSymmetricKey, ShieldCiphertextError> {
    let point = CompressedEdwardsY(*shield_key.as_bytes())
        .decompress()
        .ok_or(ShieldCiphertextError::SharedKeyDerivationFailed)?;
    let shared_point = (point * ed25519_private_scalar(viewing_private_key)).compress().to_bytes();
    let digest = Sha256::digest(shared_point);
    let mut shared_key = [0_u8; SharedSymmetricKey::LENGTH];
    shared_key.copy_from_slice(&digest[..SharedSymmetricKey::LENGTH]);
    Ok(SharedSymmetricKey::new(shared_key))
}

/// Parses a decoded shield ciphertext payload into the canonical internal model.
///
/// # Errors
///
/// Returns an error if the bundle does not contain exactly three elements or if the shield key is malformed.
pub fn parse_shield_ciphertext(
    encrypted_bundle: &[&[u8]],
    shield_key: &[u8],
) -> Result<ShieldCiphertext, ShieldCiphertextError> {
    if encrypted_bundle.len() != ENCRYPTED_BUNDLE_COUNT {
        return Err(ShieldCiphertextError::InvalidEncryptedBundleLength(encrypted_bundle.len()));
    }

    let shield_key = ViewingPublicKey::from_slice(shield_key)
        .map_err(|_| ShieldCiphertextError::InvalidShieldKey)?;

    Ok(ShieldCiphertext::new(
        [
            ShieldCiphertextBlock::new(encrypted_bundle[0].to_vec()),
            ShieldCiphertextBlock::new(encrypted_bundle[1].to_vec()),
            ShieldCiphertextBlock::new(encrypted_bundle[2].to_vec()),
        ],
        shield_key,
    ))
}

/// Decrypts the 16-byte shield random from a parsed shield ciphertext.
///
/// # Errors
///
/// Returns an error if shared-key derivation fails, authentication fails, or the decrypted random is malformed.
pub fn decrypt_shield_random(
    ciphertext: &ShieldCiphertext,
    viewing_private_key: &ViewingPrivateKey,
) -> Result<NoteRandom, ShieldCiphertextError> {
    let encrypted_bundle = ciphertext.encrypted_bundle();
    let iv_tag = encrypted_bundle[0].as_bytes();
    if iv_tag.len() != IV_TAG_LENGTH {
        return Err(ShieldCiphertextError::InvalidIvTagLength(iv_tag.len()));
    }

    let encrypted_random_and_ctr_iv = encrypted_bundle[1].as_bytes();
    if encrypted_random_and_ctr_iv.len() < ENCRYPTED_RANDOM_LENGTH {
        return Err(ShieldCiphertextError::InvalidEncryptedRandomChunkLength(
            encrypted_random_and_ctr_iv.len(),
        ));
    }

    let shared_key =
        derive_shield_shared_symmetric_key(viewing_private_key, ciphertext.shield_key())?;
    let cipher = Aes256Gcm16::new_from_slice(shared_key.as_bytes())
        .map_err(|_| ShieldCiphertextError::AuthenticationFailed)?;
    let mut decrypted_random = encrypted_random_and_ctr_iv[..ENCRYPTED_RANDOM_LENGTH].to_vec();

    // `encryptedBundle[1]` is a mixed field: the first 16 bytes are the encrypted
    // random chunk and the remaining bytes carry the CTR IV for receiver key material.
    cipher
        .decrypt_in_place_detached(
            GenericArray::from_slice(&iv_tag[..IV_LENGTH]),
            b"",
            &mut decrypted_random,
            GenericArray::from_slice(&iv_tag[IV_LENGTH..IV_LENGTH + TAG_LENGTH]),
        )
        .map_err(|_| ShieldCiphertextError::AuthenticationFailed)?;

    // Shield-random recovery intentionally ignores the trailing CTR IV bytes in
    // `encryptedBundle[1]` and all of `encryptedBundle[2]`; those belong to the
    // separately encrypted receiver viewing key material.
    NoteRandom::from_slice(&decrypted_random)
        .map_err(|_| ShieldCiphertextError::InvalidRandomLength(decrypted_random.len()))
}

#[cfg(test)]
mod tests {
    use aes_gcm::{
        AesGcm,
        aead::{AeadInPlace, KeyInit, generic_array::GenericArray},
        aes::Aes256,
    };

    use super::{ShieldCiphertextError, decrypt_shield_random, parse_shield_ciphertext};
    use crate::derive_viewing_public_key;
    use railgunners_types::{NoteRandom, ShieldCiphertext, ViewingPrivateKey};

    type Aes256Gcm16 = AesGcm<Aes256, aes_gcm::aead::consts::U16>;

    fn encrypt_shield_random_fixture(
        viewing_private_key: &ViewingPrivateKey,
        shield_private_key: &ViewingPrivateKey,
        random: &NoteRandom,
    ) -> ShieldCiphertext {
        let shield_key = derive_viewing_public_key(shield_private_key);
        let shared_key =
            super::derive_shield_shared_symmetric_key(viewing_private_key, &shield_key)
                .unwrap_or_else(|_| panic!("shield shared key should derive"));
        let cipher = Aes256Gcm16::new_from_slice(shared_key.as_bytes())
            .unwrap_or_else(|_| panic!("aes-gcm should initialize"));
        let iv = [0x11_u8; 16];
        let mut encrypted_random = random.as_bytes().to_vec();
        let tag = cipher
            .encrypt_in_place_detached(GenericArray::from_slice(&iv), b"", &mut encrypted_random)
            .unwrap_or_else(|_| panic!("shield random encryption should succeed"));

        let mut iv_tag = Vec::with_capacity(32);
        iv_tag.extend_from_slice(&iv);
        iv_tag.extend_from_slice(tag.as_slice());

        let mut encrypted_random_with_ctr_iv = encrypted_random;
        encrypted_random_with_ctr_iv.extend_from_slice(&[0x22_u8; 16]);

        parse_shield_ciphertext(
            &[iv_tag.as_slice(), encrypted_random_with_ctr_iv.as_slice(), &[0x33_u8; 32]],
            shield_key.as_bytes(),
        )
        .unwrap_or_else(|_| panic!("fixture shield ciphertext should parse"))
    }

    #[test]
    fn parses_shield_ciphertext_and_preserves_layout() {
        let bundle0 = [1_u8; 32];
        let bundle1 = [2_u8; 32];
        let bundle2 = [3_u8; 16];

        let parsed = parse_shield_ciphertext(
            &[bundle0.as_slice(), bundle1.as_slice(), bundle2.as_slice()],
            &[4_u8; 32],
        )
        .unwrap_or_else(|_| panic!("shield ciphertext should parse"));

        assert_eq!(parsed.encrypted_bundle()[0].as_bytes(), &bundle0);
        assert_eq!(parsed.encrypted_bundle()[1].as_bytes(), &bundle1);
        assert_eq!(parsed.encrypted_bundle()[2].as_bytes(), &bundle2);
        assert_eq!(parsed.shield_key().as_bytes(), &[4_u8; 32]);
    }

    #[test]
    fn rejects_wrong_shield_bundle_length() {
        let Err(error) = parse_shield_ciphertext(&[&[1_u8; 32], &[2_u8; 32]], &[4_u8; 32]) else {
            panic!("short shield bundle should fail");
        };

        assert_eq!(error, ShieldCiphertextError::InvalidEncryptedBundleLength(2));
    }

    #[test]
    fn rejects_invalid_shield_key_length() {
        let Err(error) =
            parse_shield_ciphertext(&[&[1_u8; 32], &[2_u8; 32], &[3_u8; 16]], &[4_u8; 31])
        else {
            panic!("invalid shield key should fail");
        };

        assert_eq!(error, ShieldCiphertextError::InvalidShieldKey);
    }

    #[test]
    fn decrypts_shield_random_with_shared_key_flow() {
        let viewing_private_key = ViewingPrivateKey::new([7_u8; 32]);
        let shield_private_key = ViewingPrivateKey::new([8_u8; 32]);
        let random = NoteRandom::new([9_u8; 16]);
        let ciphertext =
            encrypt_shield_random_fixture(&viewing_private_key, &shield_private_key, &random);

        let decrypted = decrypt_shield_random(&ciphertext, &viewing_private_key)
            .unwrap_or_else(|_| panic!("shield random decryption should succeed"));

        assert_eq!(decrypted, random);
    }

    #[test]
    fn rejects_tampered_shield_ciphertext() {
        let viewing_private_key = ViewingPrivateKey::new([7_u8; 32]);
        let shield_private_key = ViewingPrivateKey::new([8_u8; 32]);
        let random = NoteRandom::new([9_u8; 16]);
        let ciphertext =
            encrypt_shield_random_fixture(&viewing_private_key, &shield_private_key, &random);

        let mut tampered_bundle0 = ciphertext.encrypted_bundle()[0].as_bytes().to_vec();
        tampered_bundle0[31] ^= 0x01;
        let tampered = parse_shield_ciphertext(
            &[
                tampered_bundle0.as_slice(),
                ciphertext.encrypted_bundle()[1].as_bytes(),
                ciphertext.encrypted_bundle()[2].as_bytes(),
            ],
            ciphertext.shield_key().as_bytes(),
        )
        .unwrap_or_else(|_| panic!("tampered shield ciphertext should still parse"));

        let Err(error) = decrypt_shield_random(&tampered, &viewing_private_key) else {
            panic!("tampered shield ciphertext should fail authentication");
        };

        assert_eq!(error, ShieldCiphertextError::AuthenticationFailed);
    }

    #[test]
    fn rejects_short_encrypted_random_chunk() {
        let parsed = parse_shield_ciphertext(&[&[1_u8; 32], &[2_u8; 15], &[3_u8; 16]], &[4_u8; 32])
            .unwrap_or_else(|_| panic!("shield ciphertext should parse structurally"));

        let Err(error) = decrypt_shield_random(&parsed, &ViewingPrivateKey::new([7_u8; 32])) else {
            panic!("short encrypted random chunk should fail");
        };

        assert_eq!(error, ShieldCiphertextError::InvalidEncryptedRandomChunkLength(15));
    }
}
