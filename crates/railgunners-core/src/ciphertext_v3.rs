//! Canonical Railgun V3 note ciphertext encoding and XChaCha20-Poly1305 encryption.

use core::fmt;

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{AeadInPlace, KeyInit, OsRng, rand_core::RngCore},
};
use railgunners_types::{
    MasterPublicKey, NoteRandom, NoteValue, SenderRandom, SharedSymmetricKey, TokenHash,
    V3CiphertextBundle, V3Plaintext, V3StoredNonce,
};
use sha2::{Digest, Sha256};

const STORED_NONCE_LENGTH: usize = V3StoredNonce::LENGTH;
const DERIVED_NONCE_LENGTH: usize = 24;
const FIXED_PLAINTEXT_LENGTH: usize = 111;

/// Error returned when V3 ciphertext encoding or decoding fails.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum V3CiphertextError {
    /// The plaintext is shorter than the canonical fixed-width V3 layout.
    InvalidPlaintextLength(usize),
    /// XChaCha20-Poly1305 encryption failed unexpectedly.
    EncryptFailed,
    /// XChaCha20-Poly1305 decryption/authentication failed.
    AuthenticationFailed,
}

impl fmt::Display for V3CiphertextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPlaintextLength(length) => {
                write!(
                    formatter,
                    "invalid v3 plaintext length: expected at least 111 bytes, got {length}"
                )
            }
            Self::EncryptFailed => formatter.write_str("failed to encrypt v3 ciphertext"),
            Self::AuthenticationFailed => {
                formatter.write_str("failed to authenticate v3 ciphertext")
            }
        }
    }
}

impl std::error::Error for V3CiphertextError {}

// Railgun V3 stores a 16-byte nonce on the wire, then expands it into the 24-byte
// XChaCha nonce with SHA-256 immediately before cipher initialization.
fn derive_cipher_nonce(stored_nonce: &V3StoredNonce) -> [u8; DERIVED_NONCE_LENGTH] {
    let digest = Sha256::digest(stored_nonce.as_bytes());
    let mut nonce = [0_u8; DERIVED_NONCE_LENGTH];
    nonce.copy_from_slice(&digest[..DERIVED_NONCE_LENGTH]);
    nonce
}

fn encrypt_v3_bytes_with_nonce(
    plaintext: &[u8],
    shared_key: &SharedSymmetricKey,
    nonce: &V3StoredNonce,
) -> Result<Vec<u8>, V3CiphertextError> {
    let cipher = XChaCha20Poly1305::new_from_slice(shared_key.as_bytes())
        .map_err(|_| V3CiphertextError::EncryptFailed)?;
    let derived_nonce = derive_cipher_nonce(nonce);
    let mut encrypted = plaintext.to_vec();
    cipher
        .encrypt_in_place(XNonce::from_slice(&derived_nonce), b"", &mut encrypted)
        .map_err(|_| V3CiphertextError::EncryptFailed)?;
    Ok(encrypted)
}

fn encrypt_v3_ciphertext_with_nonce(
    plaintext: &V3Plaintext,
    shared_key: &SharedSymmetricKey,
    sender_ciphertext: Vec<u8>,
    nonce: V3StoredNonce,
) -> Result<V3CiphertextBundle, V3CiphertextError> {
    let encrypted =
        encrypt_v3_bytes_with_nonce(&encode_v3_plaintext(plaintext), shared_key, &nonce)?;

    Ok(V3CiphertextBundle::new(nonce, encrypted, sender_ciphertext))
}

/// Encodes a V3 plaintext payload into canonical bytes.
#[must_use]
pub fn encode_v3_plaintext(plaintext: &V3Plaintext) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(FIXED_PLAINTEXT_LENGTH + plaintext.memo().len());
    encoded.extend_from_slice(&plaintext.encoded_master_public_key().to_be_bytes());
    encoded.extend_from_slice(plaintext.random().as_bytes());
    encoded.extend_from_slice(&plaintext.value().to_be_bytes());
    encoded.extend_from_slice(plaintext.token_hash().as_bytes());
    encoded.extend_from_slice(plaintext.sender_random().as_bytes());
    encoded.extend_from_slice(plaintext.memo());
    encoded
}

/// Decodes canonical V3 plaintext bytes.
///
/// # Errors
///
/// Returns an error if `bytes` is shorter than the fixed-width V3 plaintext.
pub fn decode_v3_plaintext(bytes: &[u8]) -> Result<V3Plaintext, V3CiphertextError> {
    if bytes.len() < FIXED_PLAINTEXT_LENGTH {
        return Err(V3CiphertextError::InvalidPlaintextLength(bytes.len()));
    }

    let encoded_master_public_key =
        MasterPublicKey::new(num_bigint::BigUint::from_bytes_be(&bytes[..32]))
            .map_err(|_| V3CiphertextError::InvalidPlaintextLength(bytes.len()))?;
    let random = NoteRandom::from_slice(&bytes[32..48])
        .map_err(|_| V3CiphertextError::InvalidPlaintextLength(bytes.len()))?;
    let value = NoteValue::from_slice(&bytes[48..64])
        .map_err(|_| V3CiphertextError::InvalidPlaintextLength(bytes.len()))?;
    let token_hash = TokenHash::from_slice(&bytes[64..96])
        .map_err(|_| V3CiphertextError::InvalidPlaintextLength(bytes.len()))?;
    let sender_random = SenderRandom::from_slice(&bytes[96..111])
        .map_err(|_| V3CiphertextError::InvalidPlaintextLength(bytes.len()))?;
    let memo = bytes[FIXED_PLAINTEXT_LENGTH..].to_vec();

    Ok(V3Plaintext::new(encoded_master_public_key, random, value, token_hash, sender_random, memo))
}

/// Encrypts a canonical V3 plaintext into the `nonce | bundle` V3 ciphertext layout.
///
/// # Errors
///
/// Returns an error if XChaCha20-Poly1305 encryption fails unexpectedly.
pub fn encrypt_v3_ciphertext(
    plaintext: &V3Plaintext,
    shared_key: &SharedSymmetricKey,
    sender_ciphertext: Vec<u8>,
) -> Result<V3CiphertextBundle, V3CiphertextError> {
    let mut nonce = [0_u8; STORED_NONCE_LENGTH];
    OsRng.fill_bytes(&mut nonce);
    encrypt_v3_ciphertext_with_nonce(
        plaintext,
        shared_key,
        sender_ciphertext,
        V3StoredNonce::new(nonce),
    )
}

/// Decrypts a V3 ciphertext bundle back into its canonical plaintext.
///
/// # Errors
///
/// Returns an error if XChaCha20-Poly1305 authentication fails.
pub fn decrypt_v3_ciphertext(
    bundle: &V3CiphertextBundle,
    shared_key: &SharedSymmetricKey,
) -> Result<V3Plaintext, V3CiphertextError> {
    let cipher = XChaCha20Poly1305::new_from_slice(shared_key.as_bytes())
        .map_err(|_| V3CiphertextError::AuthenticationFailed)?;
    let derived_nonce = derive_cipher_nonce(bundle.nonce());
    let mut encrypted = bundle.bundle().to_vec();

    cipher
        .decrypt_in_place(XNonce::from_slice(&derived_nonce), b"", &mut encrypted)
        .map_err(|_| V3CiphertextError::AuthenticationFailed)?;
    decode_v3_plaintext(&encrypted)
}

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;
    use railgunners_types::{
        MasterPublicKey, NoteRandom, NoteValue, SenderRandom, SharedSymmetricKey, TokenHash,
        V3Plaintext, V3StoredNonce,
    };

    use super::{
        DERIVED_NONCE_LENGTH, FIXED_PLAINTEXT_LENGTH, V3CiphertextError, decode_v3_plaintext,
        decrypt_v3_ciphertext, derive_cipher_nonce, encode_v3_plaintext,
        encrypt_v3_bytes_with_nonce, encrypt_v3_ciphertext_with_nonce,
    };

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

    fn plaintext_fixture(memo: Vec<u8>) -> V3Plaintext {
        V3Plaintext::new(
            MasterPublicKey::new(BigUint::from_bytes_be(&decode_hex::<32>(
                "6595f9a971c7471695948a445aedcbb9d624a325dbe68c228dea25eccf61919d",
            )))
            .unwrap_or_else(|_| panic!("master public key should be valid")),
            NoteRandom::new(decode_hex("85b08a7cd73ee433072f1d410aeb4801")),
            NoteValue::new(0x086a_a1ad_e61c_cb53),
            TokenHash::new(decode_hex(
                "0000000000000000000000007f4925cdf66ddf5b88016df1fe915e68eff8f192",
            )),
            SenderRandom::new(decode_hex("222222222222222222222222222222")),
            memo,
        )
    }

    #[test]
    fn encodes_v3_plaintext_in_canonical_order() {
        let plaintext = plaintext_fixture(vec![0xaa, 0xbb, 0xcc]);

        let encoded = encode_v3_plaintext(&plaintext);

        assert_eq!(&encoded[..32], plaintext.encoded_master_public_key().to_be_bytes());
        assert_eq!(&encoded[32..48], plaintext.random().as_bytes());
        assert_eq!(&encoded[48..64], &plaintext.value().to_be_bytes());
        assert_eq!(&encoded[64..96], plaintext.token_hash().as_bytes());
        assert_eq!(&encoded[96..111], plaintext.sender_random().as_bytes());
        assert_eq!(&encoded[111..], plaintext.memo());
    }

    #[test]
    fn decodes_v3_plaintext_with_empty_memo() {
        let plaintext = plaintext_fixture(Vec::new());

        let decoded = decode_v3_plaintext(&encode_v3_plaintext(&plaintext))
            .unwrap_or_else(|_| panic!("v3 plaintext should decode"));

        assert_eq!(decoded, plaintext);
    }

    #[test]
    fn rejects_short_v3_plaintext() {
        let Err(error) = decode_v3_plaintext(&[0_u8; FIXED_PLAINTEXT_LENGTH - 1]) else {
            panic!("short v3 plaintext should fail");
        };

        assert_eq!(error, V3CiphertextError::InvalidPlaintextLength(FIXED_PLAINTEXT_LENGTH - 1));
    }

    #[test]
    fn derives_24_byte_cipher_nonce_from_16_byte_stored_nonce() {
        let stored_nonce = V3StoredNonce::new(decode_hex("000102030405060708090a0b0c0d0e0f"));

        let derived = derive_cipher_nonce(&stored_nonce);

        assert_eq!(derived.len(), DERIVED_NONCE_LENGTH);
        assert_eq!(derived, decode_hex("be45cb2605bf36bebde684841a28f0fd43c69850a3dce5fe"));
    }

    #[test]
    fn round_trips_v3_ciphertext_with_memo() {
        let plaintext = plaintext_fixture(b"railgun-v3".to_vec());
        let key = SharedSymmetricKey::new([0x11_u8; 32]);
        let nonce = V3StoredNonce::new([0x22_u8; 16]);

        let encrypted = encrypt_v3_ciphertext_with_nonce(&plaintext, &key, vec![0xaa, 0xbb], nonce)
            .unwrap_or_else(|_| panic!("v3 encryption should succeed"));
        let decrypted = decrypt_v3_ciphertext(&encrypted, &key)
            .unwrap_or_else(|_| panic!("v3 decryption should succeed"));

        assert_eq!(encrypted.sender_ciphertext(), &[0xaa, 0xbb]);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn rejects_tampered_v3_ciphertext_bundle() {
        let plaintext = plaintext_fixture(b"railgun-v3".to_vec());
        let key = SharedSymmetricKey::new([0x11_u8; 32]);
        let nonce = V3StoredNonce::new([0x22_u8; 16]);

        let encrypted = encrypt_v3_ciphertext_with_nonce(&plaintext, &key, Vec::new(), nonce)
            .unwrap_or_else(|_| panic!("v3 encryption should succeed"));
        let mut tampered_bundle = encrypted.bundle().to_vec();
        tampered_bundle[0] ^= 0x80;
        let tampered = railgunners_types::V3CiphertextBundle::new(
            *encrypted.nonce(),
            tampered_bundle,
            encrypted.sender_ciphertext().to_vec(),
        );

        let Err(error) = decrypt_v3_ciphertext(&tampered, &key) else {
            panic!("tampered v3 ciphertext should fail");
        };

        assert_eq!(error, V3CiphertextError::AuthenticationFailed);
    }

    #[test]
    fn matches_constructed_v3_cipher_vector() {
        let key = SharedSymmetricKey::new(decode_hex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        ));
        let nonce = V3StoredNonce::new(decode_hex("000102030405060708090a0b0c0d0e0f"));
        let plaintext = decode_hex::<16>("00112233445566778899aabbccddeeff");

        let encrypted = encrypt_v3_bytes_with_nonce(&plaintext, &key, &nonce)
            .unwrap_or_else(|_| panic!("constructed v3 vector should encrypt"));

        assert_eq!(
            encrypted,
            decode_hex::<32>("d0e2e01b52e542f34142d60039f366dcf5dcbcc16af6c28ed756f232f3b2e302",)
        );
    }
}
