//! Canonical Railgun V2 note ciphertext encoding and AES-256-GCM encryption.

use core::fmt;

use aes_gcm::{
    AesGcm,
    aead::{AeadInPlace, KeyInit, OsRng, generic_array::GenericArray, rand_core::RngCore},
    aes::Aes256,
};
use railgun_types::{
    MasterPublicKey, NoteRandom, NoteValue, SharedSymmetricKey, TokenHash, V2CiphertextBlock,
    V2CiphertextBundle, V2Plaintext,
};

type Aes256Gcm16 = AesGcm<Aes256, aes_gcm::aead::consts::U16>;

const IV_LENGTH: usize = 16;
const TAG_LENGTH: usize = 16;
const FIXED_PLAINTEXT_LENGTH: usize = 96;
const DATA_BLOCK_COUNT: usize = 3;

/// Error returned when V2 ciphertext encoding or decoding fails.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum V2CiphertextError {
    /// The plaintext is shorter than the canonical fixed-width V2 layout.
    InvalidPlaintextLength(usize),
    /// AES-GCM encryption failed unexpectedly.
    EncryptFailed,
    /// AES-GCM decryption/authentication failed.
    AuthenticationFailed,
}

impl fmt::Display for V2CiphertextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPlaintextLength(length) => {
                write!(
                    formatter,
                    "invalid v2 plaintext length: expected at least 96 bytes, got {length}"
                )
            }
            Self::EncryptFailed => formatter.write_str("failed to encrypt v2 ciphertext"),
            Self::AuthenticationFailed => {
                formatter.write_str("failed to authenticate v2 ciphertext")
            }
        }
    }
}

impl std::error::Error for V2CiphertextError {}

fn encrypt_v2_ciphertext_with_iv(
    plaintext: &V2Plaintext,
    shared_key: &SharedSymmetricKey,
    annotation_data: Vec<u8>,
    iv: [u8; IV_LENGTH],
) -> Result<V2CiphertextBundle, V2CiphertextError> {
    let cipher = Aes256Gcm16::new_from_slice(shared_key.as_bytes())
        .map_err(|_| V2CiphertextError::EncryptFailed)?;
    let mut encrypted = encode_v2_plaintext(plaintext);
    let tag = cipher
        .encrypt_in_place_detached(GenericArray::from_slice(&iv), b"", &mut encrypted)
        .map_err(|_| V2CiphertextError::EncryptFailed)?;

    let data: [V2CiphertextBlock; DATA_BLOCK_COUNT] = core::array::from_fn(|index| {
        let start = index * V2CiphertextBlock::LENGTH;
        let end = start + V2CiphertextBlock::LENGTH;
        let mut block = [0_u8; V2CiphertextBlock::LENGTH];
        block.copy_from_slice(&encrypted[start..end]);
        V2CiphertextBlock::new(block)
    });
    let memo = encrypted[FIXED_PLAINTEXT_LENGTH..].to_vec();

    let mut iv_tag = [0_u8; V2CiphertextBlock::LENGTH];
    iv_tag[..IV_LENGTH].copy_from_slice(&iv);
    iv_tag[IV_LENGTH..].copy_from_slice(tag.as_slice());

    Ok(V2CiphertextBundle::new(V2CiphertextBlock::new(iv_tag), data, annotation_data, memo))
}

/// Encodes a V2 plaintext payload into canonical bytes.
#[must_use]
pub fn encode_v2_plaintext(plaintext: &V2Plaintext) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(FIXED_PLAINTEXT_LENGTH + plaintext.memo().len());
    encoded.extend_from_slice(&plaintext.encoded_master_public_key().to_be_bytes());
    encoded.extend_from_slice(plaintext.token_hash().as_bytes());
    encoded.extend_from_slice(plaintext.random().as_bytes());
    encoded.extend_from_slice(&plaintext.value().to_be_bytes());
    encoded.extend_from_slice(plaintext.memo());
    encoded
}

/// Decodes canonical V2 plaintext bytes.
///
/// # Errors
///
/// Returns an error if `bytes` is shorter than the fixed-width V2 plaintext.
pub fn decode_v2_plaintext(bytes: &[u8]) -> Result<V2Plaintext, V2CiphertextError> {
    if bytes.len() < FIXED_PLAINTEXT_LENGTH {
        return Err(V2CiphertextError::InvalidPlaintextLength(bytes.len()));
    }

    let encoded_master_public_key =
        MasterPublicKey::new(num_bigint::BigUint::from_bytes_be(&bytes[..32]))
            .map_err(|_| V2CiphertextError::InvalidPlaintextLength(bytes.len()))?;
    let token_hash = TokenHash::from_slice(&bytes[32..64])
        .map_err(|_| V2CiphertextError::InvalidPlaintextLength(bytes.len()))?;
    let random = NoteRandom::from_slice(&bytes[64..80])
        .map_err(|_| V2CiphertextError::InvalidPlaintextLength(bytes.len()))?;
    let value = NoteValue::from_slice(&bytes[80..96])
        .map_err(|_| V2CiphertextError::InvalidPlaintextLength(bytes.len()))?;
    let memo = bytes[FIXED_PLAINTEXT_LENGTH..].to_vec();

    Ok(V2Plaintext::new(encoded_master_public_key, token_hash, random, value, memo))
}

/// Encrypts a canonical V2 plaintext into the detached V2 ciphertext layout.
///
/// # Errors
///
/// Returns an error if AES-GCM encryption fails unexpectedly.
pub fn encrypt_v2_ciphertext(
    plaintext: &V2Plaintext,
    shared_key: &SharedSymmetricKey,
    annotation_data: Vec<u8>,
) -> Result<V2CiphertextBundle, V2CiphertextError> {
    let mut iv = [0_u8; IV_LENGTH];
    OsRng.fill_bytes(&mut iv);
    encrypt_v2_ciphertext_with_iv(plaintext, shared_key, annotation_data, iv)
}

/// Decrypts a detached V2 ciphertext bundle back into its canonical plaintext.
///
/// # Errors
///
/// Returns an error if AES-GCM authentication fails.
pub fn decrypt_v2_ciphertext(
    bundle: &V2CiphertextBundle,
    shared_key: &SharedSymmetricKey,
) -> Result<V2Plaintext, V2CiphertextError> {
    let cipher = Aes256Gcm16::new_from_slice(shared_key.as_bytes())
        .map_err(|_| V2CiphertextError::AuthenticationFailed)?;
    let mut iv = [0_u8; IV_LENGTH];
    iv.copy_from_slice(&bundle.iv_tag().as_bytes()[..IV_LENGTH]);
    let tag = GenericArray::clone_from_slice(
        &bundle.iv_tag().as_bytes()[IV_LENGTH..IV_LENGTH + TAG_LENGTH],
    );

    let mut encrypted = Vec::with_capacity(FIXED_PLAINTEXT_LENGTH + bundle.memo().len());
    for block in bundle.data() {
        encrypted.extend_from_slice(block.as_bytes());
    }
    encrypted.extend_from_slice(bundle.memo());

    cipher
        .decrypt_in_place_detached(GenericArray::from_slice(&iv), b"", &mut encrypted, &tag)
        .map_err(|_| V2CiphertextError::AuthenticationFailed)?;
    decode_v2_plaintext(&encrypted)
}

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;
    use railgun_types::{
        MasterPublicKey, NoteRandom, NoteValue, SharedSymmetricKey, TokenHash, V2Plaintext,
    };

    use super::{
        FIXED_PLAINTEXT_LENGTH, V2CiphertextError, decode_v2_plaintext, decrypt_v2_ciphertext,
        encode_v2_plaintext, encrypt_v2_ciphertext_with_iv,
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

    fn plaintext_fixture(memo: Vec<u8>) -> V2Plaintext {
        V2Plaintext::new(
            MasterPublicKey::new(BigUint::from_bytes_be(&decode_hex::<32>(
                "6595f9a971c7471695948a445aedcbb9d624a325dbe68c228dea25eccf61919d",
            )))
            .unwrap_or_else(|_| panic!("master public key should be valid")),
            TokenHash::new(decode_hex(
                "0000000000000000000000007f4925cdf66ddf5b88016df1fe915e68eff8f192",
            )),
            NoteRandom::new(decode_hex("85b08a7cd73ee433072f1d410aeb4801")),
            NoteValue::new(0x086a_a1ad_e61c_cb53),
            memo,
        )
    }

    #[test]
    fn encodes_v2_plaintext_in_canonical_field_order() {
        let plaintext = plaintext_fixture(b"memo".to_vec());
        let encoded = encode_v2_plaintext(&plaintext);

        assert_eq!(&encoded[..32], plaintext.encoded_master_public_key().to_be_bytes().as_slice());
        assert_eq!(&encoded[32..64], plaintext.token_hash().as_bytes());
        assert_eq!(&encoded[64..80], plaintext.random().as_bytes());
        assert_eq!(&encoded[80..96], &plaintext.value().to_be_bytes());
        assert_eq!(&encoded[96..], b"memo");
    }

    #[test]
    fn decodes_v2_plaintext_with_empty_memo() {
        let plaintext = plaintext_fixture(Vec::new());
        let decoded = decode_v2_plaintext(&encode_v2_plaintext(&plaintext))
            .unwrap_or_else(|error| panic!("v2 plaintext decode should succeed: {error}"));

        assert_eq!(decoded, plaintext);
    }

    #[test]
    fn rejects_v2_plaintext_shorter_than_fixed_layout() {
        let Err(error) = decode_v2_plaintext(&[7_u8; FIXED_PLAINTEXT_LENGTH - 1]) else {
            panic!("short v2 plaintext should fail");
        };

        assert_eq!(error, V2CiphertextError::InvalidPlaintextLength(FIXED_PLAINTEXT_LENGTH - 1));
    }

    #[test]
    fn round_trips_v2_ciphertext_with_non_empty_memo() {
        let plaintext = plaintext_fixture(b"something".to_vec());
        let shared_key = SharedSymmetricKey::new(decode_hex(
            "b8b0ee90e05cec44880f1af4d20506265f44684eb3b6a4327bcf811244dc0a7f",
        ));
        let annotation_data = vec![1_u8, 2, 3];

        let ciphertext = encrypt_v2_ciphertext_with_iv(
            &plaintext,
            &shared_key,
            annotation_data.clone(),
            decode_hex("5f8c104eec6e72996078ca3149a153c0"),
        )
        .unwrap_or_else(|error| panic!("v2 ciphertext encryption should succeed: {error}"));
        let decrypted = decrypt_v2_ciphertext(&ciphertext, &shared_key)
            .unwrap_or_else(|error| panic!("v2 ciphertext decryption should succeed: {error}"));

        assert_eq!(ciphertext.annotation_data(), annotation_data.as_slice());
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn rejects_modified_v2_tag() {
        let plaintext = plaintext_fixture(Vec::new());
        let shared_key = SharedSymmetricKey::new(decode_hex(
            "b8b0ee90e05cec44880f1af4d20506265f44684eb3b6a4327bcf811244dc0a7f",
        ));
        let mut ciphertext = encrypt_v2_ciphertext_with_iv(
            &plaintext,
            &shared_key,
            Vec::new(),
            decode_hex("5f8c104eec6e72996078ca3149a153c0"),
        )
        .unwrap_or_else(|error| panic!("v2 ciphertext encryption should succeed: {error}"));

        let mut iv_tag = *ciphertext.iv_tag().as_bytes();
        iv_tag[31] ^= 1;
        ciphertext = railgun_types::V2CiphertextBundle::new(
            railgun_types::V2CiphertextBlock::new(iv_tag),
            *ciphertext.data(),
            ciphertext.annotation_data().to_vec(),
            ciphertext.memo().to_vec(),
        );

        let Err(error) = decrypt_v2_ciphertext(&ciphertext, &shared_key) else {
            panic!("modified v2 tag should fail");
        };

        assert_eq!(error, V2CiphertextError::AuthenticationFailed);
    }

    #[test]
    fn matches_deterministic_fixed_iv_v2_vector() {
        let plaintext = plaintext_fixture(b"something".to_vec());
        let shared_key = SharedSymmetricKey::new(decode_hex(
            "b8b0ee90e05cec44880f1af4d20506265f44684eb3b6a4327bcf811244dc0a7f",
        ));
        let ciphertext = encrypt_v2_ciphertext_with_iv(
            &plaintext,
            &shared_key,
            Vec::new(),
            decode_hex("5f8c104eec6e72996078ca3149a153c0"),
        )
        .unwrap_or_else(|error| panic!("v2 ciphertext encryption should succeed: {error}"));

        assert_eq!(
            ciphertext.iv_tag().as_bytes(),
            &decode_hex::<32>("5f8c104eec6e72996078ca3149a153c08988e4ab23cff2103c823aa106fc77d5")
        );
        assert_eq!(
            ciphertext.data()[0].as_bytes(),
            &decode_hex::<32>("ed60c5dc0304f63e6e201e2311467bd112b90224dfd523eeaafd2e59b66198c0")
        );
        assert_eq!(
            ciphertext.data()[1].as_bytes(),
            &decode_hex::<32>("402efb278eded2a2c64030f0a8b2953b9d6624da04770265c66aceca79cac188")
        );
        assert_eq!(
            ciphertext.data()[2].as_bytes(),
            &decode_hex::<32>("b9f774a8528f33b71f754781b23a484005ba4765ca5f2f018eaed22f21e3b8cf")
        );
        assert_eq!(ciphertext.memo(), &decode_hex::<9>("f64e2786ac43a8631f"));
    }
}
