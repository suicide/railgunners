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
        BlindedViewingPublicKey, MasterPublicKey, NoteRandom, NoteValue, SharedSymmetricKey,
        TokenHash, V2Plaintext, ViewingPrivateKey,
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

    struct V2Fixture {
        id: &'static str,
        sender_master_public_key_hex: &'static str,
        sender_viewing_private_key: &'static str,
        receiver_master_public_key_hex: &'static str,
        receiver_viewing_private_key: &'static str,
        encoded_master_public_key_hex: &'static str,
        token_hash_hex: &'static str,
        random_hex: &'static str,
        value_hex: &'static str,
        memo_hex: &'static str,
        shared_key_hex: &'static str,
        blinded_sender_viewing_key_hex: &'static str,
        blinded_receiver_viewing_key_hex: &'static str,
        iv_hex: &'static str,
        tag_hex: &'static str,
        data_hex: [&'static str; 3],
        detached_memo_hex: &'static str,
        annotation_data_hex: &'static str,
    }

    /// See <https://github.com/suicide/railgun-rs/issues/25>
    const FIXTURES: [V2Fixture; 3] = [
        V2Fixture {
            id: "v2-hidden-empty-memo",
            sender_master_public_key_hex: "2c59cd4733f911ba740da68fb7ba3b873f21daece4e3a105aef12d6414e54ebf",
            sender_viewing_private_key: "9da4b4f0b5493a6ba3f7df0611c3e0842f7e2bb3d640f313b235f1b75c1d80b9",
            receiver_master_public_key_hex: "22c3d1870a9f3bddf34492262f9a1ce280133fb2751f346aab32df97149bcd91",
            receiver_viewing_private_key: "9960238a86a7ecff390b7f37f680e7468fa0c41ee3704fcc68f0be82d19be4b2",
            encoded_master_public_key_hex: "22c3d1870a9f3bddf34492262f9a1ce280133fb2751f346aab32df97149bcd91",
            token_hash_hex: "0000000000000000000000009fe46736679d2d9a65f0992f2272de9f3c7fa6e0",
            random_hex: "22222222222222222222222222222222",
            value_hex: "000000000000003635c9adc5dea00000",
            memo_hex: "",
            shared_key_hex: "3e89c08522cbd907d65df1b6d200c8475c66d32df8eb3b4ca2d7f0678923a90e",
            blinded_sender_viewing_key_hex: "620d670aea4ba400b253f0e3bbd7fd293b1eee359151127e0ae7cd6d747eabde",
            blinded_receiver_viewing_key_hex: "90b58b9dfdea1210171f26acee28f4a777b344d4d47970eb7aff233b926ec06b",
            iv_hex: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            tag_hex: "439126ef4f529c962ca360dd782fc5eb",
            data_hex: [
                "a9295db7d6ebe0a252f675c234efff1eef684301038eca8f7d48b31e6dd28144",
                "82c2c78d03f6fb592b8efe364dc8250c9ec5e4c4a7500edb3dd6315a8a40bc10",
                "338e9603b26386c310c257e3d798c4777774a319cf468cf255cfdd250fd481ef",
            ],
            detached_memo_hex: "",
            annotation_data_hex: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb7d8d3705311b9e20e31add75827686cd119655505eddda0e22406d5d126f821029179f871d6d8ff6081f4b95e633",
        },
        V2Fixture {
            id: "v2-hidden-short-memo",
            sender_master_public_key_hex: "2c59cd4733f911ba740da68fb7ba3b873f21daece4e3a105aef12d6414e54ebf",
            sender_viewing_private_key: "9da4b4f0b5493a6ba3f7df0611c3e0842f7e2bb3d640f313b235f1b75c1d80b9",
            receiver_master_public_key_hex: "2cdf58dbb4e1daadcd4c864afb9562cfd925856c08acdc085fbb53ec16cb969b",
            receiver_viewing_private_key: "2b0e3d174269bf4a112a56eb40d55ec52a0ee989a27c1bb78351d30ddd5fdcc1",
            encoded_master_public_key_hex: "2cdf58dbb4e1daadcd4c864afb9562cfd925856c08acdc085fbb53ec16cb969b",
            token_hash_hex: "000000000000000000000000276c216d241856199a83bf27b2286659e5b877d3",
            random_hex: "44444444444444444444444444444444",
            value_hex: "0000000000000000ab54a98ceb1f0ad2",
            memo_hex: "7261696c67756e2d76322d666978747572652d32",
            shared_key_hex: "9236e6c8b0cb64310a8acb42230c6b8031bfd648262b236a96b203f78dbf2c41",
            blinded_sender_viewing_key_hex: "42aa3d7dd0e55c66fd03a1edafc3251d5d39495624ee63647b63cd50db659471",
            blinded_receiver_viewing_key_hex: "9f6cd16133854e3798d8a1a55abe961c8995fc7363b6332909b537ae6fcdacad",
            iv_hex: "cccccccccccccccccccccccccccccccc",
            tag_hex: "d0907004a906029e71e68e2d20f5ba8e",
            data_hex: [
                "0542e51364a1d1f1cda79180b72d3c830caa634129651167e1032ee63c1d9788",
                "7bdf2e0b1ef4a616f25bffb37a8d27de78ce3df8ac1d82b9590c0b148886490c",
                "053104fd5603947af1fe005c6626135c25397e65f3c1abad5c262312ce5cfe91",
            ],
            detached_memo_hex: "1011e6b81dd77288764e08899b62346c436c9c47",
            annotation_data_hex: "ddddddddddddddddddddddddddddddddef7c83004b19ab463c488e1a80cf1e4a51a09c76d89ed339a58f591b2c4ec8d9b23661927ad44d64772ac16e3219",
        },
        V2Fixture {
            id: "v2-visible-sender-memo",
            sender_master_public_key_hex: "2c59cd4733f911ba740da68fb7ba3b873f21daece4e3a105aef12d6414e54ebf",
            sender_viewing_private_key: "9da4b4f0b5493a6ba3f7df0611c3e0842f7e2bb3d640f313b235f1b75c1d80b9",
            receiver_master_public_key_hex: "1a6c00485f43613bd99cddc145f8df57148d98c137db8331f159110de4fd1ad1",
            receiver_viewing_private_key: "8e94cd47c91a8ee27079a4020180475b1d3b1ed6fb01e30a2fc16c543faafb51",
            encoded_master_public_key_hex: "3635cd0f6cba7081ad917b4ef242e4d02bac422dd33822345fa83c69f018546e",
            token_hash_hex: "000000000000000000000000a7c59f010700930003b33ab25a7a0679c860f29c",
            random_hex: "66666666666666666666666666666666",
            value_hex: "000000000000000005e3363cb39ec9b2",
            memo_hex: "76697369626c652d73656e6465722d7632",
            shared_key_hex: "8fcb7b92bf1d2f065291f1395842115edcbcea8b563bfca80fc4866e9c1566ed",
            blinded_sender_viewing_key_hex: "4e47197b2beb03a3922a768813de4849a7fe097d48ac7b3e62dcb0f1566b02bd",
            blinded_receiver_viewing_key_hex: "2aeabb36df44239a18a570541a1e34d7ba5eff976d4aff1aef4904233631c221",
            iv_hex: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            tag_hex: "c2b707a73b2b2139426d6f0131860b44",
            data_hex: [
                "9aade99bfea152a21793768dea122c609cea422181c2f73b3fb7d98845b43649",
                "7fce5e1d33a0f7871e23b700157c4716d5ae35e3a0a7e6c25763bcfe558f4149",
                "899ff5dbbbd18cc2aa40e20b6e0cb42684c489988ccf2a3ec3861e6044f874f5",
            ],
            detached_memo_hex: "1fe33daff0cd0234987b687250e022cc6f",
            annotation_data_hex: "ffffffffffffffffffffffffffffffff195b5891002b05c030e3bd0b08f22eb466b37d1406ddcc2590f4d99c60fb693a2ba3fb68f1bdf1248519168a001c",
        },
    ];

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

    fn plaintext_from_fixture(fixture: &V2Fixture) -> V2Plaintext {
        V2Plaintext::new(
            MasterPublicKey::new(BigUint::from_bytes_be(&decode_hex::<32>(
                fixture.encoded_master_public_key_hex,
            )))
            .unwrap_or_else(|_| panic!("{} encoded master public key should be valid", fixture.id)),
            TokenHash::new(decode_hex(fixture.token_hash_hex)),
            NoteRandom::new(decode_hex(fixture.random_hex)),
            NoteValue::from_be_bytes(decode_hex(fixture.value_hex)),
            decode_hex_to_vec(fixture.memo_hex),
        )
    }

    fn decode_hex_to_vec(value: &str) -> Vec<u8> {
        let trimmed = value.strip_prefix("0x").unwrap_or(value);
        assert_eq!(trimmed.len() % 2, 0, "hex input has unexpected odd length");
        let mut bytes = Vec::with_capacity(trimmed.len() / 2);
        for chunk in trimmed.as_bytes().chunks_exact(2) {
            let high =
                (chunk[0] as char).to_digit(16).unwrap_or_else(|| panic!("invalid hex nibble"));
            let low =
                (chunk[1] as char).to_digit(16).unwrap_or_else(|| panic!("invalid hex nibble"));
            bytes.push(
                u8::try_from((high << 4) | low)
                    .unwrap_or_else(|_| panic!("hex byte should fit into u8")),
            );
        }
        bytes
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

    #[test]
    fn matches_issue_25_generated_v2_fixtures() {
        for fixture in &FIXTURES {
            let plaintext = plaintext_from_fixture(fixture);
            let shared_key = SharedSymmetricKey::new(decode_hex(fixture.shared_key_hex));
            let annotation_data = decode_hex_to_vec(fixture.annotation_data_hex);
            let ciphertext = encrypt_v2_ciphertext_with_iv(
                &plaintext,
                &shared_key,
                annotation_data.clone(),
                decode_hex(fixture.iv_hex),
            )
            .unwrap_or_else(|error| {
                panic!("{} v2 ciphertext encryption should succeed: {error}", fixture.id)
            });

            assert_eq!(
                ciphertext.iv_tag().as_bytes(),
                decode_hex_to_vec(&format!("{}{}", fixture.iv_hex, fixture.tag_hex)).as_slice(),
                "{} iv|tag mismatch",
                fixture.id
            );

            for (index, expected) in fixture.data_hex.iter().enumerate() {
                assert_eq!(
                    ciphertext.data()[index].as_bytes(),
                    decode_hex_to_vec(expected).as_slice(),
                    "{} ciphertext block {} mismatch",
                    fixture.id,
                    index
                );
            }

            assert_eq!(
                ciphertext.memo(),
                decode_hex_to_vec(fixture.detached_memo_hex).as_slice(),
                "{} detached memo mismatch",
                fixture.id
            );
            assert_eq!(
                ciphertext.annotation_data(),
                annotation_data.as_slice(),
                "{} annotation data mismatch",
                fixture.id
            );

            let decrypted =
                decrypt_v2_ciphertext(&ciphertext, &shared_key).unwrap_or_else(|error| {
                    panic!("{} v2 ciphertext decryption should succeed: {error}", fixture.id)
                });
            assert_eq!(decrypted, plaintext, "{} decrypted plaintext mismatch", fixture.id);
        }
    }

    #[test]
    fn fixture_shared_keys_match_blinded_key_derivation() {
        for fixture in &FIXTURES {
            let sender_key = ViewingPrivateKey::new(decode_hex(fixture.sender_viewing_private_key));
            let receiver_key =
                ViewingPrivateKey::new(decode_hex(fixture.receiver_viewing_private_key));
            let blinded_sender =
                BlindedViewingPublicKey::new(decode_hex(fixture.blinded_sender_viewing_key_hex));
            let blinded_receiver =
                BlindedViewingPublicKey::new(decode_hex(fixture.blinded_receiver_viewing_key_hex));
            let expected = SharedSymmetricKey::new(decode_hex(fixture.shared_key_hex));

            let sender_shared = crate::derive_shared_symmetric_key(&sender_key, &blinded_receiver)
                .unwrap_or_else(|error| {
                    panic!("{} sender shared key derivation should succeed: {error}", fixture.id)
                });
            let receiver_shared = crate::derive_shared_symmetric_key(
                &receiver_key,
                &blinded_sender,
            )
            .unwrap_or_else(|error| {
                panic!("{} receiver shared key derivation should succeed: {error}", fixture.id)
            });

            assert_eq!(sender_shared, expected, "{} sender shared key mismatch", fixture.id);
            assert_eq!(receiver_shared, expected, "{} receiver shared key mismatch", fixture.id);
        }
    }

    #[test]
    fn visible_sender_fixture_uses_xored_master_public_key() {
        let fixture = FIXTURES
            .iter()
            .find(|fixture| fixture.id == "v2-visible-sender-memo")
            .unwrap_or_else(|| panic!("visible sender fixture should exist"));
        let sender =
            BigUint::from_bytes_be(&decode_hex::<32>(fixture.sender_master_public_key_hex));
        let receiver =
            BigUint::from_bytes_be(&decode_hex::<32>(fixture.receiver_master_public_key_hex));
        let encoded =
            BigUint::from_bytes_be(&decode_hex::<32>(fixture.encoded_master_public_key_hex));

        assert_eq!(encoded, sender ^ receiver);
    }
}
