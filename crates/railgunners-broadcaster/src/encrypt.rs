use aes_gcm::{
    AesGcm,
    aead::{AeadInPlace, KeyInit, OsRng, generic_array::GenericArray, rand_core::RngCore},
    aes::Aes256,
};
use curve25519_dalek::{edwards::CompressedEdwardsY, scalar::Scalar};
use ed25519_dalek::SigningKey;
use railgunners_core::derive_viewing_public_key;
use railgunners_types::{ViewingPrivateKey, ViewingPublicKey};

use crate::{
    BroadcasterEncryptedData, BroadcasterError, BroadcasterRawParamsTransactCommon,
    BroadcasterTransactEnvelope, parse_transact_common_payload, serialize_transact_common_payload,
};

type Aes256Gcm16 = AesGcm<Aes256, aes_gcm::aead::consts::U16>;

const IV_LENGTH: usize = 16;
const TAG_LENGTH: usize = 16;
const IV_TAG_LENGTH: usize = IV_LENGTH + TAG_LENGTH;

struct DecodedEncryptedData {
    iv: [u8; IV_LENGTH],
    tag: [u8; TAG_LENGTH],
    ciphertext: Vec<u8>,
}

/// Decrypted broadcaster transact payload and parsed COMMON request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BroadcasterDecryptedTransactCommon {
    plaintext: String,
    payload: BroadcasterRawParamsTransactCommon,
}

impl BroadcasterDecryptedTransactCommon {
    /// Creates a decrypted broadcaster transact payload result.
    #[must_use]
    pub fn new(plaintext: String, payload: BroadcasterRawParamsTransactCommon) -> Self {
        Self { plaintext, payload }
    }

    /// Returns the decrypted canonical transact JSON payload.
    #[must_use]
    pub fn plaintext(&self) -> &str {
        &self.plaintext
    }

    /// Returns the parsed typed transact payload.
    #[must_use]
    pub const fn payload(&self) -> &BroadcasterRawParamsTransactCommon {
        &self.payload
    }
}

fn ed25519_private_scalar(viewing_private_key: &ViewingPrivateKey) -> Scalar {
    SigningKey::from_bytes(viewing_private_key.as_bytes()).to_scalar()
}

fn decode_edwards_point(
    public_key: &ViewingPublicKey,
    error: BroadcasterError,
) -> Result<curve25519_dalek::edwards::EdwardsPoint, BroadcasterError> {
    CompressedEdwardsY(*public_key.as_bytes()).decompress().ok_or(error)
}

fn derive_transact_shared_key_from_point(
    private_key: &ViewingPrivateKey,
    point: &curve25519_dalek::edwards::EdwardsPoint,
) -> [u8; 32] {
    (point * ed25519_private_scalar(private_key)).compress().to_bytes()
}

fn derive_transact_shared_key_for_encryption(
    private_key: &ViewingPrivateKey,
    public_key: &ViewingPublicKey,
) -> Result<[u8; 32], BroadcasterError> {
    let point =
        decode_edwards_point(public_key, BroadcasterError::InvalidBroadcasterEncryptionKey)?;
    Ok(derive_transact_shared_key_from_point(private_key, &point))
}

fn derive_transact_shared_key_for_decryption(
    private_key: &ViewingPrivateKey,
    public_key: &ViewingPublicKey,
) -> Result<[u8; 32], BroadcasterError> {
    let point = decode_edwards_point(public_key, BroadcasterError::InvalidTransactEnvelopePubkey)?;
    Ok(derive_transact_shared_key_from_point(private_key, &point))
}

fn decode_encrypted_data(
    encrypted_data: &BroadcasterEncryptedData,
) -> Result<DecodedEncryptedData, BroadcasterError> {
    let parts = encrypted_data.parts();
    let iv_tag = parts[0].strip_prefix("0x").unwrap_or(&parts[0]);
    let ciphertext = parts[1].strip_prefix("0x").unwrap_or(&parts[1]);

    let iv_tag_bytes = hex::decode(iv_tag).map_err(|_| {
        BroadcasterError::InvalidTransactEnvelopeEncryptedData(
            "broadcaster transact encryptedData[0] must be valid hex".into(),
        )
    })?;
    if iv_tag_bytes.len() != IV_TAG_LENGTH {
        return Err(BroadcasterError::InvalidTransactEnvelopeEncryptedData(
            "broadcaster transact encryptedData[0] must contain 16-byte iv and 16-byte tag".into(),
        ));
    }

    let ciphertext_bytes = hex::decode(ciphertext).map_err(|_| {
        BroadcasterError::InvalidTransactEnvelopeEncryptedData(
            "broadcaster transact encryptedData[1] must be valid hex".into(),
        )
    })?;

    let mut iv = [0_u8; IV_LENGTH];
    iv.copy_from_slice(&iv_tag_bytes[..IV_LENGTH]);
    let mut tag = [0_u8; TAG_LENGTH];
    tag.copy_from_slice(&iv_tag_bytes[IV_LENGTH..]);

    Ok(DecodedEncryptedData { iv, tag, ciphertext: ciphertext_bytes })
}

fn encrypt_json_payload(
    plaintext: &[u8],
    shared_key: &[u8; 32],
    iv: [u8; IV_LENGTH],
) -> Result<BroadcasterEncryptedData, BroadcasterError> {
    let cipher = Aes256Gcm16::new_from_slice(shared_key)
        .map_err(|_| BroadcasterError::TransactEncryptionFailed)?;
    let mut encrypted = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(GenericArray::from_slice(&iv), b"", &mut encrypted)
        .map_err(|_| BroadcasterError::TransactEncryptionFailed)?;

    Ok(BroadcasterEncryptedData::new([
        format!("0x{}{}", hex::encode(iv), hex::encode(tag.as_slice())),
        format!("0x{}", hex::encode(encrypted)),
    ]))
}

fn decrypt_json_payload(
    encrypted_data: &BroadcasterEncryptedData,
    shared_key: &[u8; 32],
) -> Result<String, BroadcasterError> {
    let DecodedEncryptedData { iv, tag, mut ciphertext } = decode_encrypted_data(encrypted_data)?;
    let cipher = Aes256Gcm16::new_from_slice(shared_key)
        .map_err(|_| BroadcasterError::TransactDecryptionFailed)?;
    cipher
        .decrypt_in_place_detached(
            GenericArray::from_slice(&iv),
            b"",
            &mut ciphertext,
            &GenericArray::clone_from_slice(&tag),
        )
        .map_err(|_| BroadcasterError::TransactDecryptionFailed)?;

    String::from_utf8(ciphertext).map_err(|_| BroadcasterError::InvalidTransactPayloadUtf8)
}

fn encrypt_transact_common_payload_with_ephemeral_key_and_iv(
    broadcaster_viewing_key: &ViewingPublicKey,
    payload: &BroadcasterRawParamsTransactCommon,
    ephemeral_private_key: &ViewingPrivateKey,
    iv: [u8; IV_LENGTH],
) -> Result<BroadcasterTransactEnvelope, BroadcasterError> {
    let serialized = serialize_transact_common_payload(payload)?;
    let shared_key =
        derive_transact_shared_key_for_encryption(ephemeral_private_key, broadcaster_viewing_key)?;
    let pubkey = derive_viewing_public_key(ephemeral_private_key);
    let encrypted_data = encrypt_json_payload(serialized.as_bytes(), &shared_key, iv)?;

    Ok(BroadcasterTransactEnvelope::new(pubkey, encrypted_data))
}

/// Encrypts a typed COMMON transact payload into a canonical broadcaster envelope.
///
/// # Errors
///
/// Returns an error if the payload cannot be serialized, the broadcaster viewing
/// key is not a valid ed25519 point, or encryption fails unexpectedly.
pub fn encrypt_transact_common_payload(
    broadcaster_viewing_key: &ViewingPublicKey,
    payload: &BroadcasterRawParamsTransactCommon,
) -> Result<BroadcasterTransactEnvelope, BroadcasterError> {
    let mut ephemeral_private_key = [0_u8; ViewingPrivateKey::LENGTH];
    OsRng.fill_bytes(&mut ephemeral_private_key);
    encrypt_transact_common_payload_with_ephemeral_key(
        broadcaster_viewing_key,
        payload,
        &ViewingPrivateKey::new(ephemeral_private_key),
    )
}

/// Encrypts a typed COMMON transact payload into a canonical broadcaster envelope
/// using a caller-supplied ephemeral viewing private key.
///
/// # Errors
///
/// Returns an error if the payload cannot be serialized, the broadcaster viewing
/// key is not a valid ed25519 point, or encryption fails unexpectedly.
pub fn encrypt_transact_common_payload_with_ephemeral_key(
    broadcaster_viewing_key: &ViewingPublicKey,
    payload: &BroadcasterRawParamsTransactCommon,
    ephemeral_private_key: &ViewingPrivateKey,
) -> Result<BroadcasterTransactEnvelope, BroadcasterError> {
    let mut iv = [0_u8; IV_LENGTH];
    OsRng.fill_bytes(&mut iv);
    encrypt_transact_common_payload_with_ephemeral_key_and_iv(
        broadcaster_viewing_key,
        payload,
        ephemeral_private_key,
        iv,
    )
}

/// Decrypts a canonical broadcaster transact envelope into its plaintext JSON
/// without parsing the COMMON payload.
///
/// # Errors
///
/// Returns an error if the envelope public key or encrypted tuple is malformed,
/// shared-key derivation fails, decryption fails, or the decrypted plaintext is
/// not valid UTF-8.
pub fn decrypt_transact_common_envelope_plaintext(
    broadcaster_viewing_private_key: &ViewingPrivateKey,
    envelope: &BroadcasterTransactEnvelope,
) -> Result<String, BroadcasterError> {
    let shared_key = derive_transact_shared_key_for_decryption(
        broadcaster_viewing_private_key,
        envelope.pubkey(),
    )?;
    decrypt_json_payload(envelope.encrypted_data(), &shared_key)
}

/// Decrypts a canonical broadcaster transact envelope into its plaintext JSON and
/// typed COMMON transact payload.
///
/// # Errors
///
/// Returns an error if the envelope public key or encrypted tuple is malformed,
/// shared-key derivation fails, decryption fails, or the decrypted JSON does not
/// match the canonical COMMON transact payload schema.
pub fn decrypt_transact_common_envelope(
    broadcaster_viewing_private_key: &ViewingPrivateKey,
    envelope: &BroadcasterTransactEnvelope,
) -> Result<BroadcasterDecryptedTransactCommon, BroadcasterError> {
    let plaintext =
        decrypt_transact_common_envelope_plaintext(broadcaster_viewing_private_key, envelope)?;
    let payload = parse_transact_common_payload(&plaintext)?;

    Ok(BroadcasterDecryptedTransactCommon::new(plaintext, payload))
}

#[cfg(test)]
mod tests {
    use aes_gcm::{
        AesGcm,
        aead::{AeadInPlace, KeyInit, generic_array::GenericArray},
        aes::Aes256,
    };
    use curve25519_dalek::edwards::CompressedEdwardsY;
    use num_bigint::BigUint;
    use railgunners_core::derive_viewing_public_key;
    use railgunners_poi::{
        PoiListKey, PreTransactionPoi, PreTransactionPoisPerTxidLeafPerList, TxidLeafHash,
    };
    use railgunners_types::{
        ChainId, ChainType, Groth16Proof, MerkleNodeHash, MerkleRoot, RailgunTxid, TxidVersion,
        ViewingPrivateKey, ViewingPublicKey,
    };

    use super::{
        IV_LENGTH, TAG_LENGTH, decrypt_transact_common_envelope,
        decrypt_transact_common_envelope_plaintext, derive_transact_shared_key_for_decryption,
        ed25519_private_scalar, encrypt_json_payload, encrypt_transact_common_payload,
        encrypt_transact_common_payload_with_ephemeral_key,
        encrypt_transact_common_payload_with_ephemeral_key_and_iv,
    };
    use crate::{
        BroadcasterEncryptedData, BroadcasterError, BroadcasterRawParamsTransactCommon,
        BroadcasterRequestSharedParams, BroadcasterTransactEnvelope, BroadcasterVersionRange,
        parse_transact_common_payload, serialize_transact_common_payload,
    };

    type Aes256Gcm16 = AesGcm<Aes256, aes_gcm::aead::consts::U16>;

    fn sample_poi_bundle() -> PreTransactionPoisPerTxidLeafPerList {
        let mut bundle = PreTransactionPoisPerTxidLeafPerList::default();
        bundle.insert(
            PoiListKey::parse("efc6ddb59c098a13fb2b618fdae94c1c3a807abc8fb1837c93620c9143ee9e88")
                .unwrap_or_else(|error| panic!("test list key should parse: {error}")),
            TxidLeafHash::new(MerkleNodeHash::new([3_u8; 32])),
            PreTransactionPoi::new(
                Groth16Proof::new(
                    ["1".to_owned(), "2".to_owned()],
                    [["3".to_owned(), "4".to_owned()], ["5".to_owned(), "6".to_owned()]],
                    ["7".to_owned(), "8".to_owned()],
                ),
                MerkleRoot::new([9_u8; 32]),
                vec![MerkleRoot::new([10_u8; 32])],
                vec![railgunners_poi::BlindedCommitment::new(BigUint::from(11_u8)).unwrap_or_else(
                    |error| panic!("test blinded commitment should parse: {error}"),
                )],
                RailgunTxid::new(BigUint::from(12_u8))
                    .unwrap_or_else(|error| panic!("test txid should parse: {error}")),
            )
            .unwrap_or_else(|error| panic!("test POI should construct: {error}")),
        );
        bundle
    }

    fn sample_payload() -> BroadcasterRawParamsTransactCommon {
        BroadcasterRawParamsTransactCommon::new(
            BroadcasterRequestSharedParams::new(
                TxidVersion::V2PoseidonMerkle,
                ChainId::new(1)
                    .unwrap_or_else(|error| panic!("test chain id should validate: {error}")),
                ChainType::new(0),
                "fees-cache-id".to_owned(),
                "0x0707070707070707070707070707070707070707070707070707070707070707".to_owned(),
                true,
                BroadcasterVersionRange::new("1.0.0".to_owned(), "1.1.0".to_owned())
                    .unwrap_or_else(|error| panic!("test version range should construct: {error}")),
            )
            .unwrap_or_else(|error| panic!("test shared params should construct: {error}")),
            "0x1111111111111111111111111111111111111111".to_owned(),
            "0x1234".to_owned(),
            false,
            "4096".to_owned(),
            sample_poi_bundle(),
        )
        .unwrap_or_else(|error| panic!("test payload should construct: {error}"))
    }

    fn decrypt_payload(
        broadcaster_viewing_private_key: &ViewingPrivateKey,
        encrypted_data: &BroadcasterEncryptedData,
        client_pubkey: &ViewingPublicKey,
    ) -> String {
        let shared_key = derive_transact_shared_key_for_decryption(
            broadcaster_viewing_private_key,
            client_pubkey,
        )
        .unwrap_or_else(|error| panic!("shared key should derive: {error}"));
        let parts = encrypted_data.parts();
        let iv_tag = parts[0].strip_prefix("0x").unwrap_or(&parts[0]);
        let ciphertext = parts[1].strip_prefix("0x").unwrap_or(&parts[1]);

        let iv = hex::decode(&iv_tag[..IV_LENGTH * 2])
            .unwrap_or_else(|error| panic!("iv should decode: {error}"));
        let tag = hex::decode(&iv_tag[IV_LENGTH * 2..])
            .unwrap_or_else(|error| panic!("tag should decode: {error}"));
        let mut encrypted = hex::decode(ciphertext)
            .unwrap_or_else(|error| panic!("ciphertext should decode: {error}"));

        let cipher = Aes256Gcm16::new_from_slice(&shared_key)
            .unwrap_or_else(|_| panic!("cipher should initialize"));
        cipher
            .decrypt_in_place_detached(
                GenericArray::from_slice(&iv),
                b"",
                &mut encrypted,
                &GenericArray::clone_from_slice(&tag),
            )
            .unwrap_or_else(|_| panic!("ciphertext should decrypt"));

        String::from_utf8(encrypted)
            .unwrap_or_else(|error| panic!("decrypted payload should be utf8: {error}"))
    }

    fn invalid_viewing_public_key_bytes() -> [u8; 32] {
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
    fn shared_key_matches_bidirectionally_for_viewing_keys() {
        let sender = ViewingPrivateKey::new([
            0x67, 0xd7, 0xd1, 0x9d, 0x00, 0xe6, 0xe3, 0xb3, 0x51, 0x7f, 0xe6, 0x8a, 0xc4, 0x65,
            0x05, 0xdd, 0x20, 0x7d, 0xf6, 0xe8, 0xfe, 0x3a, 0xa0, 0x6b, 0xa3, 0xfa, 0xce, 0x35,
            0x2e, 0x75, 0x99, 0xef,
        ]);
        let receiver = ViewingPrivateKey::new([
            0x34, 0x28, 0xcf, 0xc9, 0x39, 0x32, 0x03, 0x28, 0x50, 0x11, 0x74, 0xa4, 0xe7, 0x6e,
            0x86, 0x91, 0x97, 0xff, 0xc8, 0x94, 0xb5, 0x8d, 0xbf, 0x4d, 0x0e, 0x95, 0x3c, 0x48,
            0x4d, 0x66, 0xcb, 0x5e,
        ]);
        let sender_shared = derive_transact_shared_key_for_decryption(
            &sender,
            &derive_viewing_public_key(&receiver),
        )
        .unwrap_or_else(|error| panic!("sender shared key should derive: {error}"));
        let receiver_shared = derive_transact_shared_key_for_decryption(
            &receiver,
            &derive_viewing_public_key(&sender),
        )
        .unwrap_or_else(|error| panic!("receiver shared key should derive: {error}"));

        assert_eq!(sender_shared, receiver_shared);
    }

    #[test]
    fn deterministic_helper_builds_decryptable_envelope() {
        let broadcaster_private_key = ViewingPrivateKey::new([7_u8; 32]);
        let broadcaster_public_key = derive_viewing_public_key(&broadcaster_private_key);
        let ephemeral_private_key = ViewingPrivateKey::new([9_u8; 32]);
        let iv = [11_u8; IV_LENGTH];

        let envelope = encrypt_transact_common_payload_with_ephemeral_key_and_iv(
            &broadcaster_public_key,
            &sample_payload(),
            &ephemeral_private_key,
            iv,
        )
        .unwrap_or_else(|error| panic!("payload should encrypt: {error}"));
        let decrypted =
            decrypt_payload(&broadcaster_private_key, envelope.encrypted_data(), envelope.pubkey());
        let reparsed = parse_transact_common_payload(&decrypted)
            .unwrap_or_else(|error| panic!("decrypted payload should parse: {error}"));

        assert_eq!(envelope.pubkey(), &derive_viewing_public_key(&ephemeral_private_key));
        assert_eq!(reparsed, sample_payload());
    }

    #[test]
    fn public_ephemeral_helper_uses_caller_key() {
        let broadcaster_public_key = derive_viewing_public_key(&ViewingPrivateKey::new([7_u8; 32]));
        let ephemeral_private_key = ViewingPrivateKey::new([9_u8; 32]);

        let envelope = encrypt_transact_common_payload_with_ephemeral_key(
            &broadcaster_public_key,
            &sample_payload(),
            &ephemeral_private_key,
        )
        .unwrap_or_else(|error| panic!("payload should encrypt: {error}"));

        assert_eq!(envelope.pubkey(), &derive_viewing_public_key(&ephemeral_private_key));
    }

    #[test]
    fn random_helper_builds_envelope_with_prefixed_tuple() {
        let broadcaster_public_key = derive_viewing_public_key(&ViewingPrivateKey::new([7_u8; 32]));

        let envelope = encrypt_transact_common_payload(&broadcaster_public_key, &sample_payload())
            .unwrap_or_else(|error| panic!("payload should encrypt: {error}"));

        assert!(envelope.encrypted_data().parts()[0].starts_with("0x"));
        assert!(envelope.encrypted_data().parts()[1].starts_with("0x"));
    }

    #[test]
    fn rejects_invalid_broadcaster_viewing_key_point() {
        let invalid_public_key = ViewingPublicKey::new(invalid_viewing_public_key_bytes());

        let Err(error) = encrypt_transact_common_payload_with_ephemeral_key_and_iv(
            &invalid_public_key,
            &sample_payload(),
            &ViewingPrivateKey::new([9_u8; 32]),
            [11_u8; IV_LENGTH],
        ) else {
            panic!("invalid broadcaster viewing key should fail");
        };

        assert_eq!(error, BroadcasterError::InvalidBroadcasterEncryptionKey);
    }

    #[test]
    fn shared_key_matches_raw_point_multiplication() {
        let private_key = ViewingPrivateKey::new([9_u8; 32]);
        let public_key = derive_viewing_public_key(&ViewingPrivateKey::new([7_u8; 32]));
        let point = CompressedEdwardsY(*public_key.as_bytes())
            .decompress()
            .unwrap_or_else(|| panic!("public key should decompress"));
        let expected = (point * ed25519_private_scalar(&private_key)).compress().to_bytes();

        let actual = derive_transact_shared_key_for_decryption(&private_key, &public_key)
            .unwrap_or_else(|error| panic!("shared key should derive: {error}"));

        assert_eq!(actual, expected);
    }

    #[test]
    fn encrypted_payload_layout_matches_canonical_tuple_shape() {
        let encrypted = encrypt_json_payload(b"{}", &[5_u8; 32], [7_u8; IV_LENGTH])
            .unwrap_or_else(|error| panic!("payload should encrypt: {error}"));

        assert_eq!(encrypted.parts()[0].len(), 2 + 32 + 32);
        assert!(encrypted.parts()[1].starts_with("0x"));
    }

    #[test]
    fn decrypt_helper_round_trips_encrypted_common_payload() {
        let broadcaster_private_key = ViewingPrivateKey::new([7_u8; 32]);
        let broadcaster_public_key = derive_viewing_public_key(&broadcaster_private_key);
        let payload = sample_payload();
        let serialized = serialize_transact_common_payload(&payload)
            .unwrap_or_else(|error| panic!("payload should serialize: {error}"));
        let envelope = encrypt_transact_common_payload_with_ephemeral_key_and_iv(
            &broadcaster_public_key,
            &payload,
            &ViewingPrivateKey::new([9_u8; 32]),
            [11_u8; IV_LENGTH],
        )
        .unwrap_or_else(|error| panic!("payload should encrypt: {error}"));

        let decrypted = decrypt_transact_common_envelope(&broadcaster_private_key, &envelope)
            .unwrap_or_else(|error| panic!("envelope should decrypt: {error}"));

        assert_eq!(decrypted.plaintext(), serialized);
        assert_eq!(decrypted.payload(), &payload);
    }

    #[test]
    fn decrypt_helper_rejects_invalid_envelope_pubkey() {
        let envelope = BroadcasterTransactEnvelope::new(
            ViewingPublicKey::new(invalid_viewing_public_key_bytes()),
            BroadcasterEncryptedData::new([
                format!("0x{}{}", hex::encode([1_u8; IV_LENGTH]), hex::encode([2_u8; TAG_LENGTH])),
                "0x00".to_owned(),
            ]),
        );

        let Err(error) =
            decrypt_transact_common_envelope(&ViewingPrivateKey::new([7_u8; 32]), &envelope)
        else {
            panic!("invalid envelope pubkey should fail");
        };

        assert_eq!(error, BroadcasterError::InvalidTransactEnvelopePubkey);
    }

    #[test]
    fn decrypt_helper_rejects_invalid_encrypted_tuple_shape() {
        let envelope = BroadcasterTransactEnvelope::new(
            derive_viewing_public_key(&ViewingPrivateKey::new([9_u8; 32])),
            BroadcasterEncryptedData::new(["0x1234".to_owned(), "0x00".to_owned()]),
        );

        let Err(error) =
            decrypt_transact_common_envelope(&ViewingPrivateKey::new([7_u8; 32]), &envelope)
        else {
            panic!("invalid encrypted tuple should fail");
        };

        assert_eq!(
            error,
            BroadcasterError::InvalidTransactEnvelopeEncryptedData(
                "broadcaster transact encryptedData[0] must contain 16-byte iv and 16-byte tag"
                    .into(),
            )
        );
    }

    #[test]
    fn decrypt_helper_rejects_wrong_private_key() {
        let broadcaster_private_key = ViewingPrivateKey::new([7_u8; 32]);
        let broadcaster_public_key = derive_viewing_public_key(&broadcaster_private_key);
        let envelope = encrypt_transact_common_payload_with_ephemeral_key_and_iv(
            &broadcaster_public_key,
            &sample_payload(),
            &ViewingPrivateKey::new([9_u8; 32]),
            [11_u8; IV_LENGTH],
        )
        .unwrap_or_else(|error| panic!("payload should encrypt: {error}"));

        let Err(error) =
            decrypt_transact_common_envelope(&ViewingPrivateKey::new([8_u8; 32]), &envelope)
        else {
            panic!("wrong private key should fail");
        };

        assert_eq!(error, BroadcasterError::TransactDecryptionFailed);
    }

    #[test]
    fn decrypt_helper_rejects_invalid_typed_payload_after_successful_decryption() {
        let broadcaster_private_key = ViewingPrivateKey::new([7_u8; 32]);
        let broadcaster_public_key = derive_viewing_public_key(&broadcaster_private_key);
        let envelope = encrypt_transact_common_payload_with_ephemeral_key_and_iv(
            &broadcaster_public_key,
            &sample_payload(),
            &ViewingPrivateKey::new([9_u8; 32]),
            [11_u8; IV_LENGTH],
        )
        .unwrap_or_else(|error| panic!("payload should encrypt: {error}"));
        let malformed_plaintext = r#"{"transactType":"COMMON"}"#;
        let shared_key = derive_transact_shared_key_for_decryption(
            &broadcaster_private_key,
            &ViewingPublicKey::new(*envelope.pubkey().as_bytes()),
        )
        .unwrap_or_else(|error| panic!("shared key should derive: {error}"));
        let encrypted_data =
            encrypt_json_payload(malformed_plaintext.as_bytes(), &shared_key, [12_u8; IV_LENGTH])
                .unwrap_or_else(|error| panic!("malformed payload should encrypt: {error}"));
        let malformed_envelope = BroadcasterTransactEnvelope::new(
            ViewingPublicKey::new(*envelope.pubkey().as_bytes()),
            encrypted_data,
        );

        let Err(error) =
            decrypt_transact_common_envelope(&broadcaster_private_key, &malformed_envelope)
        else {
            panic!("invalid typed payload should fail");
        };

        assert_eq!(error, BroadcasterError::InvalidTransactPayloadJson);
    }

    #[test]
    fn decrypt_plaintext_round_trips_encrypted_common_payload() {
        let broadcaster_private_key = ViewingPrivateKey::new([7_u8; 32]);
        let broadcaster_public_key = derive_viewing_public_key(&broadcaster_private_key);
        let payload = sample_payload();
        let serialized = serialize_transact_common_payload(&payload)
            .unwrap_or_else(|error| panic!("payload should serialize: {error}"));
        let envelope = encrypt_transact_common_payload_with_ephemeral_key_and_iv(
            &broadcaster_public_key,
            &payload,
            &ViewingPrivateKey::new([9_u8; 32]),
            [11_u8; IV_LENGTH],
        )
        .unwrap_or_else(|error| panic!("payload should encrypt: {error}"));

        let plaintext =
            decrypt_transact_common_envelope_plaintext(&broadcaster_private_key, &envelope)
                .unwrap_or_else(|error| panic!("should decrypt: {error}"));

        assert_eq!(plaintext, serialized);
    }

    #[test]
    fn decrypt_plaintext_rejects_wrong_private_key() {
        let broadcaster_private_key = ViewingPrivateKey::new([7_u8; 32]);
        let broadcaster_public_key = derive_viewing_public_key(&broadcaster_private_key);
        let envelope = encrypt_transact_common_payload_with_ephemeral_key_and_iv(
            &broadcaster_public_key,
            &sample_payload(),
            &ViewingPrivateKey::new([9_u8; 32]),
            [11_u8; IV_LENGTH],
        )
        .unwrap_or_else(|error| panic!("payload should encrypt: {error}"));

        let Err(error) = decrypt_transact_common_envelope_plaintext(
            &ViewingPrivateKey::new([8_u8; 32]),
            &envelope,
        ) else {
            panic!("wrong private key should fail");
        };

        assert_eq!(error, BroadcasterError::TransactDecryptionFailed);
    }

    #[test]
    fn decrypt_plaintext_rejects_malformed_encrypted_tuple() {
        let envelope = BroadcasterTransactEnvelope::new(
            derive_viewing_public_key(&ViewingPrivateKey::new([9_u8; 32])),
            BroadcasterEncryptedData::new(["0x1234".to_owned(), "0x00".to_owned()]),
        );

        let Err(error) = decrypt_transact_common_envelope_plaintext(
            &ViewingPrivateKey::new([7_u8; 32]),
            &envelope,
        ) else {
            panic!("malformed encrypted tuple should fail");
        };

        assert_eq!(
            error,
            BroadcasterError::InvalidTransactEnvelopeEncryptedData(
                "broadcaster transact encryptedData[0] must contain 16-byte iv and 16-byte tag"
                    .into(),
            )
        );
    }

    #[test]
    fn decrypt_plaintext_rejects_invalid_utf8_plaintext() {
        let broadcaster_private_key = ViewingPrivateKey::new([7_u8; 32]);
        let ephemeral_private_key = ViewingPrivateKey::new([9_u8; 32]);
        let ephemeral_public_key = derive_viewing_public_key(&ephemeral_private_key);
        let shared_key = derive_transact_shared_key_for_decryption(
            &broadcaster_private_key,
            &ephemeral_public_key,
        )
        .unwrap_or_else(|error| panic!("shared key should derive: {error}"));

        // Encrypt arbitrary bytes that are not valid UTF-8.
        let encrypted_data = encrypt_json_payload(&[0xFF, 0xFE], &shared_key, [11_u8; IV_LENGTH])
            .unwrap_or_else(|error| panic!("should encrypt: {error}"));
        let envelope = BroadcasterTransactEnvelope::new(ephemeral_public_key, encrypted_data);

        let Err(error) =
            decrypt_transact_common_envelope_plaintext(&broadcaster_private_key, &envelope)
        else {
            panic!("invalid UTF-8 should fail");
        };

        assert_eq!(error, BroadcasterError::InvalidTransactPayloadUtf8);
    }
}
