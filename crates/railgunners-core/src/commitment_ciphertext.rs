//! Parsing helpers for canonical V2 and V3 commitment ciphertext containers.

use core::fmt;

use railgunners_types::{
    BlindedViewingPublicKey, CommitmentCiphertextV2, CommitmentCiphertextV3, V2CiphertextBlock,
    V2CiphertextBundle, V3CiphertextBundle, V3StoredNonce,
};

/// Error returned when commitment ciphertext parsing fails.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommitmentCiphertextError {
    /// V2 commitment ciphertext must contain exactly four 32-byte words.
    InvalidV2CiphertextWordCount(usize),
    /// One V2 ciphertext word had the wrong length.
    InvalidV2CiphertextWordLength {
        /// Index of the malformed ciphertext word.
        index: usize,
        /// Actual length of the malformed ciphertext word.
        length: usize,
    },
    /// V3 commitment ciphertext must contain at least a 16-byte stored nonce.
    InvalidV3CiphertextLength(usize),
    /// Blinded sender viewing key was malformed.
    InvalidBlindedSenderViewingKey,
    /// Blinded receiver viewing key was malformed.
    InvalidBlindedReceiverViewingKey,
}

impl fmt::Display for CommitmentCiphertextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidV2CiphertextWordCount(count) => {
                write!(formatter, "invalid v2 ciphertext word count: expected 4, got {count}")
            }
            Self::InvalidV2CiphertextWordLength { index, length } => {
                write!(
                    formatter,
                    "invalid v2 ciphertext word length at index {index}: expected 32, got {length}"
                )
            }
            Self::InvalidV3CiphertextLength(length) => {
                write!(
                    formatter,
                    "invalid v3 ciphertext length: expected at least 16 bytes, got {length}"
                )
            }
            Self::InvalidBlindedSenderViewingKey => {
                formatter.write_str("invalid blinded sender viewing key")
            }
            Self::InvalidBlindedReceiverViewingKey => {
                formatter.write_str("invalid blinded receiver viewing key")
            }
        }
    }
}

impl std::error::Error for CommitmentCiphertextError {}

fn parse_blinded_sender_viewing_key(
    bytes: &[u8],
) -> Result<BlindedViewingPublicKey, CommitmentCiphertextError> {
    BlindedViewingPublicKey::from_slice(bytes)
        .map_err(|_| CommitmentCiphertextError::InvalidBlindedSenderViewingKey)
}

fn parse_blinded_receiver_viewing_key(
    bytes: &[u8],
) -> Result<BlindedViewingPublicKey, CommitmentCiphertextError> {
    BlindedViewingPublicKey::from_slice(bytes)
        .map_err(|_| CommitmentCiphertextError::InvalidBlindedReceiverViewingKey)
}

/// Parses a decoded V2 commitment ciphertext struct into the normalized internal model.
///
/// # Errors
///
/// Returns an error if the V2 ciphertext word count or field lengths are invalid.
pub fn parse_commitment_ciphertext_v2(
    ciphertext_words: &[&[u8]],
    blinded_sender_viewing_key: &[u8],
    blinded_receiver_viewing_key: &[u8],
    annotation_data: &[u8],
    memo: &[u8],
) -> Result<CommitmentCiphertextV2, CommitmentCiphertextError> {
    if ciphertext_words.len() != 4 {
        return Err(CommitmentCiphertextError::InvalidV2CiphertextWordCount(
            ciphertext_words.len(),
        ));
    }

    for (index, word) in ciphertext_words.iter().enumerate() {
        if word.len() != V2CiphertextBlock::LENGTH {
            return Err(CommitmentCiphertextError::InvalidV2CiphertextWordLength {
                index,
                length: word.len(),
            });
        }
    }

    // The first V2 ciphertext word is the packed `iv | tag` header, not ciphertext body data.
    let blocks: [V2CiphertextBlock; 4] = [
        V2CiphertextBlock::from_slice(ciphertext_words[0]).map_err(|_| {
            CommitmentCiphertextError::InvalidV2CiphertextWordLength {
                index: 0,
                length: ciphertext_words[0].len(),
            }
        })?,
        V2CiphertextBlock::from_slice(ciphertext_words[1]).map_err(|_| {
            CommitmentCiphertextError::InvalidV2CiphertextWordLength {
                index: 1,
                length: ciphertext_words[1].len(),
            }
        })?,
        V2CiphertextBlock::from_slice(ciphertext_words[2]).map_err(|_| {
            CommitmentCiphertextError::InvalidV2CiphertextWordLength {
                index: 2,
                length: ciphertext_words[2].len(),
            }
        })?,
        V2CiphertextBlock::from_slice(ciphertext_words[3]).map_err(|_| {
            CommitmentCiphertextError::InvalidV2CiphertextWordLength {
                index: 3,
                length: ciphertext_words[3].len(),
            }
        })?,
    ];

    Ok(CommitmentCiphertextV2::new(
        V2CiphertextBundle::new(
            blocks[0],
            [blocks[1], blocks[2], blocks[3]],
            annotation_data.to_vec(),
            memo.to_vec(),
        ),
        parse_blinded_sender_viewing_key(blinded_sender_viewing_key)?,
        parse_blinded_receiver_viewing_key(blinded_receiver_viewing_key)?,
    ))
}

/// Parses a decoded V3 commitment ciphertext struct into the normalized internal model.
///
/// # Errors
///
/// Returns an error if the V3 ciphertext is shorter than the stored nonce or any blinded key is malformed.
pub fn parse_commitment_ciphertext_v3(
    ciphertext: &[u8],
    blinded_sender_viewing_key: &[u8],
    blinded_receiver_viewing_key: &[u8],
) -> Result<CommitmentCiphertextV3, CommitmentCiphertextError> {
    if ciphertext.len() < V3StoredNonce::LENGTH {
        return Err(CommitmentCiphertextError::InvalidV3CiphertextLength(ciphertext.len()));
    }

    let nonce = V3StoredNonce::from_slice(&ciphertext[..V3StoredNonce::LENGTH])
        .map_err(|_| CommitmentCiphertextError::InvalidV3CiphertextLength(ciphertext.len()))?;

    // V3 note commitment containers only carry the local `nonce | bundle` payload.
    // `senderCiphertext` belongs to global bound params and is parsed separately later.
    Ok(CommitmentCiphertextV3::new(
        V3CiphertextBundle::new(nonce, ciphertext[V3StoredNonce::LENGTH..].to_vec(), Vec::new()),
        parse_blinded_sender_viewing_key(blinded_sender_viewing_key)?,
        parse_blinded_receiver_viewing_key(blinded_receiver_viewing_key)?,
    ))
}

#[cfg(test)]
mod tests {
    use railgunners_types::{V2CiphertextBlock, V3StoredNonce};

    use super::{
        CommitmentCiphertextError, parse_commitment_ciphertext_v2, parse_commitment_ciphertext_v3,
    };

    fn decode_hex_to_vec(value: &str) -> Vec<u8> {
        let trimmed = value.strip_prefix("0x").unwrap_or(value);
        assert_eq!(trimmed.len() % 2, 0, "hex input has unexpected odd length");

        let mut bytes = Vec::with_capacity(trimmed.len() / 2);
        for (index, chunk) in trimmed.as_bytes().chunks_exact(2).enumerate() {
            let high = (chunk[0] as char)
                .to_digit(16)
                .unwrap_or_else(|| panic!("invalid hex nibble at index {}", index * 2));
            let low = (chunk[1] as char)
                .to_digit(16)
                .unwrap_or_else(|| panic!("invalid hex nibble at index {}", index * 2 + 1));
            bytes.push(
                u8::try_from((high << 4) | low)
                    .unwrap_or_else(|_| panic!("hex byte should fit into u8")),
            );
        }
        bytes
    }

    #[test]
    fn parses_v2_issue_vector_into_normalized_model() {
        let ciphertext_words = [
            decode_hex_to_vec("0xba002e1e01f1d63d7fa06c83880b2bef23063903d3f4a2b8f7eb800f6c45491c"),
            decode_hex_to_vec("0x8687c2941bddfc807aa3512ebef36e889a82f3885383877e55b7f86e488b6360"),
            decode_hex_to_vec("0x40521d04c766273db030a1ee070706493383f26b8fd677cb51acf0fd30682a37"),
            decode_hex_to_vec("0x6588e860594d6709193c391b4e79de12cecdaed31eef71a2894af5729c0209f7"),
        ];
        let ciphertext_word_refs: [&[u8]; 4] = [
            ciphertext_words[0].as_slice(),
            ciphertext_words[1].as_slice(),
            ciphertext_words[2].as_slice(),
            ciphertext_words[3].as_slice(),
        ];
        let blinded_sender =
            decode_hex_to_vec("0x2b0f49a1c0fb28ed4cc26fe0531848a25422e5ebdf5bf3df34f67d36d8a484fc");
        let blinded_receiver =
            decode_hex_to_vec("0x2b0f49a1c0fb28ed4cc26fe0531848a25422e5ebdf5bf3df34f67d36d8a484fc");
        let memo = decode_hex_to_vec("0x");
        let annotation_data = decode_hex_to_vec(
            "0x3f5ff6e7bab3653afd46501dac3d55bd72b33355e41bfc02fcd63a78fe9d5da550957fabde36c9ded90126755f80a3fa3cdd0d84be4686c4192e920d85dd",
        );

        let parsed = parse_commitment_ciphertext_v2(
            &ciphertext_word_refs,
            &blinded_sender,
            &blinded_receiver,
            &annotation_data,
            &memo,
        )
        .unwrap_or_else(|_| panic!("v2 issue vector should parse"));

        assert_eq!(parsed.ciphertext().iv_tag().as_bytes(), ciphertext_words[0].as_slice());
        assert_eq!(parsed.ciphertext().data()[0].as_bytes(), ciphertext_words[1].as_slice());
        assert_eq!(parsed.ciphertext().data()[1].as_bytes(), ciphertext_words[2].as_slice());
        assert_eq!(parsed.ciphertext().data()[2].as_bytes(), ciphertext_words[3].as_slice());
        assert_eq!(parsed.ciphertext().annotation_data(), annotation_data.as_slice());
        assert_eq!(parsed.ciphertext().memo(), memo.as_slice());
        assert_eq!(parsed.blinded_sender_viewing_key().as_bytes(), blinded_sender.as_slice());
        assert_eq!(parsed.blinded_receiver_viewing_key().as_bytes(), blinded_receiver.as_slice());
    }

    #[test]
    fn rejects_v2_wrong_word_count() {
        let ciphertext_word = [0_u8; V2CiphertextBlock::LENGTH];
        let ciphertext_words = [ciphertext_word.as_slice(); 3];

        let Err(error) =
            parse_commitment_ciphertext_v2(&ciphertext_words, &[1_u8; 32], &[2_u8; 32], &[], &[])
        else {
            panic!("wrong v2 word count should fail");
        };

        assert_eq!(error, CommitmentCiphertextError::InvalidV2CiphertextWordCount(3));
    }

    #[test]
    fn rejects_v2_wrong_word_length() {
        let valid_word = [0_u8; V2CiphertextBlock::LENGTH];
        let invalid_word = [0_u8; 31];
        let ciphertext_words: [&[u8]; 4] = [
            valid_word.as_slice(),
            valid_word.as_slice(),
            invalid_word.as_slice(),
            valid_word.as_slice(),
        ];

        let Err(error) =
            parse_commitment_ciphertext_v2(&ciphertext_words, &[1_u8; 32], &[2_u8; 32], &[], &[])
        else {
            panic!("wrong v2 word length should fail");
        };

        assert_eq!(
            error,
            CommitmentCiphertextError::InvalidV2CiphertextWordLength { index: 2, length: 31 }
        );
    }

    #[test]
    fn parses_v3_nonce_and_bundle_exactly() {
        let ciphertext = decode_hex_to_vec(
            "0x000102030405060708090a0b0c0d0e0fd0e2e01b52e542f34142d60039f366dcf5dcbcc16af6c28ed756f232f3b2e302",
        );

        let parsed = parse_commitment_ciphertext_v3(&ciphertext, &[3_u8; 32], &[4_u8; 32])
            .unwrap_or_else(|_| panic!("v3 ciphertext should parse"));

        assert_eq!(
            parsed.nonce().as_bytes(),
            V3StoredNonce::new([
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f
            ])
            .as_bytes()
        );
        assert_eq!(
            parsed.bundle(),
            decode_hex_to_vec("0xd0e2e01b52e542f34142d60039f366dcf5dcbcc16af6c28ed756f232f3b2e302")
                .as_slice()
        );
        assert!(parsed.ciphertext().sender_ciphertext().is_empty());
    }

    #[test]
    fn rejects_short_v3_ciphertext() {
        let Err(error) = parse_commitment_ciphertext_v3(&[0_u8; 15], &[3_u8; 32], &[4_u8; 32])
        else {
            panic!("short v3 ciphertext should fail");
        };

        assert_eq!(error, CommitmentCiphertextError::InvalidV3CiphertextLength(15));
    }

    #[test]
    fn rejects_invalid_blinded_sender_key_length() {
        let ciphertext = [0_u8; 16];

        let Err(error) = parse_commitment_ciphertext_v3(&ciphertext, &[3_u8; 31], &[4_u8; 32])
        else {
            panic!("invalid blinded sender key should fail");
        };

        assert_eq!(error, CommitmentCiphertextError::InvalidBlindedSenderViewingKey);
    }

    #[test]
    fn rejects_invalid_blinded_receiver_key_length() {
        let ciphertext = [0_u8; 16];

        let Err(error) = parse_commitment_ciphertext_v3(&ciphertext, &[3_u8; 32], &[4_u8; 31])
        else {
            panic!("invalid blinded receiver key should fail");
        };

        assert_eq!(error, CommitmentCiphertextError::InvalidBlindedReceiverViewingKey);
    }
}
