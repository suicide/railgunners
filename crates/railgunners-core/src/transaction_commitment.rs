//! Version-aware commitment summary extraction from decoded transaction structs.

use core::fmt;

use railgunners_types::{
    CommitmentSummary, DecodedCommitmentCiphertextV2, DecodedCommitmentCiphertextV3,
    VersionedCommitmentCiphertext, VersionedTransaction,
};

use crate::{
    CommitmentCiphertextError, parse_commitment_ciphertext_v2, parse_commitment_ciphertext_v3,
};

/// Error returned when commitment summary extraction fails.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransactionCommitmentError {
    /// The requested commitment index does not exist in the transaction commitment list.
    CommitmentIndexOutOfRange {
        /// Requested commitment index.
        index: usize,
        /// Total number of commitments available.
        commitments_len: usize,
    },
    /// The transaction has a commitment hash at `index` but no matching ciphertext entry.
    MissingCommitmentCiphertext {
        /// Requested commitment index.
        index: usize,
    },
    /// The decoded commitment ciphertext entry could not be normalized.
    InvalidCommitmentCiphertext(CommitmentCiphertextError),
}

impl fmt::Display for TransactionCommitmentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CommitmentIndexOutOfRange { index, commitments_len } => write!(
                formatter,
                "commitment index {index} is out of range for {commitments_len} commitments"
            ),
            Self::MissingCommitmentCiphertext { index } => {
                write!(formatter, "missing commitment ciphertext entry at index {index}")
            }
            Self::InvalidCommitmentCiphertext(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for TransactionCommitmentError {}

fn parse_v2_commitment_ciphertext(
    commitment_ciphertext: &DecodedCommitmentCiphertextV2,
) -> Result<VersionedCommitmentCiphertext, TransactionCommitmentError> {
    let ciphertext_words =
        commitment_ciphertext.ciphertext().iter().map(<[u8; 32]>::as_slice).collect::<Vec<_>>();

    parse_commitment_ciphertext_v2(
        &ciphertext_words,
        commitment_ciphertext.blinded_sender_viewing_key(),
        commitment_ciphertext.blinded_receiver_viewing_key(),
        commitment_ciphertext.annotation_data(),
        commitment_ciphertext.memo(),
    )
    .map(VersionedCommitmentCiphertext::V2)
    .map_err(TransactionCommitmentError::InvalidCommitmentCiphertext)
}

fn parse_v3_commitment_ciphertext(
    commitment_ciphertext: &DecodedCommitmentCiphertextV3,
) -> Result<VersionedCommitmentCiphertext, TransactionCommitmentError> {
    parse_commitment_ciphertext_v3(
        commitment_ciphertext.ciphertext(),
        commitment_ciphertext.blinded_sender_viewing_key(),
        commitment_ciphertext.blinded_receiver_viewing_key(),
    )
    .map(VersionedCommitmentCiphertext::V3)
    .map_err(TransactionCommitmentError::InvalidCommitmentCiphertext)
}

/// Extracts one canonical commitment summary by batch index from a decoded transaction.
///
/// V2 reads local ciphertext entries from `bound_params.commitment_ciphertext[index]`
/// while V3 reads them from `bound_params.local.commitment_ciphertext[index]`.
/// The returned summary preserves the original batch ordering through the caller-supplied
/// `commitment_index`.
///
/// # Errors
///
/// Returns an error if `commitment_index` exceeds the commitment list, if the matching
/// commitment ciphertext entry is missing, or if ciphertext normalization fails.
pub fn extract_commitment_summary(
    transaction: &VersionedTransaction,
    commitment_index: usize,
) -> Result<CommitmentSummary, TransactionCommitmentError> {
    match transaction {
        VersionedTransaction::V2(transaction) => {
            let commitment_hash = transaction.commitments().get(commitment_index).ok_or(
                TransactionCommitmentError::CommitmentIndexOutOfRange {
                    index: commitment_index,
                    commitments_len: transaction.commitments().len(),
                },
            )?;
            let commitment_ciphertext =
                transaction.bound_params().commitment_ciphertext().get(commitment_index).ok_or(
                    TransactionCommitmentError::MissingCommitmentCiphertext {
                        index: commitment_index,
                    },
                )?;

            Ok(CommitmentSummary::new(
                commitment_hash.clone(),
                parse_v2_commitment_ciphertext(commitment_ciphertext)?,
            ))
        }
        VersionedTransaction::V3(transaction) => {
            let commitment_hash = transaction.commitments().get(commitment_index).ok_or(
                TransactionCommitmentError::CommitmentIndexOutOfRange {
                    index: commitment_index,
                    commitments_len: transaction.commitments().len(),
                },
            )?;
            let commitment_ciphertext = transaction
                .bound_params()
                .local()
                .commitment_ciphertext()
                .get(commitment_index)
                .ok_or(TransactionCommitmentError::MissingCommitmentCiphertext {
                    index: commitment_index,
                })?;

            Ok(CommitmentSummary::new(
                commitment_hash.clone(),
                parse_v3_commitment_ciphertext(commitment_ciphertext)?,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;
    use railgunners_types::{
        CommitmentSummary, DecodedCommitmentCiphertextV2, DecodedCommitmentCiphertextV3,
        NoteCommitment, TxidVersion, V2Transaction, V2TransactionBoundParams, V3StoredNonce,
        V3Transaction, V3TransactionBoundParams, V3TransactionBoundParamsLocal,
        VersionedCommitmentCiphertext, VersionedTransaction,
    };

    use super::{TransactionCommitmentError, extract_commitment_summary};

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

    fn decode_hex_vec(value: &str) -> Vec<u8> {
        decode_hex::<1>("00");
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

    fn commitment(value: &str) -> NoteCommitment {
        NoteCommitment::new(BigUint::from_bytes_be(&decode_hex::<32>(value)))
            .unwrap_or_else(|error| panic!("commitment should validate: {error}"))
    }

    fn v2_vector_transaction() -> VersionedTransaction {
        VersionedTransaction::V2(V2Transaction::new(
            TxidVersion::V2PoseidonMerkle,
            vec![commitment("10f1c4ac23f7d0b0e0a6ba3fa23efaf736a44d3e92f6dd37b5d2044cb5c081dd")],
            V2TransactionBoundParams::new(vec![DecodedCommitmentCiphertextV2::new(
                [
                    decode_hex::<32>(
                        "ba002e1e01f1d63d7fa06c83880b2bef23063903d3f4a2b8f7eb800f6c45491c",
                    ),
                    decode_hex::<32>(
                        "8687c2941bddfc807aa3512ebef36e889a82f3885383877e55b7f86e488b6360",
                    ),
                    decode_hex::<32>(
                        "40521d04c766273db030a1ee070706493383f26b8fd677cb51acf0fd30682a37",
                    ),
                    decode_hex::<32>(
                        "6588e860594d6709193c391b4e79de12cecdaed31eef71a2894af5729c0209f7",
                    ),
                ],
                decode_hex::<32>(
                    "2b0f49a1c0fb28ed4cc26fe0531848a25422e5ebdf5bf3df34f67d36d8a484fc",
                ),
                decode_hex::<32>(
                    "2b0f49a1c0fb28ed4cc26fe0531848a25422e5ebdf5bf3df34f67d36d8a484fc",
                ),
                decode_hex_vec(
                    "3f5ff6e7bab3653afd46501dac3d55bd72b33355e41bfc02fcd63a78fe9d5da550957fabde36c9ded90126755f80a3fa3cdd0d84be4686c4192e920d85dd",
                ),
                Vec::new(),
            )]),
        ))
    }

    fn v3_vector_transaction() -> VersionedTransaction {
        VersionedTransaction::V3(V3Transaction::new(
            TxidVersion::V3PoseidonMerkle,
            vec![commitment("29decce78b2f43c718ebb7c6825617ea6881836d88d9551dd2530c44f0d790c5")],
            V3TransactionBoundParams::new(V3TransactionBoundParamsLocal::new(vec![
                DecodedCommitmentCiphertextV3::new(
                    [V3StoredNonce::new([1_u8; 16]).as_bytes().as_slice(), &[2_u8, 3_u8, 4_u8]]
                        .concat(),
                    [5_u8; 32],
                    [6_u8; 32],
                ),
            ])),
        ))
    }

    #[test]
    fn extracts_v2_commitment_summary_from_issue_vector() {
        let summary = extract_commitment_summary(&v2_vector_transaction(), 0)
            .unwrap_or_else(|error| panic!("v2 commitment summary should extract: {error}"));

        assert_eq!(
            summary.commitment_hash(),
            &commitment("10f1c4ac23f7d0b0e0a6ba3fa23efaf736a44d3e92f6dd37b5d2044cb5c081dd")
        );

        let VersionedCommitmentCiphertext::V2(ciphertext) = summary.commitment_ciphertext() else {
            panic!("v2 summary should return a v2 ciphertext");
        };
        assert_eq!(
            ciphertext.ciphertext().iv_tag().as_bytes(),
            &decode_hex::<32>("ba002e1e01f1d63d7fa06c83880b2bef23063903d3f4a2b8f7eb800f6c45491c")
        );
        assert_eq!(
            ciphertext.ciphertext().data()[0].as_bytes(),
            &decode_hex::<32>("8687c2941bddfc807aa3512ebef36e889a82f3885383877e55b7f86e488b6360")
        );
        assert_eq!(ciphertext.ciphertext().memo(), &[] as &[u8]);
        assert_eq!(
            ciphertext.ciphertext().annotation_data(),
            decode_hex_vec(
                "3f5ff6e7bab3653afd46501dac3d55bd72b33355e41bfc02fcd63a78fe9d5da550957fabde36c9ded90126755f80a3fa3cdd0d84be4686c4192e920d85dd",
            )
        );
    }

    #[test]
    fn extracts_v3_commitment_summary_from_local_ciphertext_path() {
        let summary = extract_commitment_summary(&v3_vector_transaction(), 0)
            .unwrap_or_else(|error| panic!("v3 commitment summary should extract: {error}"));

        assert_eq!(
            summary.commitment_hash(),
            &commitment("29decce78b2f43c718ebb7c6825617ea6881836d88d9551dd2530c44f0d790c5")
        );

        let VersionedCommitmentCiphertext::V3(ciphertext) = summary.commitment_ciphertext() else {
            panic!("v3 summary should return a v3 ciphertext");
        };
        assert_eq!(ciphertext.nonce().as_bytes(), &[1_u8; 16]);
        assert_eq!(ciphertext.bundle(), &[2_u8, 3_u8, 4_u8]);
    }

    #[test]
    fn rejects_out_of_range_commitment_index() {
        let Err(error) = extract_commitment_summary(&v2_vector_transaction(), 1) else {
            panic!("out-of-range commitment index should fail");
        };

        assert_eq!(
            error,
            TransactionCommitmentError::CommitmentIndexOutOfRange { index: 1, commitments_len: 1 }
        );
    }

    #[test]
    fn rejects_missing_matching_commitment_ciphertext_entry() {
        let transaction = VersionedTransaction::V2(V2Transaction::new(
            TxidVersion::V2PoseidonMerkle,
            vec![commitment("10f1c4ac23f7d0b0e0a6ba3fa23efaf736a44d3e92f6dd37b5d2044cb5c081dd")],
            V2TransactionBoundParams::new(Vec::new()),
        ));

        let Err(error) = extract_commitment_summary(&transaction, 0) else {
            panic!("missing matching commitment ciphertext should fail");
        };

        assert_eq!(error, TransactionCommitmentError::MissingCommitmentCiphertext { index: 0 });
    }

    #[test]
    fn preserves_normalized_result_shape() {
        let summary = extract_commitment_summary(&v3_vector_transaction(), 0)
            .unwrap_or_else(|error| panic!("summary should extract: {error}"));

        let expected = CommitmentSummary::new(
            commitment("29decce78b2f43c718ebb7c6825617ea6881836d88d9551dd2530c44f0d790c5"),
            VersionedCommitmentCiphertext::V3(railgunners_types::CommitmentCiphertextV3::new(
                railgunners_types::V3CiphertextBundle::new(
                    V3StoredNonce::new([1_u8; 16]),
                    vec![2_u8, 3_u8, 4_u8],
                    Vec::new(),
                ),
                railgunners_types::BlindedViewingPublicKey::new([5_u8; 32]),
                railgunners_types::BlindedViewingPublicKey::new([6_u8; 32]),
            )),
        );

        assert_eq!(summary, expected);
    }
}
