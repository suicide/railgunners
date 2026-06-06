//! Transaction-local receipt inspection for public Railgun outcomes.

use core::fmt;

use railgunners_types::{
    PublicRailgunEventKind, PublicRailgunTransactionSummary, RawTransactionReceipt,
    TransactionReceiptStatus, TxHash, VersionedCommitmentEvent, VersionedNullifierEvent,
    VersionedUnshieldEvent,
};

use crate::{
    DecodedRailgunLogEvent, RawRailgunLog, RawRailgunLogError, RawRailgunLogVersion,
    decode_raw_railgun_log,
};

/// High-level receipt-local public inspection output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptPublicOutcome {
    summary: PublicRailgunTransactionSummary,
    ordered_events: Vec<DecodedRailgunLogEvent>,
}

impl ReceiptPublicOutcome {
    /// Creates the public inspection output for one receipt.
    #[must_use]
    pub fn new(
        summary: PublicRailgunTransactionSummary,
        ordered_events: Vec<DecodedRailgunLogEvent>,
    ) -> Self {
        Self { summary, ordered_events }
    }

    /// Returns the transaction-local public summary.
    #[must_use]
    pub const fn summary(&self) -> &PublicRailgunTransactionSummary {
        &self.summary
    }

    /// Returns decoded Railgun events in deterministic emitted order.
    #[must_use]
    pub fn ordered_events(&self) -> &[DecodedRailgunLogEvent] {
        &self.ordered_events
    }
}

/// Error returned when receipt-local Railgun inspection fails.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReceiptInspectionError {
    /// One supported Railgun log disagreed with the receipt transaction hash.
    TransactionHashMismatch {
        /// Transaction hash supplied by the receipt.
        receipt_transaction_hash: TxHash,
        /// Transaction hash attached to the supported Railgun log.
        log_transaction_hash: TxHash,
    },
    /// A failed receipt unexpectedly carried supported Railgun logs.
    FailedReceiptContainedRailgunEvents,
    /// Raw Railgun log decoding failed.
    RawLog(RawRailgunLogError),
}

impl fmt::Display for ReceiptInspectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TransactionHashMismatch { receipt_transaction_hash, log_transaction_hash } => {
                write!(
                    formatter,
                    "receipt transaction hash {:02x?} does not match Railgun log transaction hash {:02x?}",
                    receipt_transaction_hash.as_bytes(),
                    log_transaction_hash.as_bytes(),
                )
            }
            Self::FailedReceiptContainedRailgunEvents => {
                formatter.write_str("failed receipt unexpectedly contained supported Railgun logs")
            }
            Self::RawLog(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for ReceiptInspectionError {}

impl From<RawRailgunLogError> for ReceiptInspectionError {
    fn from(error: RawRailgunLogError) -> Self {
        Self::RawLog(error)
    }
}

fn event_kind(event: &DecodedRailgunLogEvent) -> PublicRailgunEventKind {
    match event {
        DecodedRailgunLogEvent::Commitment(_) => PublicRailgunEventKind::Commitment,
        DecodedRailgunLogEvent::Nullifier(_) => PublicRailgunEventKind::Nullifier,
        DecodedRailgunLogEvent::Unshield(_) => PublicRailgunEventKind::Unshield,
    }
}

fn build_summary(
    receipt: RawTransactionReceipt,
    ordered_events: &[DecodedRailgunLogEvent],
) -> PublicRailgunTransactionSummary {
    let mut event_kinds_in_order = Vec::with_capacity(ordered_events.len());
    let mut commitment_events = Vec::<VersionedCommitmentEvent>::new();
    let mut nullifier_events = Vec::<VersionedNullifierEvent>::new();
    let mut unshield_events = Vec::<VersionedUnshieldEvent>::new();

    for event in ordered_events {
        event_kinds_in_order.push(event_kind(event));

        match event {
            DecodedRailgunLogEvent::Commitment(event) => commitment_events.push(event.clone()),
            DecodedRailgunLogEvent::Nullifier(event) => nullifier_events.push(event.clone()),
            DecodedRailgunLogEvent::Unshield(event) => unshield_events.push(event.clone()),
        }
    }

    PublicRailgunTransactionSummary::new(
        receipt.status(),
        receipt.transaction_hash(),
        event_kinds_in_order,
        commitment_events,
        nullifier_events,
        unshield_events,
    )
}

/// Inspects one transaction receipt for transaction-local public Railgun outcomes.
///
/// The caller supplies a resolver that identifies which raw logs should be treated as supported
/// Railgun logs and which contract version each of those logs belongs to. Logs that resolve to
/// `None` are ignored without affecting the ordering of supported Railgun events.
///
/// # Errors
///
/// Returns an error when a supported Railgun log disagrees with the receipt transaction hash,
/// when a selected Railgun log cannot be decoded, or when a failed receipt unexpectedly contains
/// supported Railgun logs.
pub fn inspect_public_railgun_receipt<F>(
    receipt: &RawTransactionReceipt,
    raw_logs: &[RawRailgunLog],
    mut resolve_version: F,
) -> Result<ReceiptPublicOutcome, ReceiptInspectionError>
where
    F: FnMut(&RawRailgunLog) -> Option<RawRailgunLogVersion>,
{
    let mut ordered_events = Vec::new();

    for log in raw_logs {
        let Some(version) = resolve_version(log) else {
            continue;
        };

        if let Some(log_transaction_hash) = log.transaction_hash {
            if log_transaction_hash != receipt.transaction_hash() {
                return Err(ReceiptInspectionError::TransactionHashMismatch {
                    receipt_transaction_hash: receipt.transaction_hash(),
                    log_transaction_hash,
                });
            }
        }

        ordered_events.extend(decode_raw_railgun_log(version, log)?);
    }

    if receipt.status() == TransactionReceiptStatus::Failure && !ordered_events.is_empty() {
        return Err(ReceiptInspectionError::FailedReceiptContainedRailgunEvents);
    }

    let summary = build_summary(*receipt, &ordered_events);
    Ok(ReceiptPublicOutcome::new(summary, ordered_events))
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{
        Address as AlloyAddress, Bytes, FixedBytes, U256,
        aliases::{U120, U224},
    };
    use alloy_sol_types::{SolEvent, sol};
    use railgunners_types::{
        CommitmentLeafPosition, PublicRailgunEventKind, RawTransactionReceipt,
        TransactionReceiptStatus, TxHash,
    };

    use super::{ReceiptInspectionError, inspect_public_railgun_receipt};
    use crate::{RawRailgunLog, RawRailgunLogError, RawRailgunLogVersion};

    sol! {
        struct EventV2CommitmentCiphertextAbi {
            bytes32[4] ciphertext;
            bytes32 blindedSenderViewingKey;
            bytes32 blindedReceiverViewingKey;
            bytes annotationData;
            bytes memo;
        }

        event V2TransactLog(
            uint256 treeNumber,
            uint256 startPosition,
            bytes32[] hash,
            EventV2CommitmentCiphertextAbi[] ciphertext
        );

        event V2UnshieldLog(address to, EventTokenDataAbi token, uint256 amount, uint256 fee);

        struct EventTokenDataAbi {
            uint8 tokenType;
            address tokenAddress;
            uint256 tokenSubID;
        }

        struct EventCommitmentPreimageAbi {
            bytes32 npk;
            EventTokenDataAbi token;
            uint120 value;
        }

        struct EventShieldCiphertextAbi {
            bytes32[3] encryptedBundle;
            bytes32 shieldKey;
        }

        struct EventV3TransactionConfigurationAbi {
            bytes32[] nullifiers;
            uint8 commitmentsCount;
            uint32 spendAccumulatorNumber;
            EventCommitmentPreimageAbi unshieldPreimage;
            bytes32 boundParamsHash;
        }

        struct EventV3ShieldConfigurationAbi {
            address from;
            EventCommitmentPreimageAbi preimage;
            EventShieldCiphertextAbi ciphertext;
        }

        struct EventV3CommitmentCiphertextAbi {
            bytes ciphertext;
            bytes32 blindedSenderViewingKey;
            bytes32 blindedReceiverViewingKey;
        }

        struct EventV3TreasuryFeeAbi {
            bytes32 tokenID;
            uint256 fee;
        }

        struct EventV3StateUpdateAbi {
            bytes32[] commitments;
            EventV3TransactionConfigurationAbi[] transactions;
            EventV3ShieldConfigurationAbi[] shields;
            EventV3CommitmentCiphertextAbi[] commitmentCiphertext;
            EventV3TreasuryFeeAbi[] treasuryFees;
            bytes senderCiphertext;
        }

        event V3AccumulatorStateUpdateLog(
            EventV3StateUpdateAbi update,
            uint32 accumulatorNumber,
            uint224 startPosition
        );

        event UnrelatedLog(bytes32 value);
    }

    fn tx_hash(byte: u8) -> TxHash {
        TxHash::new([byte; 32])
    }

    fn receipt(status: TransactionReceiptStatus, byte: u8) -> RawTransactionReceipt {
        RawTransactionReceipt::new(status, tx_hash(byte))
    }

    fn address(byte: u8) -> railgunners_types::Address {
        railgunners_types::Address::new([byte; 20])
    }

    fn alloy_address(byte: u8) -> AlloyAddress {
        AlloyAddress::from([byte; 20])
    }

    fn raw_log(
        log_data: &alloy_primitives::LogData,
        transaction_hash_byte: u8,
        block_number: u64,
        log_index: Option<u64>,
    ) -> RawRailgunLog {
        RawRailgunLog {
            contract_address: address(0x90),
            topics: log_data
                .topics()
                .iter()
                .map(|topic| {
                    topic.as_slice().try_into().unwrap_or_else(|_| panic!("topic must be 32 bytes"))
                })
                .collect(),
            data: log_data.data.to_vec(),
            transaction_hash: Some(tx_hash(transaction_hash_byte)),
            block_number: Some(block_number),
            log_index,
        }
    }

    fn v2_transact_log(transaction_hash_byte: u8) -> RawRailgunLog {
        raw_log(
            &V2TransactLog {
                treeNumber: U256::ZERO,
                startPosition: U256::from(1_u8),
                hash: vec![FixedBytes::from({
                    let mut bytes = [0_u8; 32];
                    bytes[31] = 1;
                    bytes
                })],
                ciphertext: vec![EventV2CommitmentCiphertextAbi {
                    ciphertext: [
                        FixedBytes::from([1_u8; 32]),
                        FixedBytes::from([2_u8; 32]),
                        FixedBytes::from([3_u8; 32]),
                        FixedBytes::from([4_u8; 32]),
                    ],
                    blindedSenderViewingKey: FixedBytes::from([5_u8; 32]),
                    blindedReceiverViewingKey: FixedBytes::from([6_u8; 32]),
                    annotationData: Bytes::from(vec![7_u8, 8_u8]),
                    memo: Bytes::from(vec![9_u8, 10_u8]),
                }],
            }
            .encode_log_data(),
            transaction_hash_byte,
            99,
            None,
        )
    }

    fn v3_accumulator_log(transaction_hash_byte: u8) -> RawRailgunLog {
        raw_log(
            &V3AccumulatorStateUpdateLog {
                update: EventV3StateUpdateAbi {
                    commitments: vec![FixedBytes::from({
                        let mut bytes = [0_u8; 32];
                        bytes[31] = 3;
                        bytes
                    })],
                    transactions: vec![EventV3TransactionConfigurationAbi {
                        nullifiers: vec![FixedBytes::from({
                            let mut bytes = [0_u8; 32];
                            bytes[31] = 4;
                            bytes
                        })],
                        commitmentsCount: 1,
                        spendAccumulatorNumber: 0,
                        unshieldPreimage: EventCommitmentPreimageAbi {
                            npk: FixedBytes::from({
                                let mut bytes = [0_u8; 32];
                                bytes[12..].fill(0x41);
                                bytes
                            }),
                            token: EventTokenDataAbi {
                                tokenType: 0,
                                tokenAddress: alloy_address(0x11),
                                tokenSubID: U256::ZERO,
                            },
                            value: U120::from(50_u8),
                        },
                        boundParamsHash: FixedBytes::from({
                            let mut bytes = [0_u8; 32];
                            bytes[31] = 0x51;
                            bytes
                        }),
                    }],
                    shields: vec![EventV3ShieldConfigurationAbi {
                        from: alloy_address(0x22),
                        preimage: EventCommitmentPreimageAbi {
                            npk: FixedBytes::from({
                                let mut bytes = [0_u8; 32];
                                bytes[31] = 12;
                                bytes
                            }),
                            token: EventTokenDataAbi {
                                tokenType: 0,
                                tokenAddress: alloy_address(0x11),
                                tokenSubID: U256::ZERO,
                            },
                            value: U120::from(100_u8),
                        },
                        ciphertext: EventShieldCiphertextAbi {
                            encryptedBundle: [
                                FixedBytes::from([0x21_u8; 32]),
                                FixedBytes::from([0x22_u8; 32]),
                                FixedBytes::from({
                                    let mut bytes = [0_u8; 32];
                                    bytes[..16].fill(0x23);
                                    bytes
                                }),
                            ],
                            shieldKey: FixedBytes::from([0x24_u8; 32]),
                        },
                    }],
                    commitmentCiphertext: vec![EventV3CommitmentCiphertextAbi {
                        ciphertext: Bytes::from(vec![7_u8; 20]),
                        blindedSenderViewingKey: FixedBytes::from([8_u8; 32]),
                        blindedReceiverViewingKey: FixedBytes::from([9_u8; 32]),
                    }],
                    treasuryFees: Vec::new(),
                    senderCiphertext: Bytes::from(vec![0xaa_u8, 0xbb_u8]),
                },
                accumulatorNumber: 0,
                startPosition: U224::from(1_u8),
            }
            .encode_log_data(),
            transaction_hash_byte,
            10,
            None,
        )
    }

    fn unrelated_log(transaction_hash_byte: u8) -> RawRailgunLog {
        raw_log(
            &UnrelatedLog { value: FixedBytes::from([0x44_u8; 32]) }.encode_log_data(),
            transaction_hash_byte,
            77,
            None,
        )
    }

    #[test]
    fn inspects_successful_v2_receipt_into_summary_and_ordered_events() {
        let outcome = inspect_public_railgun_receipt(
            &receipt(TransactionReceiptStatus::Success, 0xaa),
            &[v2_transact_log(0xaa)],
            |_| Some(RawRailgunLogVersion::V2),
        )
        .unwrap_or_else(|error| panic!("successful v2 receipt should inspect: {error}"));

        assert_eq!(outcome.summary().status(), TransactionReceiptStatus::Success);
        assert_eq!(outcome.summary().transaction_hash(), tx_hash(0xaa));
        assert_eq!(outcome.summary().event_kinds_in_order(), &[PublicRailgunEventKind::Commitment]);
        assert_eq!(outcome.summary().commitment_events().len(), 1);
        assert!(outcome.summary().nullifier_events().is_empty());
        assert!(outcome.summary().unshield_events().is_empty());
        assert_eq!(outcome.ordered_events().len(), 1);

        let crate::DecodedRailgunLogEvent::Commitment(
            railgunners_types::VersionedCommitmentEvent::V2(event),
        ) = &outcome.ordered_events()[0]
        else {
            panic!("expected one v2 commitment event");
        };
        assert_eq!(event.start_position(), CommitmentLeafPosition::new(1));
    }

    #[test]
    fn ignores_unrelated_logs_without_corrupting_railgun_event_order() {
        let logs = [unrelated_log(0xee), v3_accumulator_log(0xee), unrelated_log(0xee)];
        let outcome = inspect_public_railgun_receipt(
            &receipt(TransactionReceiptStatus::Success, 0xee),
            &logs,
            |log| {
                if log.topics.first().is_some_and(|topic| {
                    topic.as_slice() == V3AccumulatorStateUpdateLog::SIGNATURE_HASH.as_slice()
                }) {
                    Some(RawRailgunLogVersion::V3)
                } else {
                    None
                }
            },
        )
        .unwrap_or_else(|error| panic!("mixed receipt should inspect: {error}"));

        assert_eq!(
            outcome.summary().event_kinds_in_order(),
            &[
                PublicRailgunEventKind::Commitment,
                PublicRailgunEventKind::Nullifier,
                PublicRailgunEventKind::Unshield,
                PublicRailgunEventKind::Commitment,
            ]
        );
        assert_eq!(outcome.ordered_events().len(), 4);
    }

    #[test]
    fn summarizes_failed_receipt_without_supported_railgun_logs() {
        let outcome = inspect_public_railgun_receipt(
            &receipt(TransactionReceiptStatus::Failure, 0xbb),
            &[unrelated_log(0xbb)],
            |_| None,
        )
        .unwrap_or_else(|error| {
            panic!("failed receipt without Railgun logs should inspect: {error}")
        });

        assert_eq!(outcome.summary().status(), TransactionReceiptStatus::Failure);
        assert!(outcome.summary().event_kinds_in_order().is_empty());
        assert!(outcome.ordered_events().is_empty());
    }

    #[test]
    fn rejects_supported_log_with_mismatched_transaction_hash() {
        let Err(error) = inspect_public_railgun_receipt(
            &receipt(TransactionReceiptStatus::Success, 0xaa),
            &[v2_transact_log(0xab)],
            |_| Some(RawRailgunLogVersion::V2),
        ) else {
            panic!("mismatched transaction hash should fail");
        };

        assert_eq!(
            error,
            ReceiptInspectionError::TransactionHashMismatch {
                receipt_transaction_hash: tx_hash(0xaa),
                log_transaction_hash: tx_hash(0xab),
            }
        );
    }

    #[test]
    fn rejects_supported_log_with_missing_required_context() {
        let log = raw_log(
            &V2UnshieldLog {
                to: alloy_address(0x31),
                token: EventTokenDataAbi {
                    tokenType: 0,
                    tokenAddress: alloy_address(0x11),
                    tokenSubID: U256::ZERO,
                },
                amount: U256::from(100_u8),
                fee: U256::from(1_u8),
            }
            .encode_log_data(),
            0xdd,
            8,
            None,
        );

        let Err(error) = inspect_public_railgun_receipt(
            &receipt(TransactionReceiptStatus::Success, 0xdd),
            &[log],
            |_| Some(RawRailgunLogVersion::V2),
        ) else {
            panic!("missing supported log context should fail");
        };

        assert_eq!(
            error,
            ReceiptInspectionError::RawLog(RawRailgunLogError::MissingContext("log_index"))
        );
    }

    #[test]
    fn rejects_failed_receipt_that_contains_supported_railgun_logs() {
        let Err(error) = inspect_public_railgun_receipt(
            &receipt(TransactionReceiptStatus::Failure, 0xaa),
            &[v2_transact_log(0xaa)],
            |_| Some(RawRailgunLogVersion::V2),
        ) else {
            panic!("failed receipt with Railgun logs should fail");
        };

        assert_eq!(error, ReceiptInspectionError::FailedReceiptContainedRailgunEvents);
    }
}
