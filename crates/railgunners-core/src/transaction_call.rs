//! Pure decoders for supported RAILGUN transaction calldata.
//!
//! This module understands the exact ABI shape of three supported contract
//! entrypoints and projects their output material onto the existing SDK
//! transaction types so callers can classify payments without duplicating ABI
//! or cryptography:
//!
//! - V2 [`RailgunSmartWallet.transact`](https://github.com/Railgun-Community/engine)
//!   (`0xd8ae136a`)
//! - V2 `RelayAdapt.relay` (`0x28223a77`)
//! - V3 `PoseidonMerkleVerifier.execute` (`0x3474c6fe`)
//!
//! # Output projections
//!
//! [`decode`] returns a [`Call`] carrying the decoded [`CallKind`] and an
//! ordered list of [`VersionedTransaction`] output projections. Each projection
//! keeps commitment hashes and commitment ciphertext entries in their original
//! array order. Relay actions, V3 shield requests, global bound params, proofs,
//! and unshield preimages are parsed for strict ABI validation but are not
//! exposed: this is deliberately not a lossless call serializer.
//!
//! Decoding is ABI-structural. It performs no proof verification, no contract
//! execution semantics, no destination authorization, and no fee or decryption
//! policy. Empty commitment arrays, empty ciphertext arrays, and mismatched
//! counts are preserved so callers can classify missing output material
//! themselves.
//!
//! # Strictness
//!
//! A supported selector is accepted only when the payload decodes with
//! canonical ABI rules and re-encodes to byte-identical input. Trailing bytes,
//! non-canonical offsets, and non-zero padding are therefore rejected.

use core::fmt;

use alloy_sol_types::SolCall;
use num_bigint::BigUint;
use railgunners_types::{
    DecodedCommitmentCiphertextV2, DecodedCommitmentCiphertextV3, NoteCommitment, TxidVersion,
    V2Transaction, V2TransactionBoundParams, V3Transaction, V3TransactionBoundParams,
    V3TransactionBoundParamsLocal, VersionedTransaction,
};

/// Supported RAILGUN transaction call kinds.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CallKind {
    /// V2 `transact(Transaction[])` on the Railgun smart wallet.
    V2Transact,
    /// V2 `relay(Transaction[], ActionData)` on the `RelayAdapt` contract.
    V2Relay,
    /// V3 `execute(Transaction[], ShieldRequest[], GlobalBoundParams, ShieldCiphertext)`.
    V3Execute,
}

/// Error returned when transaction-call decoding fails.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// The input is too short to contain a four-byte function selector.
    ShortInput {
        /// Number of bytes supplied.
        length: usize,
    },
    /// The selector does not match any supported call, including 7702-style
    /// `execute` and `multicall` entrypoints.
    UnsupportedSelector {
        /// The unsupported selector bytes.
        selector: [u8; 4],
    },
    /// The payload did not decode as canonical ABI for the matched selector.
    ///
    /// This covers malformed, truncated, non-canonical, or trailing data.
    MalformedAbi,
    /// A decoded commitment value was not a valid BN254 scalar field element.
    InvalidCommitment {
        /// Index of the transaction carrying the commitment.
        transaction_index: usize,
        /// Index of the invalid commitment within the transaction.
        commitment_index: usize,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShortInput { length } => {
                write!(formatter, "transaction call input is too short: {length} bytes")
            }
            Self::UnsupportedSelector { selector } => write!(
                formatter,
                "unsupported transaction call selector 0x{}",
                encode_hex(selector)
            ),
            Self::MalformedAbi => {
                formatter.write_str("malformed or non-canonical transaction call abi payload")
            }
            Self::InvalidCommitment { transaction_index, commitment_index } => write!(
                formatter,
                "commitment {commitment_index} in transaction {transaction_index} is not a valid field element"
            ),
        }
    }
}

impl std::error::Error for Error {}

/// A decoded supported transaction call projected onto SDK transaction types.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Call {
    kind: CallKind,
    transactions: Vec<VersionedTransaction>,
}

impl Call {
    /// Returns the decoded call kind.
    #[must_use]
    pub const fn kind(&self) -> CallKind {
        self.kind
    }

    /// Returns transaction output projections in original calldata order.
    #[must_use]
    pub fn transactions(&self) -> &[VersionedTransaction] {
        &self.transactions
    }

    /// Consumes the call and returns its owned transaction projections.
    #[must_use]
    pub fn into_transactions(self) -> Vec<VersionedTransaction> {
        self.transactions
    }
}

/// Decodes supported RAILGUN transaction calldata into ordered output projections.
///
/// Supported selectors are V2 `transact` (`0xd8ae136a`), V2 `relay`
/// (`0x28223a77`), and V3 `execute` (`0x3474c6fe`). The function match is exact;
/// unknown selectors, including 7702-style `execute` and `multicall` forms, are
/// rejected.
///
/// The full ABI payload is decoded and re-encoded for byte-identical equality
/// before projection. Commitment hashes and commitment ciphertext entries keep
/// their original batch order, and empty or missing entries stay observable for
/// caller-side classification.
///
/// # Errors
///
/// Returns [`Error::ShortInput`] when fewer than four selector bytes are
/// present, [`Error::UnsupportedSelector`] for an unmatched selector,
/// [`Error::MalformedAbi`] when the payload is not canonical ABI for the matched
/// selector, or [`Error::InvalidCommitment`] when a commitment is not a valid
/// field element.
pub fn decode(input: &[u8]) -> Result<Call, Error> {
    let selector = input
        .get(..SELECTOR_LENGTH)
        .ok_or(Error::ShortInput { length: input.len() })?
        .try_into()
        .map_err(|_| Error::ShortInput { length: input.len() })?;
    let arguments = &input[SELECTOR_LENGTH..];

    if selector == abi::transactCall::SELECTOR {
        let call = abi::transactCall::abi_decode_raw_validate(arguments)
            .map_err(|_| Error::MalformedAbi)?;
        validate_reencoding(&call, arguments)?;
        let transactions = project_v2(&call._transactions)?;

        return Ok(Call { kind: CallKind::V2Transact, transactions });
    }

    if selector == abi::relayCall::SELECTOR {
        let call =
            abi::relayCall::abi_decode_raw_validate(arguments).map_err(|_| Error::MalformedAbi)?;
        validate_reencoding(&call, arguments)?;
        let transactions = project_v2(&call._transactions)?;

        return Ok(Call { kind: CallKind::V2Relay, transactions });
    }

    if selector == abi::executeCall::SELECTOR {
        let call = abi::executeCall::abi_decode_raw_validate(arguments)
            .map_err(|_| Error::MalformedAbi)?;
        validate_reencoding(&call, arguments)?;
        let transactions = project_v3(&call._transactions)?;

        return Ok(Call { kind: CallKind::V3Execute, transactions });
    }

    Err(Error::UnsupportedSelector { selector })
}

const SELECTOR_LENGTH: usize = 4;

fn validate_reencoding<T: SolCall>(call: &T, arguments: &[u8]) -> Result<(), Error> {
    let mut encoded = Vec::with_capacity(arguments.len());
    call.abi_encode_raw(&mut encoded);

    if encoded.as_slice() == arguments { Ok(()) } else { Err(Error::MalformedAbi) }
}

fn commitment_from_bytes(
    bytes: &[u8; 32],
    transaction_index: usize,
    commitment_index: usize,
) -> Result<NoteCommitment, Error> {
    NoteCommitment::new(BigUint::from_bytes_be(bytes))
        .map_err(|_| Error::InvalidCommitment { transaction_index, commitment_index })
}

fn project_v2(transactions: &[abi::TransactionV2]) -> Result<Vec<VersionedTransaction>, Error> {
    transactions
        .iter()
        .enumerate()
        .map(|(transaction_index, transaction)| {
            let commitments = transaction
                .commitments
                .iter()
                .enumerate()
                .map(|(commitment_index, bytes)| {
                    commitment_from_bytes(bytes, transaction_index, commitment_index)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let commitment_ciphertext = transaction
                .boundParams
                .commitmentCiphertext
                .iter()
                .map(|entry| {
                    DecodedCommitmentCiphertextV2::new(
                        [
                            entry.ciphertext[0].0,
                            entry.ciphertext[1].0,
                            entry.ciphertext[2].0,
                            entry.ciphertext[3].0,
                        ],
                        entry.blindedSenderViewingKey.0,
                        entry.blindedReceiverViewingKey.0,
                        entry.annotationData.to_vec(),
                        entry.memo.to_vec(),
                    )
                })
                .collect();

            Ok(VersionedTransaction::V2(V2Transaction::new(
                TxidVersion::V2PoseidonMerkle,
                commitments,
                V2TransactionBoundParams::new(commitment_ciphertext),
            )))
        })
        .collect()
}

fn project_v3(transactions: &[abi::TransactionV3]) -> Result<Vec<VersionedTransaction>, Error> {
    transactions
        .iter()
        .enumerate()
        .map(|(transaction_index, transaction)| {
            let commitments = transaction
                .commitments
                .iter()
                .enumerate()
                .map(|(commitment_index, bytes)| {
                    commitment_from_bytes(bytes, transaction_index, commitment_index)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let commitment_ciphertext = transaction
                .boundParams
                .commitmentCiphertext
                .iter()
                .map(|entry| {
                    DecodedCommitmentCiphertextV3::new(
                        entry.ciphertext.to_vec(),
                        entry.blindedSenderViewingKey.0,
                        entry.blindedReceiverViewingKey.0,
                    )
                })
                .collect();

            Ok(VersionedTransaction::V3(V3Transaction::new(
                TxidVersion::V3PoseidonMerkle,
                commitments,
                V3TransactionBoundParams::new(V3TransactionBoundParamsLocal::new(
                    commitment_ciphertext,
                )),
            )))
        })
        .collect()
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

/// Pinned ABI structs for the supported calldata shapes.
///
/// The full structs are required for canonical decode and byte-identical
/// re-encoding, but stay private so no `alloy` types leak through the public
/// API.
mod abi {
    use alloy_sol_types::sol;

    sol! {
        struct G1Point {
            uint256 x;
            uint256 y;
        }

        struct G2Point {
            uint256[2] x;
            uint256[2] y;
        }

        struct Proof {
            G1Point a;
            G2Point b;
            G1Point c;
        }

        struct TokenData {
            uint8 tokenType;
            address tokenAddress;
            uint256 tokenSubID;
        }

        struct UnshieldPreimage {
            bytes32 npk;
            TokenData token;
            uint120 value;
        }

        struct CommitmentCiphertextV2 {
            bytes32[4] ciphertext;
            bytes32 blindedSenderViewingKey;
            bytes32 blindedReceiverViewingKey;
            bytes annotationData;
            bytes memo;
        }

        struct BoundParamsV2 {
            uint16 treeNumber;
            uint72 minGasPrice;
            uint8 unshield;
            uint64 chainID;
            address adaptContract;
            bytes32 adaptParams;
            CommitmentCiphertextV2[] commitmentCiphertext;
        }

        struct TransactionV2 {
            Proof proof;
            bytes32 merkleRoot;
            bytes32[] nullifiers;
            bytes32[] commitments;
            BoundParamsV2 boundParams;
            UnshieldPreimage unshieldPreimage;
        }

        struct ActionCall {
            address to;
            bytes data;
            uint256 value;
        }

        struct ActionData {
            bytes31 random;
            bool requireSuccess;
            uint256 minGasLimit;
            ActionCall[] calls;
        }

        struct CommitmentCiphertextV3 {
            bytes ciphertext;
            bytes32 blindedSenderViewingKey;
            bytes32 blindedReceiverViewingKey;
        }

        struct BoundParamsV3Local {
            uint32 treeNumber;
            CommitmentCiphertextV3[] commitmentCiphertext;
        }

        struct TransactionV3 {
            Proof proof;
            bytes32 merkleRoot;
            bytes32[] nullifiers;
            bytes32[] commitments;
            BoundParamsV3Local boundParams;
            UnshieldPreimage unshieldPreimage;
        }

        struct ShieldCiphertext {
            bytes32[3] encryptedBundle;
            bytes32 shieldKey;
        }

        struct ShieldRequest {
            ShieldCiphertext ciphertext;
            UnshieldPreimage preimage;
        }

        struct GlobalBoundParams {
            uint128 minGasPrice;
            uint128 chainID;
            bytes senderCiphertext;
            address to;
            bytes data;
        }

        function transact(TransactionV2[] _transactions) external payable;

        function relay(TransactionV2[] _transactions, ActionData _actionData) external payable;

        function execute(
            TransactionV3[] _transactions,
            ShieldRequest[] _shieldRequests,
            GlobalBoundParams _globalBoundParams,
            ShieldCiphertext _unshieldChangeCiphertext
        ) external;
    }
}

#[cfg(test)]
mod tests {
    use alloy_sol_types::SolCall;
    use num_bigint::BigUint;
    use railgunners_types::{
        BlindedViewingPublicKey, MasterPublicKey, NoteCommitment, NoteParty, NotePerspective,
        TxidVersion, VersionedCommitmentCiphertext, VersionedTransaction, ViewingPrivateKey,
        ViewingPublicKey,
    };

    use super::{CallKind, Error, SELECTOR_LENGTH, abi, decode};
    use crate::{
        NoteReconstructionError, TransactionCommitmentError, V2CiphertextError, V3CiphertextError,
        decrypt_v2_ciphertext, decrypt_v3_ciphertext, derive_shared_symmetric_key,
        extract_commitment_summary, reconstruct_v2_note, reconstruct_v3_note,
    };

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct FixtureFile {
        selectors: Selectors,
        note: NoteFixture,
        v2_accepted: Case,
        v2_relay_accepted: Case,
        v2_two_transactions: TwoTransactions,
        v2_empty: Case,
        v2_missing_output: Case,
        v2_invalid_commitment: Case,
        v3_accepted: V3Case,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Selectors {
        v2_transact: String,
        v2_relay: String,
        v3_execute: String,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct NoteFixture {
        receiver_master_public_key: String,
        receiver_viewing_private_key: String,
        receiver_viewing_public_key: String,
        commitment: String,
        shared_key: String,
        blinded_sender_viewing_key: String,
        blinded_receiver_viewing_key: String,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Case {
        calldata: String,
        #[serde(default)]
        commitment: Option<String>,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct TwoTransactions {
        calldata: String,
        commitments: Vec<String>,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct V3Case {
        calldata: String,
        commitment: String,
    }

    fn fixtures() -> FixtureFile {
        serde_json::from_str(include_str!("../testdata/transaction_call/fixtures.json"))
            .unwrap_or_else(|error| panic!("transaction_call fixtures should parse: {error}"))
    }

    fn hex_bytes(value: &str) -> Vec<u8> {
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

    fn hex32(value: &str) -> [u8; 32] {
        hex_bytes(value).try_into().unwrap_or_else(|_| panic!("expected a 32-byte hex value"))
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

    fn commitment(value: &str) -> NoteCommitment {
        NoteCommitment::new(BigUint::from_bytes_be(&hex32(value)))
            .unwrap_or_else(|error| panic!("commitment should validate: {error}"))
    }

    fn receiver_party(note: &NoteFixture) -> NoteParty {
        NoteParty::new(
            MasterPublicKey::new(BigUint::from_bytes_be(&hex32(&note.receiver_master_public_key)))
                .unwrap_or_else(|error| {
                    panic!("receiver master public key should validate: {error}")
                }),
            ViewingPublicKey::new(hex32(&note.receiver_viewing_public_key)),
        )
    }

    fn blinded_keys(note: &NoteFixture) -> (BlindedViewingPublicKey, BlindedViewingPublicKey) {
        (
            BlindedViewingPublicKey::new(hex32(&note.blinded_sender_viewing_key)),
            BlindedViewingPublicKey::new(hex32(&note.blinded_receiver_viewing_key)),
        )
    }

    #[test]
    fn selectors_match_independent_abi_evidence() {
        let fixtures = fixtures();

        assert_eq!(fixtures.selectors.v2_transact, "0xd8ae136a");
        assert_eq!(fixtures.selectors.v2_relay, "0x28223a77");
        assert_eq!(fixtures.selectors.v3_execute, "0x3474c6fe");

        assert_eq!(hex_encode(&abi::transactCall::SELECTOR), "d8ae136a");
        assert_eq!(hex_encode(&abi::relayCall::SELECTOR), "28223a77");
        assert_eq!(hex_encode(&abi::executeCall::SELECTOR), "3474c6fe");
    }

    #[test]
    fn decodes_v2_transact_fixture() {
        let fixtures = fixtures();
        let call = decode(&hex_bytes(&fixtures.v2_accepted.calldata))
            .unwrap_or_else(|error| panic!("v2 transact fixture should decode: {error}"));

        assert_eq!(call.kind(), CallKind::V2Transact);
        assert_eq!(call.transactions().len(), 1);

        let VersionedTransaction::V2(transaction) = &call.transactions()[0] else {
            panic!("v2 transact fixture should project a v2 transaction");
        };
        assert_eq!(transaction.txid_version(), TxidVersion::V2PoseidonMerkle);
        assert_eq!(transaction.commitments().len(), 1);
        assert_eq!(
            transaction.commitments()[0],
            commitment(
                &fixtures
                    .v2_accepted
                    .commitment
                    .clone()
                    .unwrap_or_else(|| panic!("v2 accepted fixture should carry a commitment"))
            )
        );
        assert_eq!(transaction.bound_params().commitment_ciphertext().len(), 1);
    }

    #[test]
    fn decodes_v2_relay_fixture_without_exposing_actions() {
        let fixtures = fixtures();
        let call = decode(&hex_bytes(&fixtures.v2_relay_accepted.calldata))
            .unwrap_or_else(|error| panic!("v2 relay fixture should decode: {error}"));

        assert_eq!(call.kind(), CallKind::V2Relay);
        assert_eq!(call.transactions().len(), 1);
        assert!(matches!(call.transactions()[0], VersionedTransaction::V2(_)));
    }

    #[test]
    fn decodes_v3_execute_fixture() {
        let fixtures = fixtures();
        let call = decode(&hex_bytes(&fixtures.v3_accepted.calldata))
            .unwrap_or_else(|error| panic!("v3 execute fixture should decode: {error}"));

        assert_eq!(call.kind(), CallKind::V3Execute);
        assert_eq!(call.transactions().len(), 1);

        let VersionedTransaction::V3(transaction) = &call.transactions()[0] else {
            panic!("v3 execute fixture should project a v3 transaction");
        };
        assert_eq!(transaction.txid_version(), TxidVersion::V3PoseidonMerkle);
        assert_eq!(transaction.commitments(), &[commitment(&fixtures.v3_accepted.commitment)]);
        assert_eq!(transaction.bound_params().local().commitment_ciphertext().len(), 1);
    }

    #[test]
    fn preserves_empty_batch_and_batch_order() {
        let fixtures = fixtures();

        let empty = decode(&hex_bytes(&fixtures.v2_empty.calldata))
            .unwrap_or_else(|error| panic!("empty batch fixture should decode: {error}"));
        assert_eq!(empty.kind(), CallKind::V2Transact);
        assert!(empty.transactions().is_empty());

        let ordered = decode(&hex_bytes(&fixtures.v2_two_transactions.calldata))
            .unwrap_or_else(|error| panic!("two-transaction fixture should decode: {error}"));
        assert_eq!(ordered.transactions().len(), 2);
        assert_ne!(ordered.transactions()[0], ordered.transactions()[1]);

        for (transaction, expected) in
            ordered.transactions().iter().zip(&fixtures.v2_two_transactions.commitments)
        {
            let VersionedTransaction::V2(transaction) = transaction else {
                panic!("two-transaction fixture should project v2 transactions");
            };
            assert_eq!(transaction.commitments(), &[commitment(expected)]);
        }

        let first = extract_commitment_summary(&ordered.transactions()[0], 0)
            .unwrap_or_else(|error| panic!("first output should extract: {error}"));
        assert_eq!(
            first.commitment_hash(),
            &commitment(&fixtures.v2_two_transactions.commitments[0])
        );
    }

    #[test]
    fn preserves_missing_output_entries() {
        let fixtures = fixtures();
        let call = decode(&hex_bytes(&fixtures.v2_missing_output.calldata))
            .unwrap_or_else(|error| panic!("missing-output fixture should decode: {error}"));

        let VersionedTransaction::V2(transaction) = &call.transactions()[0] else {
            panic!("missing-output fixture should project a v2 transaction");
        };
        assert_eq!(transaction.commitments().len(), 1);
        assert!(transaction.bound_params().commitment_ciphertext().is_empty());

        assert_eq!(
            extract_commitment_summary(&call.transactions()[0], 0),
            Err(TransactionCommitmentError::MissingCommitmentCiphertext { index: 0 })
        );
    }

    #[test]
    fn rejects_non_field_commitment_without_panic() {
        let fixtures = fixtures();
        assert_eq!(
            decode(&hex_bytes(&fixtures.v2_invalid_commitment.calldata)),
            Err(Error::InvalidCommitment { transaction_index: 0, commitment_index: 0 })
        );
    }

    #[test]
    fn rejects_short_and_unknown_selectors() {
        assert_eq!(decode(&[]), Err(Error::ShortInput { length: 0 }));
        assert_eq!(decode(&[0x01, 0x02, 0x03]), Err(Error::ShortInput { length: 3 }));
        assert_eq!(
            decode(&[0xde, 0xad, 0xbe, 0xef, 0x00]),
            Err(Error::UnsupportedSelector { selector: [0xde, 0xad, 0xbe, 0xef] })
        );
    }

    #[test]
    fn rejects_7702_execute_and_multicall_selectors() {
        // RAILGUN RelayAdapt7702 execute variants and multicall, followed by
        // adjacent account entrypoints, must never match the V3 execute selector.
        for selector in [
            [0xdb, 0x43, 0xcb, 0x8f],
            [0x19, 0xac, 0x07, 0x55],
            [0x7a, 0x0d, 0xc2, 0xa5],
            [0xe9, 0xae, 0x5c, 0x53],
            [0x24, 0x85, 0x6b, 0xc3],
            [0xac, 0x96, 0x50, 0xd8],
        ] {
            let mut input = selector.to_vec();
            input.extend_from_slice(&[0_u8; 64]);
            assert_eq!(decode(&input), Err(Error::UnsupportedSelector { selector }));
        }
    }

    #[test]
    fn rejects_truncated_trailing_and_noncanonical_payloads() {
        let fixtures = fixtures();
        let calldata = hex_bytes(&fixtures.v2_accepted.calldata);

        let mut truncated = calldata.clone();
        truncated.pop();
        assert_eq!(decode(&truncated), Err(Error::MalformedAbi));

        let mut trailing = calldata.clone();
        trailing.push(0);
        assert_eq!(decode(&trailing), Err(Error::MalformedAbi));

        let mut bad_offset = calldata.clone();
        bad_offset[SELECTOR_LENGTH..SELECTOR_LENGTH + 32].fill(0);
        bad_offset[SELECTOR_LENGTH + 30] = 0x20;
        assert_eq!(decode(&bad_offset), Err(Error::MalformedAbi));

        let mut bad_padding = calldata;
        let padding_index = bad_padding.len() - 34;
        assert_eq!(bad_padding[padding_index], 0, "expected annotation-data padding byte");
        bad_padding[padding_index] = 1;
        assert_eq!(decode(&bad_padding), Err(Error::MalformedAbi));
    }

    #[test]
    fn v2_accepted_fixture_reconstructs_received_note() {
        let fixtures = fixtures();
        let note = &fixtures.note;
        let call = decode(&hex_bytes(&fixtures.v2_accepted.calldata))
            .unwrap_or_else(|error| panic!("v2 accepted fixture should decode: {error}"));
        let summary = extract_commitment_summary(&call.transactions()[0], 0)
            .unwrap_or_else(|error| panic!("v2 commitment summary should extract: {error}"));
        assert_eq!(summary.commitment_hash(), &commitment(&note.commitment));

        let receiver_viewing_private_key =
            ViewingPrivateKey::new(hex32(&note.receiver_viewing_private_key));
        let (blinded_sender, blinded_receiver) = blinded_keys(note);
        let shared_key =
            derive_shared_symmetric_key(&receiver_viewing_private_key, &blinded_sender)
                .unwrap_or_else(|error| panic!("receiver shared key should derive: {error}"));
        assert_eq!(hex_encode(shared_key.as_bytes()), note.shared_key);

        let VersionedCommitmentCiphertext::V2(ciphertext) = summary.commitment_ciphertext() else {
            panic!("v2 accepted fixture should yield a v2 ciphertext");
        };
        let plaintext = decrypt_v2_ciphertext(ciphertext.ciphertext(), &shared_key)
            .unwrap_or_else(|error| panic!("v2 ciphertext should decrypt: {error}"));

        let reconstructed = reconstruct_v2_note(
            &plaintext,
            &receiver_party(note),
            &blinded_sender,
            &blinded_receiver,
            NotePerspective::Received,
            None,
            summary.commitment_hash(),
        )
        .unwrap_or_else(|error| panic!("received v2 note should reconstruct: {error}"));
        assert_eq!(reconstructed.note().commitment(), summary.commitment_hash());
        assert_eq!(
            reconstructed.note().receiver().master_public_key(),
            receiver_party(note).master_public_key()
        );

        let mut wrong_bytes = hex32(&note.receiver_viewing_private_key);
        wrong_bytes[0] ^= 1;
        let wrong_key =
            derive_shared_symmetric_key(&ViewingPrivateKey::new(wrong_bytes), &blinded_sender)
                .unwrap_or_else(|error| panic!("wrong shared key should still derive: {error}"));
        assert_ne!(wrong_key, shared_key);
        assert_eq!(
            decrypt_v2_ciphertext(ciphertext.ciphertext(), &wrong_key),
            Err(V2CiphertextError::AuthenticationFailed)
        );

        let mut tampered_bytes = hex32(&note.commitment);
        tampered_bytes[31] ^= 1;
        let tampered_commitment = NoteCommitment::new(BigUint::from_bytes_be(&tampered_bytes))
            .unwrap_or_else(|error| panic!("tampered commitment should remain valid: {error}"));
        assert_eq!(
            reconstruct_v2_note(
                &plaintext,
                &receiver_party(note),
                &blinded_sender,
                &blinded_receiver,
                NotePerspective::Received,
                None,
                &tampered_commitment,
            ),
            Err(NoteReconstructionError::CommitmentMismatch)
        );
    }

    #[test]
    fn v3_accepted_fixture_reconstructs_received_note() {
        let fixtures = fixtures();
        let note = &fixtures.note;
        let call = decode(&hex_bytes(&fixtures.v3_accepted.calldata))
            .unwrap_or_else(|error| panic!("v3 accepted fixture should decode: {error}"));
        assert_eq!(call.kind(), CallKind::V3Execute);
        let summary = extract_commitment_summary(&call.transactions()[0], 0)
            .unwrap_or_else(|error| panic!("v3 commitment summary should extract: {error}"));
        assert_eq!(summary.commitment_hash(), &commitment(&fixtures.v3_accepted.commitment));

        let receiver_viewing_private_key =
            ViewingPrivateKey::new(hex32(&note.receiver_viewing_private_key));
        let (blinded_sender, blinded_receiver) = blinded_keys(note);
        let shared_key =
            derive_shared_symmetric_key(&receiver_viewing_private_key, &blinded_sender)
                .unwrap_or_else(|error| panic!("receiver shared key should derive: {error}"));

        let VersionedCommitmentCiphertext::V3(ciphertext) = summary.commitment_ciphertext() else {
            panic!("v3 accepted fixture should yield a v3 ciphertext");
        };
        let plaintext = decrypt_v3_ciphertext(ciphertext.ciphertext(), &shared_key)
            .unwrap_or_else(|error| panic!("v3 ciphertext should decrypt: {error}"));

        let reconstructed = reconstruct_v3_note(
            &plaintext,
            &receiver_party(note),
            &blinded_sender,
            &blinded_receiver,
            NotePerspective::Received,
            summary.commitment_hash(),
        )
        .unwrap_or_else(|error| panic!("received v3 note should reconstruct: {error}"));
        assert_eq!(reconstructed.note().commitment(), summary.commitment_hash());

        let mut wrong_bytes = hex32(&note.receiver_viewing_private_key);
        wrong_bytes[31] ^= 1;
        let wrong_key =
            derive_shared_symmetric_key(&ViewingPrivateKey::new(wrong_bytes), &blinded_sender)
                .unwrap_or_else(|error| panic!("wrong shared key should still derive: {error}"));
        assert_eq!(
            decrypt_v3_ciphertext(ciphertext.ciphertext(), &wrong_key),
            Err(V3CiphertextError::AuthenticationFailed)
        );
    }
}
