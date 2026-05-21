//! Decoded V2 and V3 event normalization into canonical typed event models.

use core::fmt;

use alloy_primitives::{Bytes, FixedBytes, LogData, U256};
use alloy_sol_types::{SolEvent, sol};
use num_bigint::BigUint;
use railgun_types::{
    AccumulatorTransactionIndex, Address, BlockNumber, BoundParamsHash, CommitmentLeafPosition,
    DecodedCommitmentCiphertextV2, DecodedCommitmentCiphertextV3, EventLogIndex, NoteCommitment,
    NotePublicKey, NoteValue, Nullifier, ParseDomainError, RailgunTxid, SenderCiphertext,
    ShieldCommitment, ShieldPreimage, TREE_MAX_ITEMS, TokenData, TokenHash, TokenSubId, TokenType,
    TransactCommitmentBatchIndex, TxHash, UnshieldData, UtxoLeafCoordinate, UtxoTreeCoordinate,
    V2Commitment, V2CommitmentEvent, V2NullifierEvent, V2TransactCommitment, V2UnshieldEvent,
    V3Commitment, V3CommitmentEvent, V3NullifierEvent, V3TransactCommitment, V3TransactionEvent,
    V3TransactionUnshieldData, V3UnshieldEvent, VerificationHash, VersionedCommitmentEvent,
    VersionedNullifierEvent, VersionedUnshieldEvent,
};

use crate::{
    CommitmentCiphertextError, KeyDerivationError, ShieldCiphertextError, derive_note_commitment,
    derive_railgun_txid, derive_token_hash, parse_commitment_ciphertext_v2,
    parse_commitment_ciphertext_v3, parse_shield_ciphertext,
};

sol! {
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

    event V2ShieldLog(
        uint256 treeNumber,
        uint256 startPosition,
        EventCommitmentPreimageAbi[] commitments,
        EventShieldCiphertextAbi[] shieldCiphertext,
        uint256[] fees
    );

    event V2NullifiedLog(uint16 treeNumber, bytes32[] nullifier);

    event V2UnshieldLog(address to, EventTokenDataAbi token, uint256 amount, uint256 fee);

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
}

/// Error returned when decoded event normalization fails.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EventError {
    /// A required decoded field was missing.
    MissingField(&'static str),
    /// One decoded byte field had the wrong length.
    InvalidLength {
        /// Field name.
        field: &'static str,
        /// Expected length in bytes.
        expected: usize,
        /// Actual length in bytes.
        actual: usize,
    },
    /// Parallel decoded arrays had mismatched lengths.
    MismatchedFieldCounts {
        /// Field name.
        field: &'static str,
        /// Expected item count.
        expected: usize,
        /// Actual item count.
        actual: usize,
    },
    /// A decoded field failed domain validation.
    InvalidDomainValue(String),
    /// A decoded commitment ciphertext failed normalization.
    InvalidCommitmentCiphertext(CommitmentCiphertextError),
    /// A decoded shield ciphertext failed normalization.
    InvalidShieldCiphertext(ShieldCiphertextError),
    /// A decoded shield preimage could not derive a canonical commitment.
    InvalidShieldCommitmentDerivation,
}

impl fmt::Display for EventError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingField(field) => write!(formatter, "missing required event field: {field}"),
            Self::InvalidLength { field, expected, actual } => write!(
                formatter,
                "invalid length for {field}: expected {expected} bytes, got {actual}"
            ),
            Self::MismatchedFieldCounts { field, expected, actual } => write!(
                formatter,
                "mismatched item count for {field}: expected {expected}, got {actual}"
            ),
            Self::InvalidDomainValue(message) => formatter.write_str(message),
            Self::InvalidCommitmentCiphertext(error) => error.fmt(formatter),
            Self::InvalidShieldCiphertext(error) => error.fmt(formatter),
            Self::InvalidShieldCommitmentDerivation => {
                formatter.write_str("failed to derive canonical shield commitment from preimage")
            }
        }
    }
}

impl std::error::Error for EventError {}

fn parse_domain_error(error: &ParseDomainError) -> EventError {
    EventError::InvalidDomainValue(error.to_string())
}

fn parse_derivation_error(_: KeyDerivationError) -> EventError {
    EventError::InvalidShieldCommitmentDerivation
}

fn required<T>(value: Option<T>, field: &'static str) -> Result<T, EventError> {
    value.ok_or(EventError::MissingField(field))
}

fn parse_fixed_bytes<const N: usize>(
    bytes: &[u8],
    field: &'static str,
) -> Result<[u8; N], EventError> {
    bytes.try_into().map_err(|_| EventError::InvalidLength {
        field,
        expected: N,
        actual: bytes.len(),
    })
}

fn parse_tx_hash(bytes: &[u8]) -> Result<TxHash, EventError> {
    Ok(TxHash::new(parse_fixed_bytes::<32>(bytes, "transaction_hash")?))
}

fn parse_scalar_note_commitment(
    bytes: &[u8],
    field: &'static str,
) -> Result<NoteCommitment, EventError> {
    let bytes = parse_fixed_bytes::<32>(bytes, field)?;
    NoteCommitment::new(BigUint::from_bytes_be(&bytes)).map_err(|error| parse_domain_error(&error))
}

fn parse_scalar_nullifier(bytes: &[u8], field: &'static str) -> Result<Nullifier, EventError> {
    let bytes = parse_fixed_bytes::<32>(bytes, field)?;
    Nullifier::new(BigUint::from_bytes_be(&bytes)).map_err(|error| parse_domain_error(&error))
}

fn parse_scalar_note_public_key(
    bytes: &[u8],
    field: &'static str,
) -> Result<NotePublicKey, EventError> {
    let bytes = parse_fixed_bytes::<32>(bytes, field)?;
    NotePublicKey::new(BigUint::from_bytes_be(&bytes)).map_err(|error| parse_domain_error(&error))
}

fn parse_scalar_railgun_txid(bytes: &[u8], field: &'static str) -> Result<RailgunTxid, EventError> {
    let bytes = parse_fixed_bytes::<32>(bytes, field)?;
    RailgunTxid::new(BigUint::from_bytes_be(&bytes)).map_err(|error| parse_domain_error(&error))
}

fn parse_bound_params_hash(bytes: &[u8]) -> Result<BoundParamsHash, EventError> {
    BoundParamsHash::from_slice(bytes).map_err(|error| parse_domain_error(&error))
}

fn parse_verification_hash(bytes: &[u8]) -> Result<VerificationHash, EventError> {
    VerificationHash::from_slice(bytes).map_err(|error| parse_domain_error(&error))
}

fn parse_address(bytes: &[u8], field: &'static str) -> Result<Address, EventError> {
    Address::from_slice(bytes).map_err(|_| EventError::InvalidLength {
        field,
        expected: Address::LENGTH,
        actual: bytes.len(),
    })
}

fn parse_token_data(input: DecodedTokenDataInput) -> Result<TokenData, EventError> {
    let token_address = parse_address(
        &required(input.token_address, "token_data.token_address")?,
        "token_data.token_address",
    )?;
    let token_type = TokenType::try_from(required(input.token_type, "token_data.token_type")?)
        .map_err(|error| parse_domain_error(&error))?;
    let token_sub_id =
        TokenSubId::from_slice(&required(input.token_sub_id, "token_data.token_sub_id")?)
            .map_err(|error| parse_domain_error(&error))?;

    TokenData::new(token_address, token_type, token_sub_id)
        .map_err(|error| parse_domain_error(&error))
}

fn parse_note_value(bytes: &[u8], field: &'static str) -> Result<NoteValue, EventError> {
    NoteValue::from_slice(bytes).map_err(|_| EventError::InvalidLength {
        field,
        expected: NoteValue::LENGTH,
        actual: bytes.len(),
    })
}

fn parse_shield_preimage(input: DecodedShieldPreimageInput) -> Result<ShieldPreimage, EventError> {
    Ok(ShieldPreimage::new(
        parse_scalar_note_public_key(
            &required(input.note_public_key, "shield_preimage.note_public_key")?,
            "shield_preimage.note_public_key",
        )?,
        parse_token_data(required(input.token_data, "shield_preimage.token_data")?)?,
        parse_note_value(
            &required(input.value, "shield_preimage.value")?,
            "shield_preimage.value",
        )?,
    ))
}

fn parse_v2_decoded_ciphertext(
    input: DecodedV2CommitmentCiphertextInput,
) -> Result<DecodedCommitmentCiphertextV2, EventError> {
    let ciphertext = required(input.ciphertext, "commitment_ciphertext.ciphertext")?;
    let ciphertext_words: [&[u8]; 4] =
        ciphertext.iter().map(Vec::as_slice).collect::<Vec<_>>().try_into().map_err(
            |words: Vec<&[u8]>| EventError::MismatchedFieldCounts {
                field: "commitment_ciphertext.ciphertext",
                expected: 4,
                actual: words.len(),
            },
        )?;
    let blinded_sender_viewing_key = required(
        input.blinded_sender_viewing_key,
        "commitment_ciphertext.blinded_sender_viewing_key",
    )?;
    let blinded_receiver_viewing_key = required(
        input.blinded_receiver_viewing_key,
        "commitment_ciphertext.blinded_receiver_viewing_key",
    )?;
    let annotation_data = required(input.annotation_data, "commitment_ciphertext.annotation_data")?;
    let memo = required(input.memo, "commitment_ciphertext.memo")?;

    parse_commitment_ciphertext_v2(
        &ciphertext_words,
        &blinded_sender_viewing_key,
        &blinded_receiver_viewing_key,
        &annotation_data,
        &memo,
    )
    .map_err(EventError::InvalidCommitmentCiphertext)?;

    let ciphertext: [[u8; 32]; 4] = core::array::from_fn(|index| {
        parse_fixed_bytes::<32>(ciphertext_words[index], "commitment_ciphertext.ciphertext.word")
            .unwrap_or_else(|_| unreachable!("validated by parse_commitment_ciphertext_v2"))
    });

    Ok(DecodedCommitmentCiphertextV2::new(
        ciphertext,
        parse_fixed_bytes::<32>(
            &blinded_sender_viewing_key,
            "commitment_ciphertext.blinded_sender_viewing_key",
        )?,
        parse_fixed_bytes::<32>(
            &blinded_receiver_viewing_key,
            "commitment_ciphertext.blinded_receiver_viewing_key",
        )?,
        annotation_data,
        memo,
    ))
}

fn parse_v3_decoded_ciphertext(
    input: DecodedV3CommitmentCiphertextInput,
) -> Result<DecodedCommitmentCiphertextV3, EventError> {
    let ciphertext = required(input.ciphertext, "commitment_ciphertext.ciphertext")?;
    let blinded_sender_viewing_key = required(
        input.blinded_sender_viewing_key,
        "commitment_ciphertext.blinded_sender_viewing_key",
    )?;
    let blinded_receiver_viewing_key = required(
        input.blinded_receiver_viewing_key,
        "commitment_ciphertext.blinded_receiver_viewing_key",
    )?;

    parse_commitment_ciphertext_v3(
        &ciphertext,
        &blinded_sender_viewing_key,
        &blinded_receiver_viewing_key,
    )
    .map_err(EventError::InvalidCommitmentCiphertext)?;

    Ok(DecodedCommitmentCiphertextV3::new(
        ciphertext,
        parse_fixed_bytes::<32>(
            &blinded_sender_viewing_key,
            "commitment_ciphertext.blinded_sender_viewing_key",
        )?,
        parse_fixed_bytes::<32>(
            &blinded_receiver_viewing_key,
            "commitment_ciphertext.blinded_receiver_viewing_key",
        )?,
    ))
}

fn parse_shield_ciphertext_input(
    input: DecodedShieldCiphertextInput,
) -> Result<railgun_types::ShieldCiphertext, EventError> {
    let encrypted_bundle = required(input.encrypted_bundle, "shield_ciphertext.encrypted_bundle")?;
    let shield_key = required(input.shield_key, "shield_ciphertext.shield_key")?;
    let encrypted_bundle_refs = encrypted_bundle.iter().map(Vec::as_slice).collect::<Vec<_>>();

    parse_shield_ciphertext(&encrypted_bundle_refs, &shield_key)
        .map_err(EventError::InvalidShieldCiphertext)
}

fn derive_shield_event_commitment(
    pre_image: &ShieldPreimage,
) -> Result<NoteCommitment, EventError> {
    let token_hash = derive_token_hash(pre_image.token_data());
    derive_note_commitment(pre_image.note_public_key(), &token_hash, pre_image.value())
        .map_err(parse_derivation_error)
}

/// Public parser input for decoded token data fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedTokenDataInput {
    /// Decoded token address bytes.
    pub token_address: Option<Vec<u8>>,
    /// Decoded token type discriminator.
    pub token_type: Option<u8>,
    /// Decoded token sub-ID bytes.
    pub token_sub_id: Option<Vec<u8>>,
}

/// Public parser input for decoded shield preimage fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedShieldPreimageInput {
    /// Decoded note public key bytes.
    pub note_public_key: Option<Vec<u8>>,
    /// Decoded token data.
    pub token_data: Option<DecodedTokenDataInput>,
    /// Decoded canonical 16-byte note value bytes.
    pub value: Option<Vec<u8>>,
}

/// Public parser input for decoded V2 commitment ciphertext fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedV2CommitmentCiphertextInput {
    /// Four decoded 32-byte ciphertext words.
    pub ciphertext: Option<Vec<Vec<u8>>>,
    /// Decoded blinded sender viewing key bytes.
    pub blinded_sender_viewing_key: Option<Vec<u8>>,
    /// Decoded blinded receiver viewing key bytes.
    pub blinded_receiver_viewing_key: Option<Vec<u8>>,
    /// Decoded annotation data bytes.
    pub annotation_data: Option<Vec<u8>>,
    /// Decoded memo bytes.
    pub memo: Option<Vec<u8>>,
}

/// Public parser input for decoded V3 commitment ciphertext fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedV3CommitmentCiphertextInput {
    /// Decoded concatenated `nonce | bundle` bytes.
    pub ciphertext: Option<Vec<u8>>,
    /// Decoded blinded sender viewing key bytes.
    pub blinded_sender_viewing_key: Option<Vec<u8>>,
    /// Decoded blinded receiver viewing key bytes.
    pub blinded_receiver_viewing_key: Option<Vec<u8>>,
}

/// Public parser input for decoded shield ciphertext fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedShieldCiphertextInput {
    /// Three decoded encrypted-bundle parts.
    pub encrypted_bundle: Option<Vec<Vec<u8>>>,
    /// Decoded shield key bytes.
    pub shield_key: Option<Vec<u8>>,
}

/// Public parser input for a decoded V2 transact event.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(missing_docs)]
pub struct V2TransactEventInput {
    pub transaction_hash: Option<Vec<u8>>,
    pub block_number: Option<u64>,
    pub tree_number: Option<u32>,
    pub start_position: Option<u32>,
    pub commitment_hashes: Option<Vec<Vec<u8>>>,
    pub commitment_ciphertexts: Option<Vec<DecodedV2CommitmentCiphertextInput>>,
    pub railgun_txid: Option<Vec<u8>>,
}

/// Public parser input for a decoded V2 shield event.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(missing_docs)]
pub struct V2ShieldEventInput {
    pub transaction_hash: Option<Vec<u8>>,
    pub block_number: Option<u64>,
    pub tree_number: Option<u32>,
    pub start_position: Option<u32>,
    pub preimages: Option<Vec<DecodedShieldPreimageInput>>,
    pub shield_ciphertexts: Option<Vec<DecodedShieldCiphertextInput>>,
    pub fees: Option<Vec<Vec<u8>>>,
}

/// Public parser input for a decoded V2 nullifier event.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(missing_docs)]
pub struct V2NullifierEventInput {
    pub transaction_hash: Option<Vec<u8>>,
    pub block_number: Option<u64>,
    pub tree_number: Option<u32>,
    pub nullifiers: Option<Vec<Vec<u8>>>,
}

/// Public parser input for a decoded V2 unshield event.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(missing_docs)]
pub struct V2UnshieldEventInput {
    pub transaction_hash: Option<Vec<u8>>,
    pub block_number: Option<u64>,
    pub event_log_index: Option<u64>,
    pub to_address: Option<Vec<u8>>,
    pub token_data: Option<DecodedTokenDataInput>,
    pub amount: Option<Vec<u8>>,
    pub fee: Option<Vec<u8>>,
}

/// Public parser input for a decoded V3 shield event.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(missing_docs)]
pub struct V3ShieldEventInput {
    pub transaction_hash: Option<Vec<u8>>,
    pub block_number: Option<u64>,
    pub tree_number: Option<u32>,
    pub start_position: Option<u32>,
    pub preimage: Option<DecodedShieldPreimageInput>,
    pub shield_ciphertext: Option<DecodedShieldCiphertextInput>,
    pub fee: Option<Vec<u8>>,
    pub from_address: Option<Vec<u8>>,
}

/// Public parser input for a decoded V3 transact event.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(missing_docs)]
pub struct V3TransactEventInput {
    pub transaction_hash: Option<Vec<u8>>,
    pub block_number: Option<u64>,
    pub tree_number: Option<u32>,
    pub start_position: Option<u32>,
    pub commitment_hashes: Option<Vec<Vec<u8>>>,
    pub commitment_ciphertexts: Option<Vec<DecodedV3CommitmentCiphertextInput>>,
    pub transact_commitment_batch_start_index: Option<u32>,
    pub sender_ciphertext: Option<Vec<u8>>,
    pub railgun_txid: Option<Vec<u8>>,
}

/// Public parser input for a decoded V3 nullifier event.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(missing_docs)]
pub struct V3NullifierEventInput {
    pub transaction_hash: Option<Vec<u8>>,
    pub block_number: Option<u64>,
    pub spend_tree_number: Option<u32>,
    pub nullifiers: Option<Vec<Vec<u8>>>,
}

/// Public parser input for a decoded V3 unshield event.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(missing_docs)]
pub struct V3UnshieldEventInput {
    pub transaction_hash: Option<Vec<u8>>,
    pub block_number: Option<u64>,
    pub transact_index: Option<u32>,
    pub railgun_txid: Option<Vec<u8>>,
    pub to_address: Option<Vec<u8>>,
    pub token_data: Option<DecodedTokenDataInput>,
    pub amount: Option<Vec<u8>>,
    pub fee: Option<Vec<u8>>,
}

/// Public parser input for V3 transaction-level unshield data.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(missing_docs)]
pub struct V3TransactionUnshieldDataInput {
    pub to_address: Option<Vec<u8>>,
    pub token_data: Option<DecodedTokenDataInput>,
    pub value: Option<Vec<u8>>,
}

/// Public parser input for a decoded V3 transaction-level event.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(missing_docs)]
pub struct V3TransactionEventInput {
    pub transaction_hash: Option<Vec<u8>>,
    pub block_number: Option<u64>,
    pub commitments: Option<Vec<Vec<u8>>>,
    pub nullifiers: Option<Vec<Vec<u8>>>,
    pub bound_params_hash: Option<Vec<u8>>,
    pub unshield: Option<V3TransactionUnshieldDataInput>,
    pub utxo_tree_in: Option<u32>,
    pub utxo_tree_out: Option<u32>,
    pub utxo_batch_start_position_out: Option<u32>,
    pub verification_hash: Option<Vec<u8>>,
}

/// Decodes one V2 transact event into the canonical typed model.
///
/// # Errors
///
/// Returns an error if any required field is missing, any field length is malformed,
/// any ciphertext entry fails normalization, or any domain value is invalid.
pub fn decode_v2_transact_event(
    input: V2TransactEventInput,
) -> Result<V2CommitmentEvent, EventError> {
    let txid = parse_tx_hash(&required(input.transaction_hash, "transaction_hash")?)?;
    let block_number = BlockNumber::new(required(input.block_number, "block_number")?);
    let tree_number = UtxoTreeCoordinate::from_raw(required(input.tree_number, "tree_number")?)
        .map_err(|error| parse_domain_error(&error))?;
    let start_position =
        CommitmentLeafPosition::new(required(input.start_position, "start_position")?);
    let commitment_hashes = required(input.commitment_hashes, "commitment_hashes")?;
    let commitment_ciphertexts = required(input.commitment_ciphertexts, "commitment_ciphertexts")?;

    if commitment_hashes.len() != commitment_ciphertexts.len() {
        return Err(EventError::MismatchedFieldCounts {
            field: "commitment_hashes/commitment_ciphertexts",
            expected: commitment_hashes.len(),
            actual: commitment_ciphertexts.len(),
        });
    }

    let railgun_txid = input
        .railgun_txid
        .as_deref()
        .map(|bytes| parse_scalar_railgun_txid(bytes, "railgun_txid"))
        .transpose()?;

    let commitments = commitment_hashes
        .into_iter()
        .zip(commitment_ciphertexts)
        .enumerate()
        .map(|(index, (hash, ciphertext))| {
            Ok(V2Commitment::Transact(V2TransactCommitment::new(
                parse_scalar_note_commitment(&hash, "commitment_hash")?,
                txid,
                block_number,
                parse_v2_decoded_ciphertext(ciphertext)?,
                tree_number,
                CommitmentLeafPosition::new(
                    start_position.get() + u32::try_from(index).unwrap_or(u32::MAX),
                ),
                railgun_txid.clone(),
            )))
        })
        .collect::<Result<Vec<_>, EventError>>()?;

    Ok(V2CommitmentEvent::new(txid, tree_number, start_position, commitments, block_number))
}

/// Decodes one V2 shield event into the canonical typed model.
///
/// # Errors
///
/// Returns an error if any required field is missing, decoded array lengths mismatch,
/// any shield ciphertext is malformed, or any derived domain value is invalid.
pub fn decode_v2_shield_event(input: V2ShieldEventInput) -> Result<V2CommitmentEvent, EventError> {
    let txid = parse_tx_hash(&required(input.transaction_hash, "transaction_hash")?)?;
    let block_number = BlockNumber::new(required(input.block_number, "block_number")?);
    let tree_number = UtxoTreeCoordinate::from_raw(required(input.tree_number, "tree_number")?)
        .map_err(|error| parse_domain_error(&error))?;
    let start_position =
        CommitmentLeafPosition::new(required(input.start_position, "start_position")?);
    let preimages = required(input.preimages, "preimages")?;
    let shield_ciphertexts = required(input.shield_ciphertexts, "shield_ciphertexts")?;

    if preimages.len() != shield_ciphertexts.len() {
        return Err(EventError::MismatchedFieldCounts {
            field: "preimages/shield_ciphertexts",
            expected: preimages.len(),
            actual: shield_ciphertexts.len(),
        });
    }
    if let Some(fees) = &input.fees
        && fees.len() != preimages.len()
    {
        return Err(EventError::MismatchedFieldCounts {
            field: "fees",
            expected: preimages.len(),
            actual: fees.len(),
        });
    }

    let commitments = preimages
        .into_iter()
        .zip(shield_ciphertexts)
        .enumerate()
        .map(|(index, (preimage, ciphertext))| {
            let pre_image = parse_shield_preimage(preimage)?;
            let fee = input
                .fees
                .as_ref()
                .and_then(|fees| fees.get(index))
                .map(|bytes| parse_note_value(bytes, "fee"))
                .transpose()?;
            Ok(V2Commitment::Shield(ShieldCommitment::new(
                derive_shield_event_commitment(&pre_image)?,
                txid,
                block_number,
                pre_image,
                parse_shield_ciphertext_input(ciphertext)?,
                fee,
                tree_number,
                CommitmentLeafPosition::new(
                    start_position.get() + u32::try_from(index).unwrap_or(u32::MAX),
                ),
                None,
            )))
        })
        .collect::<Result<Vec<_>, EventError>>()?;

    Ok(V2CommitmentEvent::new(txid, tree_number, start_position, commitments, block_number))
}

/// Decodes one V2 nullifier event into the canonical typed model.
///
/// # Errors
///
/// Returns an error if any required field is missing, any nullifier bytes are malformed,
/// or the tree coordinate is invalid.
pub fn decode_v2_nullifier_event(
    input: V2NullifierEventInput,
) -> Result<V2NullifierEvent, EventError> {
    Ok(V2NullifierEvent::new(
        parse_tx_hash(&required(input.transaction_hash, "transaction_hash")?)?,
        UtxoTreeCoordinate::from_raw(required(input.tree_number, "tree_number")?)
            .map_err(|error| parse_domain_error(&error))?,
        required(input.nullifiers, "nullifiers")?
            .into_iter()
            .map(|bytes| parse_scalar_nullifier(&bytes, "nullifier"))
            .collect::<Result<Vec<_>, _>>()?,
        BlockNumber::new(required(input.block_number, "block_number")?),
    ))
}

/// Decodes one V2 unshield event into the canonical typed model.
///
/// # Errors
///
/// Returns an error if any required field is missing or any typed token, address,
/// or value field is malformed.
pub fn decode_v2_unshield_event(
    input: V2UnshieldEventInput,
) -> Result<V2UnshieldEvent, EventError> {
    Ok(V2UnshieldEvent::new(
        parse_tx_hash(&required(input.transaction_hash, "transaction_hash")?)?,
        BlockNumber::new(required(input.block_number, "block_number")?),
        EventLogIndex::new(required(input.event_log_index, "event_log_index")?),
        UnshieldData::new(
            parse_address(&required(input.to_address, "to_address")?, "to_address")?,
            parse_token_data(required(input.token_data, "token_data")?)?,
            parse_note_value(&required(input.amount, "amount")?, "amount")?,
            parse_note_value(&required(input.fee, "fee")?, "fee")?,
        ),
    ))
}

/// Decodes one V3 shield event into the canonical typed model.
///
/// # Errors
///
/// Returns an error if any required field is missing, any shield ciphertext is malformed,
/// or any typed token, address, or value field is invalid.
pub fn decode_v3_shield_event(input: V3ShieldEventInput) -> Result<V3CommitmentEvent, EventError> {
    let txid = parse_tx_hash(&required(input.transaction_hash, "transaction_hash")?)?;
    let block_number = BlockNumber::new(required(input.block_number, "block_number")?);
    let tree_number = UtxoTreeCoordinate::from_raw(required(input.tree_number, "tree_number")?)
        .map_err(|error| parse_domain_error(&error))?;
    let start_position =
        CommitmentLeafPosition::new(required(input.start_position, "start_position")?);
    let pre_image = parse_shield_preimage(required(input.preimage, "preimage")?)?;
    let shield_ciphertext =
        parse_shield_ciphertext_input(required(input.shield_ciphertext, "shield_ciphertext")?)?;
    let fee = input.fee.as_deref().map(|bytes| parse_note_value(bytes, "fee")).transpose()?;
    let from_address = input
        .from_address
        .as_deref()
        .map(|bytes| parse_address(bytes, "from_address"))
        .transpose()?;

    Ok(V3CommitmentEvent::new(
        txid,
        tree_number,
        start_position,
        vec![V3Commitment::Shield(ShieldCommitment::new(
            derive_shield_event_commitment(&pre_image)?,
            txid,
            block_number,
            pre_image,
            shield_ciphertext,
            fee,
            tree_number,
            start_position,
            from_address,
        ))],
        block_number,
    ))
}

/// Decodes one V3 transact event into the canonical typed model.
///
/// # Errors
///
/// Returns an error if any required field is missing, decoded array lengths mismatch,
/// any ciphertext entry fails normalization, or any domain value is invalid.
pub fn decode_v3_transact_event(
    input: V3TransactEventInput,
) -> Result<V3CommitmentEvent, EventError> {
    let txid = parse_tx_hash(&required(input.transaction_hash, "transaction_hash")?)?;
    let block_number = BlockNumber::new(required(input.block_number, "block_number")?);
    let tree_number = UtxoTreeCoordinate::from_raw(required(input.tree_number, "tree_number")?)
        .map_err(|error| parse_domain_error(&error))?;
    let start_position =
        CommitmentLeafPosition::new(required(input.start_position, "start_position")?);
    let commitment_hashes = required(input.commitment_hashes, "commitment_hashes")?;
    let commitment_ciphertexts = required(input.commitment_ciphertexts, "commitment_ciphertexts")?;
    if commitment_hashes.len() != commitment_ciphertexts.len() {
        return Err(EventError::MismatchedFieldCounts {
            field: "commitment_hashes/commitment_ciphertexts",
            expected: commitment_hashes.len(),
            actual: commitment_ciphertexts.len(),
        });
    }

    let transact_commitment_batch_start_index = required(
        input.transact_commitment_batch_start_index,
        "transact_commitment_batch_start_index",
    )?;
    let sender_ciphertext =
        SenderCiphertext::new(required(input.sender_ciphertext, "sender_ciphertext")?);
    let railgun_txid =
        parse_scalar_railgun_txid(&required(input.railgun_txid, "railgun_txid")?, "railgun_txid")?;

    let commitments = commitment_hashes
        .into_iter()
        .zip(commitment_ciphertexts)
        .enumerate()
        .map(|(index, (hash, ciphertext))| {
            let index_u32 = u32::try_from(index).map_err(|_| {
                EventError::InvalidDomainValue("v3 commitment index overflowed u32".to_string())
            })?;
            Ok(V3Commitment::Transact(V3TransactCommitment::new(
                parse_scalar_note_commitment(&hash, "commitment_hash")?,
                txid,
                block_number,
                parse_v3_decoded_ciphertext(ciphertext)?,
                tree_number,
                CommitmentLeafPosition::new(start_position.get() + index_u32),
                TransactCommitmentBatchIndex::new(
                    transact_commitment_batch_start_index + index_u32,
                ),
                railgun_txid.clone(),
                sender_ciphertext.clone(),
            )))
        })
        .collect::<Result<Vec<_>, EventError>>()?;

    Ok(V3CommitmentEvent::new(txid, tree_number, start_position, commitments, block_number))
}

/// Decodes one V3 nullifier event into the canonical typed model.
///
/// # Errors
///
/// Returns an error if any required field is missing, any nullifier bytes are malformed,
/// or the spend tree coordinate is invalid.
pub fn decode_v3_nullifier_event(
    input: V3NullifierEventInput,
) -> Result<V3NullifierEvent, EventError> {
    Ok(V3NullifierEvent::new(
        parse_tx_hash(&required(input.transaction_hash, "transaction_hash")?)?,
        UtxoTreeCoordinate::from_raw(required(input.spend_tree_number, "spend_tree_number")?)
            .map_err(|error| parse_domain_error(&error))?,
        required(input.nullifiers, "nullifiers")?
            .into_iter()
            .map(|bytes| parse_scalar_nullifier(&bytes, "nullifier"))
            .collect::<Result<Vec<_>, _>>()?,
        BlockNumber::new(required(input.block_number, "block_number")?),
    ))
}

/// Decodes one V3 unshield event into the canonical typed model.
///
/// # Errors
///
/// Returns an error if any required field is missing or any typed token, address,
/// amount, fee, or linked txid field is malformed.
pub fn decode_v3_unshield_event(
    input: V3UnshieldEventInput,
) -> Result<V3UnshieldEvent, EventError> {
    Ok(V3UnshieldEvent::new(
        parse_tx_hash(&required(input.transaction_hash, "transaction_hash")?)?,
        BlockNumber::new(required(input.block_number, "block_number")?),
        AccumulatorTransactionIndex::new(required(input.transact_index, "transact_index")?),
        parse_scalar_railgun_txid(&required(input.railgun_txid, "railgun_txid")?, "railgun_txid")?,
        UnshieldData::new(
            parse_address(&required(input.to_address, "to_address")?, "to_address")?,
            parse_token_data(required(input.token_data, "token_data")?)?,
            parse_note_value(&required(input.amount, "amount")?, "amount")?,
            parse_note_value(&required(input.fee, "fee")?, "fee")?,
        ),
    ))
}

/// Decodes one V3 transaction-level event into the canonical typed model.
///
/// # Errors
///
/// Returns an error if any required field is missing, any hash bytes are malformed,
/// or any typed tree, token, address, value, or verification-hash field is invalid.
pub fn decode_v3_transaction_event(
    input: V3TransactionEventInput,
) -> Result<V3TransactionEvent, EventError> {
    let unshield = input
        .unshield
        .map(|unshield| {
            Ok(V3TransactionUnshieldData::new(
                parse_address(
                    &required(unshield.to_address, "unshield.to_address")?,
                    "unshield.to_address",
                )?,
                parse_token_data(required(unshield.token_data, "unshield.token_data")?)?,
                parse_note_value(&required(unshield.value, "unshield.value")?, "unshield.value")?,
            ))
        })
        .transpose()?;

    let verification_hash =
        input.verification_hash.as_deref().map(parse_verification_hash).transpose()?;

    Ok(V3TransactionEvent::new(
        parse_tx_hash(&required(input.transaction_hash, "transaction_hash")?)?,
        BlockNumber::new(required(input.block_number, "block_number")?),
        required(input.commitments, "commitments")?
            .into_iter()
            .map(|bytes| parse_scalar_note_commitment(&bytes, "commitment"))
            .collect::<Result<Vec<_>, _>>()?,
        required(input.nullifiers, "nullifiers")?
            .into_iter()
            .map(|bytes| parse_scalar_nullifier(&bytes, "nullifier"))
            .collect::<Result<Vec<_>, _>>()?,
        parse_bound_params_hash(&required(input.bound_params_hash, "bound_params_hash")?)?,
        unshield,
        UtxoTreeCoordinate::from_raw(required(input.utxo_tree_in, "utxo_tree_in")?)
            .map_err(|error| parse_domain_error(&error))?,
        UtxoTreeCoordinate::from_raw(required(input.utxo_tree_out, "utxo_tree_out")?)
            .map_err(|error| parse_domain_error(&error))?,
        UtxoLeafCoordinate::from_raw(required(
            input.utxo_batch_start_position_out,
            "utxo_batch_start_position_out",
        )?)
        .map_err(|error| parse_domain_error(&error))?,
        verification_hash,
    ))
}

/// Convenience wrapper for version-aware commitment event decoding.
///
/// # Errors
///
/// Returns any error produced while decoding the selected commitment event variant.
pub fn decode_commitment_event(
    input: DecodedCommitmentEventInput,
) -> Result<VersionedCommitmentEvent, EventError> {
    match input {
        DecodedCommitmentEventInput::V2Transact(input) => {
            decode_v2_transact_event(input).map(VersionedCommitmentEvent::V2)
        }
        DecodedCommitmentEventInput::V2Shield(input) => {
            decode_v2_shield_event(input).map(VersionedCommitmentEvent::V2)
        }
        DecodedCommitmentEventInput::V3Shield(input) => {
            decode_v3_shield_event(input).map(VersionedCommitmentEvent::V3)
        }
        DecodedCommitmentEventInput::V3Transact(input) => {
            decode_v3_transact_event(input).map(VersionedCommitmentEvent::V3)
        }
    }
}

/// Convenience wrapper for version-aware nullifier event decoding.
///
/// # Errors
///
/// Returns any error produced while decoding the selected nullifier event variant.
pub fn decode_nullifier_event(
    input: DecodedNullifierEventInput,
) -> Result<VersionedNullifierEvent, EventError> {
    match input {
        DecodedNullifierEventInput::V2(input) => {
            decode_v2_nullifier_event(input).map(VersionedNullifierEvent::V2)
        }
        DecodedNullifierEventInput::V3(input) => {
            decode_v3_nullifier_event(input).map(VersionedNullifierEvent::V3)
        }
    }
}

/// Convenience wrapper for version-aware unshield event decoding.
///
/// # Errors
///
/// Returns any error produced while decoding the selected unshield event variant.
pub fn decode_unshield_event(
    input: DecodedUnshieldEventInput,
) -> Result<VersionedUnshieldEvent, EventError> {
    match input {
        DecodedUnshieldEventInput::V2(input) => {
            decode_v2_unshield_event(input).map(VersionedUnshieldEvent::V2)
        }
        DecodedUnshieldEventInput::V3(input) => {
            decode_v3_unshield_event(input).map(VersionedUnshieldEvent::V3)
        }
    }
}

/// Version-aware decoded commitment event parser input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecodedCommitmentEventInput {
    /// V2 transact event.
    V2Transact(V2TransactEventInput),
    /// V2 shield event.
    V2Shield(V2ShieldEventInput),
    /// V3 shield event.
    V3Shield(V3ShieldEventInput),
    /// V3 transact event.
    V3Transact(V3TransactEventInput),
}

/// Version-aware decoded nullifier event parser input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecodedNullifierEventInput {
    /// V2 nullifier event.
    V2(V2NullifierEventInput),
    /// V3 nullifier event.
    V3(V3NullifierEventInput),
}

/// Version-aware decoded unshield event parser input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecodedUnshieldEventInput {
    /// V2 unshield event.
    V2(V2UnshieldEventInput),
    /// V3 unshield event.
    V3(V3UnshieldEventInput),
}

/// Explicit contract-version context for raw Railgun log decoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RawRailgunLogVersion {
    /// Decode as a V2 `RailgunSmartWallet` log.
    V2,
    /// Decode as a V3 `PoseidonMerkleAccumulator` log.
    V3,
}

/// Minimal provider-agnostic raw log input for canonical Railgun event decoding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawRailgunLog {
    /// Emitting contract address.
    pub contract_address: Address,
    /// Raw EVM topics in emitted order.
    pub topics: Vec<[u8; 32]>,
    /// Raw ABI-encoded data payload.
    pub data: Vec<u8>,
    /// Containing transaction hash when available.
    pub transaction_hash: Option<TxHash>,
    /// Containing block number when available.
    pub block_number: Option<u64>,
    /// EVM log index when available.
    pub log_index: Option<u64>,
}

/// Version-aware canonical event output derived from a raw Railgun log.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecodedRailgunLogEvent {
    /// Commitment-oriented event.
    Commitment(VersionedCommitmentEvent),
    /// Nullifier-oriented event.
    Nullifier(VersionedNullifierEvent),
    /// Unshield-oriented event.
    Unshield(VersionedUnshieldEvent),
}

/// Error returned when raw Railgun log decoding fails.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RawRailgunLogError {
    /// The log did not contain the expected topic count.
    InvalidTopicCount {
        /// Expected number of topics.
        expected: usize,
        /// Actual number of topics.
        actual: usize,
    },
    /// The event topic is not supported for the selected version.
    UnsupportedTopic([u8; 32]),
    /// The selected contract version does not support this topic.
    UnsupportedVersionTopic {
        /// Selected version.
        version: RawRailgunLogVersion,
        /// Event topic hash.
        topic: [u8; 32],
    },
    /// One raw numeric field could not fit the canonical target type.
    ValueOutOfRange(&'static str),
    /// A required receipt or log context field was missing.
    MissingContext(&'static str),
    /// ABI event decoding failed.
    AbiDecodeFailed(&'static str),
    /// The accumulator payload was internally inconsistent.
    MalformedAccumulatorUpdate(&'static str),
    /// One fee/value relationship was invalid.
    InvalidFeeSplit(&'static str),
    /// Canonical event normalization failed after ABI decoding.
    Event(EventError),
}

impl fmt::Display for RawRailgunLogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTopicCount { expected, actual } => {
                write!(formatter, "invalid topic count: expected {expected}, got {actual}")
            }
            Self::UnsupportedTopic(topic) => {
                write!(formatter, "unsupported Railgun event topic: {topic:02x?}")
            }
            Self::UnsupportedVersionTopic { version, topic } => {
                write!(formatter, "topic {topic:02x?} is unsupported for {version:?}")
            }
            Self::ValueOutOfRange(field) => {
                write!(formatter, "raw log value out of range for {field}")
            }
            Self::MissingContext(field) => {
                write!(formatter, "missing required raw log context: {field}")
            }
            Self::AbiDecodeFailed(event_name) => {
                write!(formatter, "failed to ABI decode {event_name} log payload")
            }
            Self::MalformedAccumulatorUpdate(message) | Self::InvalidFeeSplit(message) => {
                formatter.write_str(message)
            }
            Self::Event(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for RawRailgunLogError {}

impl From<EventError> for RawRailgunLogError {
    fn from(error: EventError) -> Self {
        Self::Event(error)
    }
}

fn raw_log_data(log: &RawRailgunLog) -> LogData {
    LogData::new_unchecked(
        log.topics.iter().copied().map(FixedBytes::<32>::from).collect(),
        Bytes::from(log.data.clone()),
    )
}

fn raw_transaction_hash(log: &RawRailgunLog) -> Result<Vec<u8>, RawRailgunLogError> {
    log.transaction_hash
        .as_ref()
        .map(|hash| hash.as_bytes().to_vec())
        .ok_or(RawRailgunLogError::MissingContext("transaction_hash"))
}

fn raw_block_number(log: &RawRailgunLog) -> Result<u64, RawRailgunLogError> {
    log.block_number.ok_or(RawRailgunLogError::MissingContext("block_number"))
}

fn event_token_data_input(token_data: &EventTokenDataAbi) -> DecodedTokenDataInput {
    DecodedTokenDataInput {
        token_address: Some(token_data.tokenAddress.as_slice().to_vec()),
        token_type: Some(token_data.tokenType),
        token_sub_id: Some(token_data.tokenSubID.to_be_bytes::<32>().to_vec()),
    }
}

fn event_preimage_input(preimage: &EventCommitmentPreimageAbi) -> DecodedShieldPreimageInput {
    let value = u128::try_from(preimage.value)
        .unwrap_or_else(|_| unreachable!("uint120 always fits into u128"));
    DecodedShieldPreimageInput {
        note_public_key: Some(preimage.npk.as_slice().to_vec()),
        token_data: Some(event_token_data_input(&preimage.token)),
        value: Some(value.to_be_bytes().to_vec()),
    }
}

fn event_shield_ciphertext_input(
    ciphertext: &EventShieldCiphertextAbi,
) -> DecodedShieldCiphertextInput {
    DecodedShieldCiphertextInput {
        encrypted_bundle: Some(
            ciphertext
                .encryptedBundle
                .iter()
                .map(|word| word.as_slice().to_vec())
                .collect(),
        ),
        shield_key: Some(ciphertext.shieldKey.as_slice().to_vec()),
    }
}

fn note_value_bytes_from_u256(
    value: U256,
    field: &'static str,
) -> Result<Vec<u8>, RawRailgunLogError> {
    let bytes = value.to_be_bytes::<32>();
    if bytes[..16].iter().any(|byte| *byte != 0) {
        return Err(RawRailgunLogError::ValueOutOfRange(field));
    }
    Ok(bytes[16..].to_vec())
}

fn u32_from_uint<T>(value: T, field: &'static str) -> Result<u32, RawRailgunLogError>
where
    T: TryInto<u32>,
{
    value.try_into().map_err(|_| RawRailgunLogError::ValueOutOfRange(field))
}

fn token_hash_from_preimage(
    preimage: &EventCommitmentPreimageAbi,
) -> Result<TokenHash, RawRailgunLogError> {
    let token_data = parse_token_data(event_token_data_input(&preimage.token))?;
    Ok(derive_token_hash(&token_data))
}

fn railgun_txid_bytes(railgun_txid: &RailgunTxid) -> Vec<u8> {
    let bytes = railgun_txid.value().to_bytes_be();
    let mut padded = [0_u8; 32];
    let start = 32 - bytes.len();
    padded[start..].copy_from_slice(&bytes);
    padded.to_vec()
}

fn split_treasury_fees(
    transactions: &[EventV3TransactionConfigurationAbi],
    shields: &[EventV3ShieldConfigurationAbi],
    treasury_fees: &[EventV3TreasuryFeeAbi],
) -> Result<std::collections::BTreeMap<[u8; 32], (U256, U256)>, RawRailgunLogError> {
    let mut split = std::collections::BTreeMap::new();

    for treasury_fee in treasury_fees {
        let token_id: [u8; 32] = treasury_fee.tokenID.as_slice().try_into().map_err(|_| {
            RawRailgunLogError::MalformedAccumulatorUpdate("treasury token id must be 32 bytes")
        })?;
        let unshield_value = transactions
            .iter()
            .find(|transaction| {
                token_hash_from_preimage(&transaction.unshieldPreimage)
                    .is_ok_and(|hash| hash.as_bytes() == treasury_fee.tokenID.as_slice())
            })
            .map_or(U256::ZERO, |transaction| U256::from(transaction.unshieldPreimage.value));
        let shield_value = shields
            .iter()
            .find(|shield| {
                token_hash_from_preimage(&shield.preimage)
                    .is_ok_and(|hash| hash.as_bytes() == treasury_fee.tokenID.as_slice())
            })
            .map_or(U256::ZERO, |shield| U256::from(shield.preimage.value));

        let (shield_fee, unshield_fee) = if unshield_value < shield_value {
            let unshield_fee = if unshield_value.is_zero() {
                U256::ZERO
            } else {
                treasury_fee.fee * unshield_value / (unshield_value + shield_value)
            };
            (treasury_fee.fee - unshield_fee, unshield_fee)
        } else {
            let shield_fee = if shield_value.is_zero() {
                U256::ZERO
            } else {
                treasury_fee.fee * shield_value / (unshield_value + shield_value)
            };
            (shield_fee, treasury_fee.fee - shield_fee)
        };

        split.insert(token_id, (shield_fee, unshield_fee));
    }

    Ok(split)
}

fn derive_v3_log_railgun_txid(
    transaction: &EventV3TransactionConfigurationAbi,
    commitment_hashes: &[FixedBytes<32>],
) -> Result<RailgunTxid, RawRailgunLogError> {
    let mut commitments = commitment_hashes
        .iter()
        .map(|hash| parse_scalar_note_commitment(hash.as_slice(), "commitment_hash"))
        .collect::<Result<Vec<_>, _>>()?;
    let nullifiers = transaction
        .nullifiers
        .iter()
        .map(|nullifier| parse_scalar_nullifier(nullifier.as_slice(), "nullifier"))
        .collect::<Result<Vec<_>, _>>()?;
    let bound_params_hash = parse_bound_params_hash(transaction.boundParamsHash.as_slice())?;

    if transaction.unshieldPreimage.value > 0 {
        let preimage =
            parse_shield_preimage(event_preimage_input(&transaction.unshieldPreimage))?;
        commitments.push(derive_shield_event_commitment(&preimage)?);
    }

    derive_railgun_txid(&nullifiers, &commitments, &bound_params_hash).map_err(|error| {
        RawRailgunLogError::MalformedAccumulatorUpdate(match error {
            crate::RailgunTxidError::TooManyNullifiers => "too many V3 nullifiers for railgun txid",
            crate::RailgunTxidError::TooManyCommitments => {
                "too many V3 commitments for railgun txid"
            }
            crate::RailgunTxidError::InvalidBoundParamsHash => "invalid V3 bound params hash",
            crate::RailgunTxidError::HashingFailure => "failed to derive V3 railgun txid",
        })
    })
}

fn decode_v2_transact_raw_log(
    log: &RawRailgunLog,
) -> Result<Vec<DecodedRailgunLogEvent>, RawRailgunLogError> {
    let decoded = V2TransactLog::decode_log_data(&raw_log_data(log))
        .map_err(|_| RawRailgunLogError::AbiDecodeFailed("V2 Transact"))?;

    Ok(vec![DecodedRailgunLogEvent::Commitment(decode_commitment_event(
        DecodedCommitmentEventInput::V2Transact(V2TransactEventInput {
            transaction_hash: Some(raw_transaction_hash(log)?),
            block_number: Some(raw_block_number(log)?),
            tree_number: Some(u32_from_uint(decoded.treeNumber, "tree_number")?),
            start_position: Some(u32_from_uint(decoded.startPosition, "start_position")?),
            commitment_hashes: Some(
                decoded.hash.into_iter().map(|hash| hash.as_slice().to_vec()).collect(),
            ),
            commitment_ciphertexts: Some(
                decoded
                    .ciphertext
                    .into_iter()
                    .map(|ciphertext| DecodedV2CommitmentCiphertextInput {
                        ciphertext: Some(
                            ciphertext
                                .ciphertext
                                .into_iter()
                                .map(|word| word.as_slice().to_vec())
                                .collect(),
                        ),
                        blinded_sender_viewing_key: Some(
                            ciphertext.blindedSenderViewingKey.as_slice().to_vec(),
                        ),
                        blinded_receiver_viewing_key: Some(
                            ciphertext.blindedReceiverViewingKey.as_slice().to_vec(),
                        ),
                        annotation_data: Some(ciphertext.annotationData.to_vec()),
                        memo: Some(ciphertext.memo.to_vec()),
                    })
                    .collect(),
            ),
            railgun_txid: None,
        }),
    )?)])
}

fn decode_v2_shield_raw_log(
    log: &RawRailgunLog,
) -> Result<Vec<DecodedRailgunLogEvent>, RawRailgunLogError> {
    let decoded = V2ShieldLog::decode_log_data(&raw_log_data(log))
        .map_err(|_| RawRailgunLogError::AbiDecodeFailed("V2 Shield"))?;

    Ok(vec![DecodedRailgunLogEvent::Commitment(decode_commitment_event(
        DecodedCommitmentEventInput::V2Shield(V2ShieldEventInput {
            transaction_hash: Some(raw_transaction_hash(log)?),
            block_number: Some(raw_block_number(log)?),
            tree_number: Some(u32_from_uint(decoded.treeNumber, "tree_number")?),
            start_position: Some(u32_from_uint(decoded.startPosition, "start_position")?),
            preimages: Some(
                decoded
                    .commitments
                    .into_iter()
                    .map(|preimage| event_preimage_input(&preimage))
                    .collect(),
            ),
            shield_ciphertexts: Some(
                decoded
                    .shieldCiphertext
                    .into_iter()
                    .map(|ciphertext| event_shield_ciphertext_input(&ciphertext))
                    .collect(),
            ),
            fees: Some(
                decoded
                    .fees
                    .into_iter()
                    .map(|fee| note_value_bytes_from_u256(fee, "fee"))
                    .collect::<Result<Vec<_>, _>>()?,
            ),
        }),
    )?)])
}

fn decode_v2_nullified_raw_log(
    log: &RawRailgunLog,
) -> Result<Vec<DecodedRailgunLogEvent>, RawRailgunLogError> {
    let decoded = V2NullifiedLog::decode_log_data(&raw_log_data(log))
        .map_err(|_| RawRailgunLogError::AbiDecodeFailed("V2 Nullified"))?;

    Ok(vec![DecodedRailgunLogEvent::Nullifier(decode_nullifier_event(
        DecodedNullifierEventInput::V2(V2NullifierEventInput {
            transaction_hash: Some(raw_transaction_hash(log)?),
            block_number: Some(raw_block_number(log)?),
            tree_number: Some(u32::from(decoded.treeNumber)),
            nullifiers: Some(
                decoded
                    .nullifier
                    .into_iter()
                    .map(|nullifier| nullifier.as_slice().to_vec())
                    .collect(),
            ),
        }),
    )?)])
}

fn decode_v2_unshield_raw_log(
    log: &RawRailgunLog,
) -> Result<Vec<DecodedRailgunLogEvent>, RawRailgunLogError> {
    let decoded = V2UnshieldLog::decode_log_data(&raw_log_data(log))
        .map_err(|_| RawRailgunLogError::AbiDecodeFailed("V2 Unshield"))?;

    Ok(vec![DecodedRailgunLogEvent::Unshield(decode_unshield_event(
        DecodedUnshieldEventInput::V2(V2UnshieldEventInput {
            transaction_hash: Some(raw_transaction_hash(log)?),
            block_number: Some(raw_block_number(log)?),
            event_log_index: Some(
                log.log_index.ok_or(RawRailgunLogError::MissingContext("log_index"))?,
            ),
            to_address: Some(decoded.to.as_slice().to_vec()),
            token_data: Some(event_token_data_input(&decoded.token)),
            amount: Some(note_value_bytes_from_u256(decoded.amount, "amount")?),
            fee: Some(note_value_bytes_from_u256(decoded.fee, "fee")?),
        }),
    )?)])
}

#[allow(clippy::too_many_lines)]
fn decode_v3_accumulator_raw_log(
    log: &RawRailgunLog,
) -> Result<Vec<DecodedRailgunLogEvent>, RawRailgunLogError> {
    let decoded = V3AccumulatorStateUpdateLog::decode_log_data(&raw_log_data(log))
        .map_err(|_| RawRailgunLogError::AbiDecodeFailed("V3 AccumulatorStateUpdate"))?;

    let transaction_hash = raw_transaction_hash(log)?;
    let block_number = raw_block_number(log)?;
    let EventV3StateUpdateAbi {
        commitments,
        transactions,
        shields,
        commitmentCiphertext,
        treasuryFees,
        senderCiphertext,
    } = decoded.update;
    let split_treasury_fees = split_treasury_fees(&transactions, &shields, &treasuryFees)?;

    let total_unshield_values = transactions.iter().fold(U256::ZERO, |accumulator, transaction| {
        accumulator + U256::from(transaction.unshieldPreimage.value)
    });
    let total_shield_values = shields
        .iter()
        .fold(U256::ZERO, |accumulator, shield| accumulator + U256::from(shield.preimage.value));

    let mut events = Vec::new();
    let mut commitment_start_index = 0_usize;
    let mut utxo_tree = decoded.accumulatorNumber;
    let mut utxo_start_position = u32_from_uint(decoded.startPosition, "start_position")?;

    for (transaction_index, transaction) in transactions.into_iter().enumerate() {
        let commitments_count = usize::from(transaction.commitmentsCount);
        let commitment_end_index = commitment_start_index + commitments_count;
        let commitment_hashes = commitments
            .get(commitment_start_index..commitment_end_index)
            .ok_or(RawRailgunLogError::MalformedAccumulatorUpdate(
                "v3 commitment count exceeded commitment hash array",
            ))?;
        let commitment_ciphertexts = commitmentCiphertext
            .get(commitment_start_index..commitment_end_index)
            .ok_or(RawRailgunLogError::MalformedAccumulatorUpdate(
                "v3 commitment count exceeded commitment ciphertext array",
            ))?;
        let railgun_txid = derive_v3_log_railgun_txid(&transaction, commitment_hashes)?;

        events.push(DecodedRailgunLogEvent::Commitment(decode_commitment_event(
            DecodedCommitmentEventInput::V3Transact(V3TransactEventInput {
                transaction_hash: Some(transaction_hash.clone()),
                block_number: Some(block_number),
                tree_number: Some(utxo_tree),
                start_position: Some(utxo_start_position),
                commitment_hashes: Some(
                    commitment_hashes.iter().map(|hash| hash.as_slice().to_vec()).collect(),
                ),
                commitment_ciphertexts: Some(
                    commitment_ciphertexts
                        .iter()
                        .map(|ciphertext| DecodedV3CommitmentCiphertextInput {
                            ciphertext: Some(ciphertext.ciphertext.to_vec()),
                            blinded_sender_viewing_key: Some(
                                ciphertext.blindedSenderViewingKey.as_slice().to_vec(),
                            ),
                            blinded_receiver_viewing_key: Some(
                                ciphertext.blindedReceiverViewingKey.as_slice().to_vec(),
                            ),
                        })
                        .collect(),
                ),
                transact_commitment_batch_start_index: Some(
                    u32::try_from(commitment_start_index).map_err(|_| {
                        RawRailgunLogError::ValueOutOfRange("transact_commitment_batch_start_index")
                    })?,
                ),
                sender_ciphertext: Some(senderCiphertext.to_vec()),
                railgun_txid: Some(railgun_txid_bytes(&railgun_txid)),
            }),
        )?));

        events.push(DecodedRailgunLogEvent::Nullifier(decode_nullifier_event(
            DecodedNullifierEventInput::V3(V3NullifierEventInput {
                transaction_hash: Some(transaction_hash.clone()),
                block_number: Some(block_number),
                spend_tree_number: Some(transaction.spendAccumulatorNumber),
                nullifiers: Some(
                    transaction
                        .nullifiers
                        .into_iter()
                        .map(|nullifier| nullifier.as_slice().to_vec())
                        .collect(),
                ),
            }),
        )?));

        let token_hash = token_hash_from_preimage(&transaction.unshieldPreimage)?;
        let value = U256::from(transaction.unshieldPreimage.value);
        if !value.is_zero() {
            let unshield_fee_total = split_treasury_fees
                .get(token_hash.as_bytes())
                .map_or(U256::ZERO, |(_, unshield_fee)| *unshield_fee);
            let unshield_fee = if total_unshield_values.is_zero() {
                U256::ZERO
            } else {
                unshield_fee_total * value / total_unshield_values
            };
            if unshield_fee > value {
                return Err(RawRailgunLogError::InvalidFeeSplit(
                    "v3 unshield fee exceeded unshield preimage value",
                ));
            }
            events.push(DecodedRailgunLogEvent::Unshield(decode_unshield_event(
                DecodedUnshieldEventInput::V3(V3UnshieldEventInput {
                    transaction_hash: Some(transaction_hash.clone()),
                    block_number: Some(block_number),
                    transact_index: Some(
                        u32::try_from(transaction_index)
                            .map_err(|_| RawRailgunLogError::ValueOutOfRange("transact_index"))?,
                    ),
                    railgun_txid: Some(railgun_txid_bytes(&railgun_txid)),
                    to_address: Some(transaction.unshieldPreimage.npk.as_slice()[12..].to_vec()),
                    token_data: Some(event_token_data_input(&transaction.unshieldPreimage.token)),
                    amount: Some(note_value_bytes_from_u256(value - unshield_fee, "amount")?),
                    fee: Some(note_value_bytes_from_u256(unshield_fee, "fee")?),
                }),
            )?));
        }

        commitment_start_index = commitment_end_index;
        utxo_start_position = utxo_start_position
            .checked_add(u32::from(transaction.commitmentsCount))
            .ok_or(RawRailgunLogError::ValueOutOfRange("utxo_start_position"))?;
        if utxo_start_position >= TREE_MAX_ITEMS {
            utxo_start_position = 0;
            utxo_tree =
                utxo_tree.checked_add(1).ok_or(RawRailgunLogError::ValueOutOfRange("utxo_tree"))?;
        }
    }

    for shield in shields {
        let token_hash = token_hash_from_preimage(&shield.preimage)?;
        let shield_fee_total = split_treasury_fees
            .get(token_hash.as_bytes())
            .map_or(U256::ZERO, |(shield_fee, _)| *shield_fee);
        let shield_value = U256::from(shield.preimage.value);
        let shield_fee = if total_shield_values.is_zero() {
            U256::ZERO
        } else {
            shield_fee_total * shield_value / total_shield_values
        };

        events.push(DecodedRailgunLogEvent::Commitment(decode_commitment_event(
            DecodedCommitmentEventInput::V3Shield(V3ShieldEventInput {
                transaction_hash: Some(transaction_hash.clone()),
                block_number: Some(block_number),
                tree_number: Some(utxo_tree),
                start_position: Some(utxo_start_position),
                preimage: Some(event_preimage_input(&shield.preimage)),
                shield_ciphertext: Some(event_shield_ciphertext_input(&shield.ciphertext)),
                fee: Some(note_value_bytes_from_u256(shield_fee, "fee")?),
                from_address: Some(shield.from.as_slice().to_vec()),
            }),
        )?));

        utxo_start_position = utxo_start_position
            .checked_add(1)
            .ok_or(RawRailgunLogError::ValueOutOfRange("utxo_start_position"))?;
        if utxo_start_position >= TREE_MAX_ITEMS {
            utxo_start_position = 0;
            utxo_tree =
                utxo_tree.checked_add(1).ok_or(RawRailgunLogError::ValueOutOfRange("utxo_tree"))?;
        }
    }

    Ok(events)
}

/// Decodes one raw Railgun contract log into canonical event models.
///
/// V2 logs produce exactly one canonical event. V3 accumulator-update logs may expand into
/// multiple canonical commitment, nullifier, and unshield events in deterministic order.
///
/// # Errors
///
/// Returns an error when the topic is unsupported, the ABI payload is malformed, required
/// receipt context is missing, or canonical event normalization fails.
pub fn decode_raw_railgun_log(
    version: RawRailgunLogVersion,
    log: &RawRailgunLog,
) -> Result<Vec<DecodedRailgunLogEvent>, RawRailgunLogError> {
    if log.topics.len() != 1 {
        return Err(RawRailgunLogError::InvalidTopicCount {
            expected: 1,
            actual: log.topics.len(),
        });
    }

    let topic = log.topics[0];

    match version {
        RawRailgunLogVersion::V2 => {
            if topic == *V2TransactLog::SIGNATURE_HASH.as_slice() {
                decode_v2_transact_raw_log(log)
            } else if topic == *V2ShieldLog::SIGNATURE_HASH.as_slice() {
                decode_v2_shield_raw_log(log)
            } else if topic == *V2NullifiedLog::SIGNATURE_HASH.as_slice() {
                decode_v2_nullified_raw_log(log)
            } else if topic == *V2UnshieldLog::SIGNATURE_HASH.as_slice() {
                decode_v2_unshield_raw_log(log)
            } else {
                Err(RawRailgunLogError::UnsupportedVersionTopic { version, topic })
            }
        }
        RawRailgunLogVersion::V3 => {
            if topic == *V3AccumulatorStateUpdateLog::SIGNATURE_HASH.as_slice() {
                decode_v3_accumulator_raw_log(log)
            } else {
                Err(RawRailgunLogError::UnsupportedVersionTopic { version, topic })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{
        Address as AlloyAddress, Bytes, FixedBytes, U256,
        aliases::{U120, U224},
    };
    use alloy_sol_types::SolEvent;
    use railgun_types::{
        Address, CommitmentLeafPosition, GLOBAL_UTXO_POSITION_UNSHIELD_EVENT_HARDCODED_VALUE,
        GLOBAL_UTXO_TREE_UNSHIELD_EVENT_HARDCODED_VALUE, TxHash, UtxoLeafCoordinate,
        UtxoTreeCoordinate,
    };

    use super::{
        DecodedCommitmentEventInput, DecodedRailgunLogEvent, DecodedShieldCiphertextInput,
        DecodedShieldPreimageInput, DecodedTokenDataInput, DecodedV2CommitmentCiphertextInput,
        DecodedV3CommitmentCiphertextInput, EventCommitmentPreimageAbi, EventError,
        EventShieldCiphertextAbi, EventTokenDataAbi, EventV2CommitmentCiphertextAbi,
        EventV3CommitmentCiphertextAbi, EventV3ShieldConfigurationAbi, EventV3StateUpdateAbi,
        EventV3TransactionConfigurationAbi, RawRailgunLog, RawRailgunLogError,
        RawRailgunLogVersion, V2NullifierEventInput, V2ShieldEventInput, V2TransactEventInput,
        V2TransactLog, V2UnshieldEventInput, V2UnshieldLog, V3AccumulatorStateUpdateLog,
        V3NullifierEventInput, V3TransactEventInput, V3TransactionEventInput,
        V3TransactionUnshieldDataInput, V3UnshieldEventInput, decode_commitment_event,
        decode_raw_railgun_log, decode_v2_nullifier_event, decode_v2_unshield_event,
        decode_v3_nullifier_event, decode_v3_transaction_event, decode_v3_unshield_event,
    };

    fn repeated(byte: u8, len: usize) -> Vec<u8> {
        vec![byte; len]
    }

    fn tx_hash(byte: u8) -> TxHash {
        TxHash::new([byte; 32])
    }

    fn address(byte: u8) -> Address {
        Address::from_slice(&[byte; 20])
            .unwrap_or_else(|error| panic!("expected valid test address: {error}"))
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

    fn value_bytes(value: u128) -> Vec<u8> {
        value.to_be_bytes().to_vec()
    }

    fn token_data_input() -> DecodedTokenDataInput {
        DecodedTokenDataInput {
            token_address: Some(repeated(0x11, 20)),
            token_type: Some(0),
            token_sub_id: Some(repeated(0, 32)),
        }
    }

    fn v2_ciphertext_input() -> DecodedV2CommitmentCiphertextInput {
        DecodedV2CommitmentCiphertextInput {
            ciphertext: Some(vec![
                repeated(1, 32),
                repeated(2, 32),
                repeated(3, 32),
                repeated(4, 32),
            ]),
            blinded_sender_viewing_key: Some(repeated(5, 32)),
            blinded_receiver_viewing_key: Some(repeated(6, 32)),
            annotation_data: Some(vec![7, 8]),
            memo: Some(vec![9, 10]),
        }
    }

    fn v3_ciphertext_input() -> DecodedV3CommitmentCiphertextInput {
        DecodedV3CommitmentCiphertextInput {
            ciphertext: Some(repeated(7, 20)),
            blinded_sender_viewing_key: Some(repeated(8, 32)),
            blinded_receiver_viewing_key: Some(repeated(9, 32)),
        }
    }

    fn shield_preimage_input() -> DecodedShieldPreimageInput {
        DecodedShieldPreimageInput {
            note_public_key: Some({
                let mut bytes = repeated(0, 32);
                bytes[31] = 12;
                bytes
            }),
            token_data: Some(token_data_input()),
            value: Some(value_bytes(100)),
        }
    }

    fn shield_ciphertext_input() -> DecodedShieldCiphertextInput {
        DecodedShieldCiphertextInput {
            encrypted_bundle: Some(vec![
                repeated(0x21, 32),
                repeated(0x22, 32),
                repeated(0x23, 16),
            ]),
            shield_key: Some(repeated(0x24, 32)),
        }
    }

    #[test]
    fn decodes_v2_transact_event_into_typed_commitment_event() {
        let event = decode_commitment_event(DecodedCommitmentEventInput::V2Transact(
            V2TransactEventInput {
                transaction_hash: Some(repeated(0xaa, 32)),
                block_number: Some(99),
                tree_number: Some(0),
                start_position: Some(1),
                commitment_hashes: Some(vec![
                    {
                        let mut bytes = repeated(0, 32);
                        bytes[31] = 1;
                        bytes
                    },
                    {
                        let mut bytes = repeated(0, 32);
                        bytes[31] = 2;
                        bytes
                    },
                ]),
                commitment_ciphertexts: Some(vec![v2_ciphertext_input(), v2_ciphertext_input()]),
                railgun_txid: None,
            },
        ))
        .unwrap_or_else(|error| panic!("v2 transact event should decode: {error}"));

        let railgun_types::VersionedCommitmentEvent::V2(event) = event else {
            panic!("expected v2 commitment event");
        };
        assert_eq!(event.tree_number(), UtxoTreeCoordinate::in_tree(0));
        assert_eq!(event.start_position(), CommitmentLeafPosition::new(1));
        assert_eq!(event.commitments().len(), 2);
    }

    #[test]
    fn decodes_v2_shield_event_and_derives_commitment_hash() {
        let event =
            decode_commitment_event(DecodedCommitmentEventInput::V2Shield(V2ShieldEventInput {
                transaction_hash: Some(repeated(0xbb, 32)),
                block_number: Some(100),
                tree_number: Some(0),
                start_position: Some(0),
                preimages: Some(vec![shield_preimage_input()]),
                shield_ciphertexts: Some(vec![shield_ciphertext_input()]),
                fees: Some(vec![value_bytes(1)]),
            }))
            .unwrap_or_else(|error| panic!("v2 shield event should decode: {error}"));

        let railgun_types::VersionedCommitmentEvent::V2(event) = event else {
            panic!("expected v2 commitment event");
        };
        assert_eq!(event.tree_number(), UtxoTreeCoordinate::in_tree(0));
        assert_eq!(event.start_position(), CommitmentLeafPosition::new(0));
        assert_eq!(event.commitments().len(), 1);
    }

    #[test]
    fn rejects_v2_transact_mismatched_commitment_counts() {
        let Err(error) = decode_commitment_event(DecodedCommitmentEventInput::V2Transact(
            V2TransactEventInput {
                transaction_hash: Some(repeated(0xaa, 32)),
                block_number: Some(99),
                tree_number: Some(0),
                start_position: Some(1),
                commitment_hashes: Some(vec![repeated(0, 32)]),
                commitment_ciphertexts: Some(vec![v2_ciphertext_input(), v2_ciphertext_input()]),
                railgun_txid: None,
            },
        )) else {
            panic!("mismatched v2 transact counts should fail");
        };

        assert_eq!(
            error,
            EventError::MismatchedFieldCounts {
                field: "commitment_hashes/commitment_ciphertexts",
                expected: 1,
                actual: 2,
            }
        );
    }

    #[test]
    fn rejects_missing_required_field() {
        let Err(error) = decode_v2_nullifier_event(V2NullifierEventInput {
            transaction_hash: Some(repeated(0xcc, 32)),
            block_number: Some(5),
            tree_number: None,
            nullifiers: Some(vec![repeated(0, 32)]),
        }) else {
            panic!("missing tree number should fail");
        };

        assert_eq!(error, EventError::MissingField("tree_number"));
    }

    #[test]
    fn rejects_malformed_v2_ciphertext_word_length() {
        let Err(error) = decode_commitment_event(DecodedCommitmentEventInput::V2Transact(
            V2TransactEventInput {
                transaction_hash: Some(repeated(0xaa, 32)),
                block_number: Some(99),
                tree_number: Some(0),
                start_position: Some(1),
                commitment_hashes: Some(vec![{
                    let mut bytes = repeated(0, 32);
                    bytes[31] = 1;
                    bytes
                }]),
                commitment_ciphertexts: Some(vec![DecodedV2CommitmentCiphertextInput {
                    ciphertext: Some(vec![
                        repeated(1, 31),
                        repeated(2, 32),
                        repeated(3, 32),
                        repeated(4, 32),
                    ]),
                    blinded_sender_viewing_key: Some(repeated(5, 32)),
                    blinded_receiver_viewing_key: Some(repeated(6, 32)),
                    annotation_data: Some(vec![7]),
                    memo: Some(vec![8]),
                }]),
                railgun_txid: None,
            },
        )) else {
            panic!("malformed ciphertext should fail");
        };

        assert!(matches!(error, EventError::InvalidCommitmentCiphertext(_)));
    }

    #[test]
    fn decodes_v2_and_v3_nullifier_events_preserving_order() {
        let v2 = decode_v2_nullifier_event(V2NullifierEventInput {
            transaction_hash: Some(repeated(0xcd, 32)),
            block_number: Some(6),
            tree_number: Some(7),
            nullifiers: Some(vec![
                {
                    let mut bytes = repeated(0, 32);
                    bytes[31] = 1;
                    bytes
                },
                {
                    let mut bytes = repeated(0, 32);
                    bytes[31] = 2;
                    bytes
                },
            ]),
        })
        .unwrap_or_else(|error| panic!("v2 nullifier event should decode: {error}"));
        let v3 = decode_v3_nullifier_event(V3NullifierEventInput {
            transaction_hash: Some(repeated(0xce, 32)),
            block_number: Some(7),
            spend_tree_number: Some(8),
            nullifiers: Some(vec![
                {
                    let mut bytes = repeated(0, 32);
                    bytes[31] = 1;
                    bytes
                },
                {
                    let mut bytes = repeated(0, 32);
                    bytes[31] = 2;
                    bytes
                },
            ]),
        })
        .unwrap_or_else(|error| panic!("v3 nullifier event should decode: {error}"));

        assert_eq!(v2.nullifiers().len(), 2);
        assert_eq!(v3.nullifiers().len(), 2);
        assert_eq!(v2.tree_number(), UtxoTreeCoordinate::in_tree(7));
        assert_eq!(v3.spend_tree_number(), UtxoTreeCoordinate::in_tree(8));
    }

    #[test]
    fn decodes_v2_unshield_event() {
        let event = decode_v2_unshield_event(V2UnshieldEventInput {
            transaction_hash: Some(repeated(0xdd, 32)),
            block_number: Some(8),
            event_log_index: Some(9),
            to_address: Some(repeated(0x31, 20)),
            token_data: Some(token_data_input()),
            amount: Some(value_bytes(100)),
            fee: Some(value_bytes(1)),
        })
        .unwrap_or_else(|error| panic!("v2 unshield event should decode: {error}"));

        assert_eq!(event.event_log_index().get(), 9);
        assert_eq!(event.data().amount().get(), 100);
    }

    #[test]
    fn decodes_v3_transact_event() {
        let event = decode_commitment_event(DecodedCommitmentEventInput::V3Transact(
            V3TransactEventInput {
                transaction_hash: Some(repeated(0xee, 32)),
                block_number: Some(10),
                tree_number: Some(0),
                start_position: Some(1),
                commitment_hashes: Some(vec![
                    {
                        let mut bytes = repeated(0, 32);
                        bytes[31] = 3;
                        bytes
                    },
                    {
                        let mut bytes = repeated(0, 32);
                        bytes[31] = 4;
                        bytes
                    },
                ]),
                commitment_ciphertexts: Some(vec![v3_ciphertext_input(), v3_ciphertext_input()]),
                transact_commitment_batch_start_index: Some(0),
                sender_ciphertext: Some(vec![0xaa, 0xbb]),
                railgun_txid: Some({
                    let mut bytes = repeated(0, 32);
                    bytes[31] = 5;
                    bytes
                }),
            },
        ))
        .unwrap_or_else(|error| panic!("v3 transact event should decode: {error}"));

        let railgun_types::VersionedCommitmentEvent::V3(event) = event else {
            panic!("expected v3 event");
        };
        assert_eq!(event.tree_number(), UtxoTreeCoordinate::in_tree(0));
        assert_eq!(event.start_position(), CommitmentLeafPosition::new(1));
        assert_eq!(event.commitments().len(), 2);
    }

    #[test]
    fn decodes_v3_unshield_event() {
        let event = decode_v3_unshield_event(V3UnshieldEventInput {
            transaction_hash: Some(repeated(0xef, 32)),
            block_number: Some(11),
            transact_index: Some(3),
            railgun_txid: Some({
                let mut bytes = repeated(0, 32);
                bytes[31] = 6;
                bytes
            }),
            to_address: Some(repeated(0x41, 20)),
            token_data: Some(token_data_input()),
            amount: Some(value_bytes(99)),
            fee: Some(value_bytes(1)),
        })
        .unwrap_or_else(|error| panic!("v3 unshield event should decode: {error}"));

        assert_eq!(event.transact_index().get(), 3);
        assert_eq!(event.data().amount().get(), 99);
    }

    #[test]
    fn decodes_v3_transaction_event_with_unshield_sentinels() {
        let event = decode_v3_transaction_event(V3TransactionEventInput {
            transaction_hash: Some(repeated(0xf0, 32)),
            block_number: Some(12),
            commitments: Some(vec![{
                let mut bytes = repeated(0, 32);
                bytes[31] = 7;
                bytes
            }]),
            nullifiers: Some(vec![{
                let mut bytes = repeated(0, 32);
                bytes[31] = 8;
                bytes
            }]),
            bound_params_hash: Some(repeated(0x51, 32)),
            unshield: Some(V3TransactionUnshieldDataInput {
                to_address: Some(repeated(0x61, 20)),
                token_data: Some(token_data_input()),
                value: Some(value_bytes(100)),
            }),
            utxo_tree_in: Some(0),
            utxo_tree_out: Some(GLOBAL_UTXO_TREE_UNSHIELD_EVENT_HARDCODED_VALUE),
            utxo_batch_start_position_out: Some(
                GLOBAL_UTXO_POSITION_UNSHIELD_EVENT_HARDCODED_VALUE,
            ),
            verification_hash: Some(repeated(0x71, 32)),
        })
        .unwrap_or_else(|error| panic!("v3 transaction event should decode: {error}"));

        assert_eq!(event.commitments().len(), 1);
        assert_eq!(event.bound_params_hash().as_bytes(), &repeated(0x51, 32).as_slice());
        assert_eq!(event.utxo_tree_out(), UtxoTreeCoordinate::unshield_event_hardcoded());
        assert_eq!(
            event.utxo_batch_start_position_out(),
            UtxoLeafCoordinate::unshield_event_hardcoded()
        );
        assert_eq!(event.unshield().map(|value| value.value().get()), Some(100));
        assert_eq!(
            event.verification_hash().map(railgun_types::VerificationHash::as_bytes),
            Some(&[0x71; 32])
        );
    }

    #[test]
    fn decodes_raw_v2_transact_log_into_canonical_event() {
        let log = raw_log(
            &V2TransactLog {
                treeNumber: U256::ZERO,
                startPosition: U256::from(1_u8),
                hash: vec![
                    FixedBytes::from({
                        let mut bytes = [0_u8; 32];
                        bytes[31] = 1;
                        bytes
                    }),
                    FixedBytes::from({
                        let mut bytes = [0_u8; 32];
                        bytes[31] = 2;
                        bytes
                    }),
                ],
                ciphertext: vec![
                    EventV2CommitmentCiphertextAbi {
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
                    },
                    EventV2CommitmentCiphertextAbi {
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
                    },
                ],
            }
            .encode_log_data(),
            0xaa,
            99,
            None,
        );

        let events = decode_raw_railgun_log(RawRailgunLogVersion::V2, &log)
            .unwrap_or_else(|error| panic!("raw v2 transact log should decode: {error}"));

        assert_eq!(events.len(), 1);
        let DecodedRailgunLogEvent::Commitment(railgun_types::VersionedCommitmentEvent::V2(event)) =
            &events[0]
        else {
            panic!("expected one v2 commitment event");
        };
        assert_eq!(event.start_position(), CommitmentLeafPosition::new(1));
        assert_eq!(event.commitments().len(), 2);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn decodes_raw_v3_accumulator_log_into_ordered_canonical_events() {
        let log = raw_log(
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
            0xee,
            10,
            None,
        );

        let events = decode_raw_railgun_log(RawRailgunLogVersion::V3, &log)
            .unwrap_or_else(|error| panic!("raw v3 accumulator log should decode: {error}"));

        assert_eq!(events.len(), 4);
        let DecodedRailgunLogEvent::Commitment(railgun_types::VersionedCommitmentEvent::V3(
            transact,
        )) = &events[0]
        else {
            panic!("expected first v3 event to be a commitment event");
        };
        assert_eq!(transact.start_position(), CommitmentLeafPosition::new(1));
        assert_eq!(transact.commitments().len(), 1);

        let DecodedRailgunLogEvent::Nullifier(railgun_types::VersionedNullifierEvent::V3(
            nullifiers,
        )) = &events[1]
        else {
            panic!("expected second v3 event to be a nullifier event");
        };
        assert_eq!(nullifiers.nullifiers().len(), 1);

        let DecodedRailgunLogEvent::Unshield(railgun_types::VersionedUnshieldEvent::V3(unshield)) =
            &events[2]
        else {
            panic!("expected third v3 event to be an unshield event");
        };
        assert_eq!(unshield.data().amount().get(), 50);

        let DecodedRailgunLogEvent::Commitment(railgun_types::VersionedCommitmentEvent::V3(shield)) =
            &events[3]
        else {
            panic!("expected fourth v3 event to be a shield commitment event");
        };
        assert_eq!(shield.start_position(), CommitmentLeafPosition::new(2));
        assert_eq!(shield.commitments().len(), 1);
    }

    #[test]
    fn rejects_raw_log_with_unsupported_topic() {
        let log = RawRailgunLog {
            contract_address: address(0x90),
            topics: vec![[0x99_u8; 32]],
            data: Vec::new(),
            transaction_hash: Some(tx_hash(0xaa)),
            block_number: Some(1),
            log_index: None,
        };

        let Err(error) = decode_raw_railgun_log(RawRailgunLogVersion::V2, &log) else {
            panic!("unsupported topic should fail");
        };

        assert_eq!(
            error,
            RawRailgunLogError::UnsupportedVersionTopic {
                version: RawRailgunLogVersion::V2,
                topic: [0x99_u8; 32],
            }
        );
    }

    #[test]
    fn rejects_raw_v2_unshield_without_log_index() {
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

        let Err(error) = decode_raw_railgun_log(RawRailgunLogVersion::V2, &log) else {
            panic!("missing v2 unshield log index should fail");
        };

        assert_eq!(error, RawRailgunLogError::MissingContext("log_index"));
    }

    #[test]
    fn rejects_malformed_v3_verification_hash_length() {
        let Err(error) = decode_v3_transaction_event(V3TransactionEventInput {
            transaction_hash: Some(repeated(0xf0, 32)),
            block_number: Some(12),
            commitments: Some(vec![{
                let mut bytes = repeated(0, 32);
                bytes[31] = 7;
                bytes
            }]),
            nullifiers: Some(vec![{
                let mut bytes = repeated(0, 32);
                bytes[31] = 8;
                bytes
            }]),
            bound_params_hash: Some(repeated(0x51, 32)),
            unshield: None,
            utxo_tree_in: Some(0),
            utxo_tree_out: Some(0),
            utxo_batch_start_position_out: Some(0),
            verification_hash: Some(repeated(0x71, 31)),
        }) else {
            panic!("short verification hash should fail");
        };

        assert_eq!(
            error,
            EventError::InvalidDomainValue(
                "verification hash must be exactly 32 bytes".to_string()
            )
        );
    }
}
