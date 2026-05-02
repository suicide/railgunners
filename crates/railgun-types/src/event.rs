use crate::{
    Address, BoundParamsHash, CommitmentLeafPosition, DecodedCommitmentCiphertextV2,
    DecodedCommitmentCiphertextV3, NoteCommitment, NotePublicKey, NoteValue, Nullifier,
    RailgunTxid, ShieldCiphertext, TxHash, UtxoLeafCoordinate, UtxoTreeCoordinate,
    VerificationHash,
};

/// Typed EVM block number attached to decoded event records.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BlockNumber(u64);

impl BlockNumber {
    /// Creates a block number from an explicit integer value.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the inner integer value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Typed EVM log index used by V2 decoded unshield events.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EventLogIndex(u64);

impl EventLogIndex {
    /// Creates an event log index from an explicit integer value.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the inner integer value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Typed accumulator transaction index used by V3 accumulator-derived event flows.
///
/// This is intentionally distinct from an EVM log index because V3 unshield data is
/// grouped inside one accumulator update and addressed by transaction batch position.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AccumulatorTransactionIndex(u32);

impl AccumulatorTransactionIndex {
    /// Creates an accumulator transaction index from an explicit integer value.
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Returns the inner integer value.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Typed per-output V3 transact commitment batch index.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TransactCommitmentBatchIndex(u32);

impl TransactCommitmentBatchIndex {
    /// Creates a transact commitment batch index from an explicit integer value.
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Returns the inner integer value.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Opaque V3 sender-ciphertext payload shared across transact commitments in one transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SenderCiphertext(Vec<u8>);

impl SenderCiphertext {
    /// Creates a sender-ciphertext payload from raw bytes.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Returns the raw sender-ciphertext bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Canonical shield-note preimage reconstructed from decoded shield event fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShieldPreimage {
    note_public_key: NotePublicKey,
    token_data: crate::TokenData,
    value: NoteValue,
}

impl ShieldPreimage {
    /// Creates a canonical shield preimage from explicit typed note fields.
    #[must_use]
    pub const fn new(
        note_public_key: NotePublicKey,
        token_data: crate::TokenData,
        value: NoteValue,
    ) -> Self {
        Self { note_public_key, token_data, value }
    }

    /// Returns the note public key.
    #[must_use]
    pub const fn note_public_key(&self) -> &NotePublicKey {
        &self.note_public_key
    }

    /// Returns the token data.
    #[must_use]
    pub const fn token_data(&self) -> &crate::TokenData {
        &self.token_data
    }

    /// Returns the note value.
    #[must_use]
    pub const fn value(&self) -> NoteValue {
        self.value
    }
}

/// Shared decoded shield commitment model used by both V2 and V3 shield events.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShieldCommitment {
    hash: NoteCommitment,
    txid: TxHash,
    block_number: BlockNumber,
    pre_image: ShieldPreimage,
    shield_ciphertext: ShieldCiphertext,
    fee: Option<NoteValue>,
    utxo_tree: UtxoTreeCoordinate,
    utxo_index: CommitmentLeafPosition,
    from: Option<Address>,
}

impl ShieldCommitment {
    /// Creates a decoded shield commitment.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        hash: NoteCommitment,
        txid: TxHash,
        block_number: BlockNumber,
        pre_image: ShieldPreimage,
        shield_ciphertext: ShieldCiphertext,
        fee: Option<NoteValue>,
        utxo_tree: UtxoTreeCoordinate,
        utxo_index: CommitmentLeafPosition,
        from: Option<Address>,
    ) -> Self {
        Self {
            hash,
            txid,
            block_number,
            pre_image,
            shield_ciphertext,
            fee,
            utxo_tree,
            utxo_index,
            from,
        }
    }

    /// Returns the note commitment hash.
    #[must_use]
    pub const fn hash(&self) -> &NoteCommitment {
        &self.hash
    }

    /// Returns the containing EVM transaction hash.
    #[must_use]
    pub const fn txid(&self) -> &TxHash {
        &self.txid
    }

    /// Returns the EVM block number.
    #[must_use]
    pub const fn block_number(&self) -> BlockNumber {
        self.block_number
    }

    /// Returns the canonical shield preimage.
    #[must_use]
    pub const fn pre_image(&self) -> &ShieldPreimage {
        &self.pre_image
    }

    /// Returns the parsed shield ciphertext.
    #[must_use]
    pub const fn shield_ciphertext(&self) -> &ShieldCiphertext {
        &self.shield_ciphertext
    }

    /// Returns the optional fee value.
    #[must_use]
    pub const fn fee(&self) -> Option<NoteValue> {
        self.fee
    }

    /// Returns the output UTXO tree.
    #[must_use]
    pub const fn utxo_tree(&self) -> UtxoTreeCoordinate {
        self.utxo_tree
    }

    /// Returns the output UTXO leaf position.
    #[must_use]
    pub const fn utxo_index(&self) -> CommitmentLeafPosition {
        self.utxo_index
    }

    /// Returns the optional public sender address when present on-chain.
    #[must_use]
    pub const fn from(&self) -> Option<Address> {
        self.from
    }
}

/// Decoded V2 transact commitment emitted by the V2 `Transact` event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct V2TransactCommitment {
    hash: NoteCommitment,
    txid: TxHash,
    block_number: BlockNumber,
    ciphertext: DecodedCommitmentCiphertextV2,
    utxo_tree: UtxoTreeCoordinate,
    utxo_index: CommitmentLeafPosition,
    railgun_txid: Option<RailgunTxid>,
}

impl V2TransactCommitment {
    /// Creates a decoded V2 transact commitment.
    #[must_use]
    pub const fn new(
        hash: NoteCommitment,
        txid: TxHash,
        block_number: BlockNumber,
        ciphertext: DecodedCommitmentCiphertextV2,
        utxo_tree: UtxoTreeCoordinate,
        utxo_index: CommitmentLeafPosition,
        railgun_txid: Option<RailgunTxid>,
    ) -> Self {
        Self { hash, txid, block_number, ciphertext, utxo_tree, utxo_index, railgun_txid }
    }

    /// Returns the note commitment hash.
    #[must_use]
    pub const fn hash(&self) -> &NoteCommitment {
        &self.hash
    }

    /// Returns the containing EVM transaction hash.
    #[must_use]
    pub const fn txid(&self) -> &TxHash {
        &self.txid
    }

    /// Returns the EVM block number.
    #[must_use]
    pub const fn block_number(&self) -> BlockNumber {
        self.block_number
    }

    /// Returns the raw decoded V2 ciphertext payload.
    #[must_use]
    pub const fn ciphertext(&self) -> &DecodedCommitmentCiphertextV2 {
        &self.ciphertext
    }

    /// Returns the output UTXO tree.
    #[must_use]
    pub const fn utxo_tree(&self) -> UtxoTreeCoordinate {
        self.utxo_tree
    }

    /// Returns the output UTXO leaf position.
    #[must_use]
    pub const fn utxo_index(&self) -> CommitmentLeafPosition {
        self.utxo_index
    }

    /// Returns the Railgun txid when linked by later processing.
    #[must_use]
    pub const fn railgun_txid(&self) -> Option<&RailgunTxid> {
        self.railgun_txid.as_ref()
    }
}

/// Decoded V3 transact commitment emitted by the V3 accumulator flow.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct V3TransactCommitment {
    hash: NoteCommitment,
    txid: TxHash,
    block_number: BlockNumber,
    ciphertext: DecodedCommitmentCiphertextV3,
    utxo_tree: UtxoTreeCoordinate,
    utxo_index: CommitmentLeafPosition,
    transact_commitment_batch_index: TransactCommitmentBatchIndex,
    railgun_txid: RailgunTxid,
    sender_ciphertext: SenderCiphertext,
}

impl V3TransactCommitment {
    /// Creates a decoded V3 transact commitment.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        hash: NoteCommitment,
        txid: TxHash,
        block_number: BlockNumber,
        ciphertext: DecodedCommitmentCiphertextV3,
        utxo_tree: UtxoTreeCoordinate,
        utxo_index: CommitmentLeafPosition,
        transact_commitment_batch_index: TransactCommitmentBatchIndex,
        railgun_txid: RailgunTxid,
        sender_ciphertext: SenderCiphertext,
    ) -> Self {
        Self {
            hash,
            txid,
            block_number,
            ciphertext,
            utxo_tree,
            utxo_index,
            transact_commitment_batch_index,
            railgun_txid,
            sender_ciphertext,
        }
    }

    /// Returns the note commitment hash.
    #[must_use]
    pub const fn hash(&self) -> &NoteCommitment {
        &self.hash
    }

    /// Returns the containing EVM transaction hash.
    #[must_use]
    pub const fn txid(&self) -> &TxHash {
        &self.txid
    }

    /// Returns the EVM block number.
    #[must_use]
    pub const fn block_number(&self) -> BlockNumber {
        self.block_number
    }

    /// Returns the raw decoded V3 ciphertext payload.
    #[must_use]
    pub const fn ciphertext(&self) -> &DecodedCommitmentCiphertextV3 {
        &self.ciphertext
    }

    /// Returns the output UTXO tree.
    #[must_use]
    pub const fn utxo_tree(&self) -> UtxoTreeCoordinate {
        self.utxo_tree
    }

    /// Returns the output UTXO leaf position.
    #[must_use]
    pub const fn utxo_index(&self) -> CommitmentLeafPosition {
        self.utxo_index
    }

    /// Returns the batch index used for sender-ciphertext metadata decryption.
    #[must_use]
    pub const fn transact_commitment_batch_index(&self) -> TransactCommitmentBatchIndex {
        self.transact_commitment_batch_index
    }

    /// Returns the canonical linked Railgun txid.
    #[must_use]
    pub const fn railgun_txid(&self) -> &RailgunTxid {
        &self.railgun_txid
    }

    /// Returns the opaque transaction-level sender ciphertext.
    #[must_use]
    pub const fn sender_ciphertext(&self) -> &SenderCiphertext {
        &self.sender_ciphertext
    }
}

/// Decoded V2 commitment entry emitted by V2 wallet-relevant events.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum V2Commitment {
    /// V2 transact commitment.
    Transact(V2TransactCommitment),
    /// V2 shield commitment.
    Shield(ShieldCommitment),
}

/// Decoded V3 commitment entry emitted by V3 wallet-relevant events.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum V3Commitment {
    /// V3 transact commitment.
    Transact(V3TransactCommitment),
    /// V3 shield commitment.
    Shield(ShieldCommitment),
}

/// Decoded V2 commitment event preserving output tree placement and ordering.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct V2CommitmentEvent {
    txid: TxHash,
    tree_number: UtxoTreeCoordinate,
    start_position: CommitmentLeafPosition,
    commitments: Vec<V2Commitment>,
    block_number: BlockNumber,
}

impl V2CommitmentEvent {
    /// Creates a decoded V2 commitment event.
    #[must_use]
    pub fn new(
        txid: TxHash,
        tree_number: UtxoTreeCoordinate,
        start_position: CommitmentLeafPosition,
        commitments: Vec<V2Commitment>,
        block_number: BlockNumber,
    ) -> Self {
        Self { txid, tree_number, start_position, commitments, block_number }
    }

    /// Returns the containing EVM transaction hash.
    #[must_use]
    pub const fn txid(&self) -> &TxHash {
        &self.txid
    }

    /// Returns the output UTXO tree number.
    #[must_use]
    pub const fn tree_number(&self) -> UtxoTreeCoordinate {
        self.tree_number
    }

    /// Returns the first output leaf position for this batch.
    #[must_use]
    pub const fn start_position(&self) -> CommitmentLeafPosition {
        self.start_position
    }

    /// Returns decoded commitment entries in canonical event order.
    #[must_use]
    pub fn commitments(&self) -> &[V2Commitment] {
        &self.commitments
    }

    /// Returns the EVM block number.
    #[must_use]
    pub const fn block_number(&self) -> BlockNumber {
        self.block_number
    }
}

/// Decoded V3 commitment event preserving output tree placement and ordering.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct V3CommitmentEvent {
    txid: TxHash,
    tree_number: UtxoTreeCoordinate,
    start_position: CommitmentLeafPosition,
    commitments: Vec<V3Commitment>,
    block_number: BlockNumber,
}

impl V3CommitmentEvent {
    /// Creates a decoded V3 commitment event.
    #[must_use]
    pub fn new(
        txid: TxHash,
        tree_number: UtxoTreeCoordinate,
        start_position: CommitmentLeafPosition,
        commitments: Vec<V3Commitment>,
        block_number: BlockNumber,
    ) -> Self {
        Self { txid, tree_number, start_position, commitments, block_number }
    }

    /// Returns the containing EVM transaction hash.
    #[must_use]
    pub const fn txid(&self) -> &TxHash {
        &self.txid
    }

    /// Returns the output UTXO tree number.
    #[must_use]
    pub const fn tree_number(&self) -> UtxoTreeCoordinate {
        self.tree_number
    }

    /// Returns the first output leaf position for this batch.
    #[must_use]
    pub const fn start_position(&self) -> CommitmentLeafPosition {
        self.start_position
    }

    /// Returns decoded commitment entries in canonical event order.
    #[must_use]
    pub fn commitments(&self) -> &[V3Commitment] {
        &self.commitments
    }

    /// Returns the EVM block number.
    #[must_use]
    pub const fn block_number(&self) -> BlockNumber {
        self.block_number
    }
}

/// Version-aware decoded commitment event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VersionedCommitmentEvent {
    /// V2 decoded commitment event.
    V2(V2CommitmentEvent),
    /// V3 decoded commitment event.
    V3(V3CommitmentEvent),
}

/// Decoded V2 nullifier event preserving spend tree context and ordering.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct V2NullifierEvent {
    txid: TxHash,
    tree_number: UtxoTreeCoordinate,
    nullifiers: Vec<Nullifier>,
    block_number: BlockNumber,
}

impl V2NullifierEvent {
    /// Creates a decoded V2 nullifier event.
    #[must_use]
    pub fn new(
        txid: TxHash,
        tree_number: UtxoTreeCoordinate,
        nullifiers: Vec<Nullifier>,
        block_number: BlockNumber,
    ) -> Self {
        Self { txid, tree_number, nullifiers, block_number }
    }

    /// Returns the containing EVM transaction hash.
    #[must_use]
    pub const fn txid(&self) -> &TxHash {
        &self.txid
    }

    /// Returns the spend tree number.
    #[must_use]
    pub const fn tree_number(&self) -> UtxoTreeCoordinate {
        self.tree_number
    }

    /// Returns nullifiers in the emitted on-chain order.
    #[must_use]
    pub fn nullifiers(&self) -> &[Nullifier] {
        &self.nullifiers
    }

    /// Returns the EVM block number.
    #[must_use]
    pub const fn block_number(&self) -> BlockNumber {
        self.block_number
    }
}

/// Decoded V3 nullifier event preserving spend accumulator context and ordering.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct V3NullifierEvent {
    txid: TxHash,
    spend_tree_number: UtxoTreeCoordinate,
    nullifiers: Vec<Nullifier>,
    block_number: BlockNumber,
}

impl V3NullifierEvent {
    /// Creates a decoded V3 nullifier event.
    #[must_use]
    pub fn new(
        txid: TxHash,
        spend_tree_number: UtxoTreeCoordinate,
        nullifiers: Vec<Nullifier>,
        block_number: BlockNumber,
    ) -> Self {
        Self { txid, spend_tree_number, nullifiers, block_number }
    }

    /// Returns the containing EVM transaction hash.
    #[must_use]
    pub const fn txid(&self) -> &TxHash {
        &self.txid
    }

    /// Returns the spend accumulator tree number.
    #[must_use]
    pub const fn spend_tree_number(&self) -> UtxoTreeCoordinate {
        self.spend_tree_number
    }

    /// Returns nullifiers in the emitted on-chain order.
    #[must_use]
    pub fn nullifiers(&self) -> &[Nullifier] {
        &self.nullifiers
    }

    /// Returns the EVM block number.
    #[must_use]
    pub const fn block_number(&self) -> BlockNumber {
        self.block_number
    }
}

/// Version-aware decoded nullifier event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VersionedNullifierEvent {
    /// V2 decoded nullifier event.
    V2(V2NullifierEvent),
    /// V3 decoded nullifier event.
    V3(V3NullifierEvent),
}

/// Canonical unshield payload shared by versioned unshield event models.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnshieldData {
    to_address: Address,
    token_data: crate::TokenData,
    amount: NoteValue,
    fee: NoteValue,
}

impl UnshieldData {
    /// Creates canonical unshield payload data.
    #[must_use]
    pub const fn new(
        to_address: Address,
        token_data: crate::TokenData,
        amount: NoteValue,
        fee: NoteValue,
    ) -> Self {
        Self { to_address, token_data, amount, fee }
    }

    /// Returns the public recipient address.
    #[must_use]
    pub const fn to_address(&self) -> Address {
        self.to_address
    }

    /// Returns the token data.
    #[must_use]
    pub const fn token_data(&self) -> &crate::TokenData {
        &self.token_data
    }

    /// Returns the unshield amount.
    #[must_use]
    pub const fn amount(&self) -> NoteValue {
        self.amount
    }

    /// Returns the associated fee amount.
    #[must_use]
    pub const fn fee(&self) -> NoteValue {
        self.fee
    }
}

/// Decoded V2 unshield event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct V2UnshieldEvent {
    txid: TxHash,
    block_number: BlockNumber,
    event_log_index: EventLogIndex,
    data: UnshieldData,
}

impl V2UnshieldEvent {
    /// Creates a decoded V2 unshield event.
    #[must_use]
    pub const fn new(
        txid: TxHash,
        block_number: BlockNumber,
        event_log_index: EventLogIndex,
        data: UnshieldData,
    ) -> Self {
        Self { txid, block_number, event_log_index, data }
    }

    /// Returns the containing EVM transaction hash.
    #[must_use]
    pub const fn txid(&self) -> &TxHash {
        &self.txid
    }

    /// Returns the EVM block number.
    #[must_use]
    pub const fn block_number(&self) -> BlockNumber {
        self.block_number
    }

    /// Returns the EVM log index.
    #[must_use]
    pub const fn event_log_index(&self) -> EventLogIndex {
        self.event_log_index
    }

    /// Returns canonical unshield payload data.
    #[must_use]
    pub const fn data(&self) -> &UnshieldData {
        &self.data
    }
}

/// Decoded V3 unshield event derived from one accumulator transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct V3UnshieldEvent {
    txid: TxHash,
    block_number: BlockNumber,
    transact_index: AccumulatorTransactionIndex,
    railgun_txid: RailgunTxid,
    data: UnshieldData,
}

impl V3UnshieldEvent {
    /// Creates a decoded V3 unshield event.
    #[must_use]
    pub const fn new(
        txid: TxHash,
        block_number: BlockNumber,
        transact_index: AccumulatorTransactionIndex,
        railgun_txid: RailgunTxid,
        data: UnshieldData,
    ) -> Self {
        Self { txid, block_number, transact_index, railgun_txid, data }
    }

    /// Returns the containing EVM transaction hash.
    #[must_use]
    pub const fn txid(&self) -> &TxHash {
        &self.txid
    }

    /// Returns the EVM block number.
    #[must_use]
    pub const fn block_number(&self) -> BlockNumber {
        self.block_number
    }

    /// Returns the transaction index inside the accumulator update batch.
    #[must_use]
    pub const fn transact_index(&self) -> AccumulatorTransactionIndex {
        self.transact_index
    }

    /// Returns the linked Railgun txid.
    #[must_use]
    pub const fn railgun_txid(&self) -> &RailgunTxid {
        &self.railgun_txid
    }

    /// Returns canonical unshield payload data.
    #[must_use]
    pub const fn data(&self) -> &UnshieldData {
        &self.data
    }
}

/// Version-aware decoded unshield event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VersionedUnshieldEvent {
    /// V2 decoded unshield event.
    V2(V2UnshieldEvent),
    /// V3 decoded unshield event.
    V3(V3UnshieldEvent),
}

/// Canonical decoded V3 unshield payload embedded in transaction-level data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct V3TransactionUnshieldData {
    to_address: Address,
    token_data: crate::TokenData,
    value: NoteValue,
}

impl V3TransactionUnshieldData {
    /// Creates V3 transaction-level unshield payload data.
    #[must_use]
    pub const fn new(to_address: Address, token_data: crate::TokenData, value: NoteValue) -> Self {
        Self { to_address, token_data, value }
    }

    /// Returns the public recipient address.
    #[must_use]
    pub const fn to_address(&self) -> Address {
        self.to_address
    }

    /// Returns the token data.
    #[must_use]
    pub const fn token_data(&self) -> &crate::TokenData {
        &self.token_data
    }

    /// Returns the unshield value.
    #[must_use]
    pub const fn value(&self) -> NoteValue {
        self.value
    }
}

/// Decoded V3 transaction-level event emitted by accumulator processing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct V3TransactionEvent {
    txid: TxHash,
    block_number: BlockNumber,
    commitments: Vec<NoteCommitment>,
    nullifiers: Vec<Nullifier>,
    bound_params_hash: BoundParamsHash,
    unshield: Option<V3TransactionUnshieldData>,
    utxo_tree_in: UtxoTreeCoordinate,
    utxo_tree_out: UtxoTreeCoordinate,
    utxo_batch_start_position_out: UtxoLeafCoordinate,
    verification_hash: Option<VerificationHash>,
}

impl V3TransactionEvent {
    /// Creates a decoded V3 transaction-level event.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        txid: TxHash,
        block_number: BlockNumber,
        commitments: Vec<NoteCommitment>,
        nullifiers: Vec<Nullifier>,
        bound_params_hash: BoundParamsHash,
        unshield: Option<V3TransactionUnshieldData>,
        utxo_tree_in: UtxoTreeCoordinate,
        utxo_tree_out: UtxoTreeCoordinate,
        utxo_batch_start_position_out: UtxoLeafCoordinate,
        verification_hash: Option<VerificationHash>,
    ) -> Self {
        Self {
            txid,
            block_number,
            commitments,
            nullifiers,
            bound_params_hash,
            unshield,
            utxo_tree_in,
            utxo_tree_out,
            utxo_batch_start_position_out,
            verification_hash,
        }
    }

    /// Returns the containing EVM transaction hash.
    #[must_use]
    pub const fn txid(&self) -> &TxHash {
        &self.txid
    }

    /// Returns the EVM block number.
    #[must_use]
    pub const fn block_number(&self) -> BlockNumber {
        self.block_number
    }

    /// Returns transaction commitments in canonical order.
    #[must_use]
    pub fn commitments(&self) -> &[NoteCommitment] {
        &self.commitments
    }

    /// Returns transaction nullifiers in canonical order.
    #[must_use]
    pub fn nullifiers(&self) -> &[Nullifier] {
        &self.nullifiers
    }

    /// Returns the canonical local+global bound params hash.
    #[must_use]
    pub const fn bound_params_hash(&self) -> &BoundParamsHash {
        &self.bound_params_hash
    }

    /// Returns the optional transaction-level unshield payload.
    #[must_use]
    pub const fn unshield(&self) -> Option<&V3TransactionUnshieldData> {
        self.unshield.as_ref()
    }

    /// Returns the input spend tree number.
    #[must_use]
    pub const fn utxo_tree_in(&self) -> UtxoTreeCoordinate {
        self.utxo_tree_in
    }

    /// Returns the output tree number, including protocol-defined sentinels.
    #[must_use]
    pub const fn utxo_tree_out(&self) -> UtxoTreeCoordinate {
        self.utxo_tree_out
    }

    /// Returns the output batch start position, including protocol-defined sentinels.
    #[must_use]
    pub const fn utxo_batch_start_position_out(&self) -> UtxoLeafCoordinate {
        self.utxo_batch_start_position_out
    }

    /// Returns the verification hash when present on-chain.
    #[must_use]
    pub const fn verification_hash(&self) -> Option<&VerificationHash> {
        self.verification_hash.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;

    use super::{
        AccumulatorTransactionIndex, BlockNumber, CommitmentLeafPosition, EventLogIndex,
        SenderCiphertext, ShieldCommitment, ShieldPreimage, TransactCommitmentBatchIndex,
        UnshieldData, V2Commitment, V2CommitmentEvent, V2NullifierEvent, V2TransactCommitment,
        V2UnshieldEvent, V3Commitment, V3CommitmentEvent, V3NullifierEvent, V3TransactCommitment,
        V3TransactionEvent, V3TransactionUnshieldData, V3UnshieldEvent, VersionedCommitmentEvent,
        VersionedNullifierEvent, VersionedUnshieldEvent,
    };
    use crate::{
        Address, BoundParamsHash, DecodedCommitmentCiphertextV2, DecodedCommitmentCiphertextV3,
        NoteCommitment, NotePublicKey, NoteValue, Nullifier, RailgunTxid, ShieldCiphertext,
        ShieldCiphertextBlock, TokenData, TokenSubId, TokenType, TxHash, UtxoLeafCoordinate,
        UtxoTreeCoordinate, V2CiphertextBlock, VerificationHash, bn254_scalar_field_modulus,
    };

    fn scalar_from_hex(value: &str) -> BigUint {
        let trimmed = value.strip_prefix("0x").unwrap_or(value);
        BigUint::parse_bytes(trimmed.as_bytes(), 16)
            .unwrap_or_else(|| panic!("hex scalar should parse"))
    }

    fn note_commitment(value: &str) -> NoteCommitment {
        NoteCommitment::new(scalar_from_hex(value))
            .unwrap_or_else(|error| panic!("note commitment should validate: {error}"))
    }

    fn nullifier(value: &str) -> Nullifier {
        Nullifier::new(scalar_from_hex(value))
            .unwrap_or_else(|error| panic!("nullifier should validate: {error}"))
    }

    fn note_public_key(value: &str) -> NotePublicKey {
        NotePublicKey::new(scalar_from_hex(value))
            .unwrap_or_else(|error| panic!("note public key should validate: {error}"))
    }

    fn tx_hash(byte: u8) -> TxHash {
        TxHash::new([byte; 32])
    }

    fn railgun_txid(byte: u8) -> RailgunTxid {
        RailgunTxid::new(BigUint::from(byte))
            .unwrap_or_else(|error| panic!("railgun txid should validate: {error}"))
    }

    fn verification_hash(byte: u8) -> VerificationHash {
        VerificationHash::new([byte; 32])
    }

    fn bound_params_hash(byte: u8) -> BoundParamsHash {
        BoundParamsHash::new([byte; 32])
    }

    fn token_data() -> TokenData {
        TokenData::new(Address::new([0x11; 20]), TokenType::ERC20, TokenSubId::zero())
            .unwrap_or_else(|error| panic!("token data should validate: {error}"))
    }

    fn v2_ciphertext() -> DecodedCommitmentCiphertextV2 {
        DecodedCommitmentCiphertextV2::new(
            [[1_u8; 32], [2_u8; 32], [3_u8; 32], [4_u8; 32]],
            [5_u8; 32],
            [6_u8; 32],
            vec![7_u8; 3],
            vec![8_u8; 2],
        )
    }

    fn v3_ciphertext() -> DecodedCommitmentCiphertextV3 {
        DecodedCommitmentCiphertextV3::new(vec![9_u8; 20], [10_u8; 32], [11_u8; 32])
    }

    fn shield_ciphertext() -> ShieldCiphertext {
        ShieldCiphertext::new(
            [
                ShieldCiphertextBlock::new(vec![12_u8; 32]),
                ShieldCiphertextBlock::new(vec![13_u8; 32]),
                ShieldCiphertextBlock::new(vec![14_u8; 16]),
            ],
            crate::ViewingPublicKey::new([15_u8; 32]),
        )
    }

    #[test]
    fn scalar_wrappers_preserve_semantic_values() {
        assert_eq!(BlockNumber::new(42).get(), 42);
        assert_eq!(EventLogIndex::new(7).get(), 7);
        assert_eq!(AccumulatorTransactionIndex::new(3).get(), 3);
        assert_eq!(TransactCommitmentBatchIndex::new(5).get(), 5);
        assert_eq!(SenderCiphertext::new(vec![1_u8, 2_u8, 3_u8]).as_bytes(), &[1_u8, 2_u8, 3_u8]);
    }

    #[test]
    fn v2_commitment_event_preserves_tree_position_and_ordering() {
        let transact = V2Commitment::Transact(V2TransactCommitment::new(
            note_commitment("10"),
            tx_hash(1),
            BlockNumber::new(9),
            v2_ciphertext(),
            UtxoTreeCoordinate::in_tree(0),
            CommitmentLeafPosition::new(1),
            None,
        ));
        let shield = V2Commitment::Shield(ShieldCommitment::new(
            note_commitment("11"),
            tx_hash(1),
            BlockNumber::new(9),
            ShieldPreimage::new(note_public_key("12"), token_data(), NoteValue::new(100)),
            shield_ciphertext(),
            Some(NoteValue::new(2)),
            UtxoTreeCoordinate::in_tree(0),
            CommitmentLeafPosition::new(2),
            None,
        ));
        let event = V2CommitmentEvent::new(
            tx_hash(1),
            UtxoTreeCoordinate::in_tree(0),
            CommitmentLeafPosition::new(1),
            vec![transact, shield],
            BlockNumber::new(9),
        );

        assert_eq!(event.tree_number(), UtxoTreeCoordinate::in_tree(0));
        assert_eq!(event.start_position().get(), 1);
        assert_eq!(event.commitments().len(), 2);
        assert!(matches!(event.commitments()[0], V2Commitment::Transact(_)));
        assert!(matches!(event.commitments()[1], V2Commitment::Shield(_)));
        assert_eq!(event.block_number().get(), 9);
    }

    #[test]
    fn v3_commitment_event_preserves_sender_ciphertext_and_batch_index() {
        let railgun_txid = railgun_txid(2);
        let event = V3CommitmentEvent::new(
            tx_hash(2),
            UtxoTreeCoordinate::in_tree(0),
            CommitmentLeafPosition::new(1),
            vec![V3Commitment::Transact(V3TransactCommitment::new(
                note_commitment("13"),
                tx_hash(2),
                BlockNumber::new(10),
                v3_ciphertext(),
                UtxoTreeCoordinate::in_tree(0),
                CommitmentLeafPosition::new(1),
                TransactCommitmentBatchIndex::new(0),
                railgun_txid.clone(),
                SenderCiphertext::new(vec![0xaa, 0xbb]),
            ))],
            BlockNumber::new(10),
        );

        let V3Commitment::Transact(commitment) = &event.commitments()[0] else {
            panic!("expected transact commitment");
        };

        assert_eq!(event.tree_number(), UtxoTreeCoordinate::in_tree(0));
        assert_eq!(event.start_position().get(), 1);
        assert_eq!(commitment.transact_commitment_batch_index().get(), 0);
        assert_eq!(commitment.sender_ciphertext().as_bytes(), &[0xaa, 0xbb]);
        assert_eq!(commitment.railgun_txid(), &railgun_txid);
    }

    #[test]
    fn versioned_nullifier_events_preserve_ordering_and_context() {
        let first = nullifier("21");
        let second = nullifier("22");
        let v2 = VersionedNullifierEvent::V2(V2NullifierEvent::new(
            tx_hash(3),
            UtxoTreeCoordinate::in_tree(4),
            vec![first.clone(), second.clone()],
            BlockNumber::new(11),
        ));
        let v3 = VersionedNullifierEvent::V3(V3NullifierEvent::new(
            tx_hash(4),
            UtxoTreeCoordinate::in_tree(5),
            vec![first.clone(), second.clone()],
            BlockNumber::new(12),
        ));

        let VersionedNullifierEvent::V2(v2) = v2 else {
            panic!("expected v2 nullifier event");
        };
        assert_eq!(v2.tree_number(), UtxoTreeCoordinate::in_tree(4));
        assert_eq!(v2.nullifiers(), &[first.clone(), second.clone()]);

        let VersionedNullifierEvent::V3(v3) = v3 else {
            panic!("expected v3 nullifier event");
        };
        assert_eq!(v3.spend_tree_number(), UtxoTreeCoordinate::in_tree(5));
        assert_eq!(v3.nullifiers(), &[first, second]);
    }

    #[test]
    fn versioned_unshield_events_keep_v2_log_index_and_v3_transact_index_distinct() {
        let payload = UnshieldData::new(
            Address::new([0x22; 20]),
            token_data(),
            NoteValue::new(100),
            NoteValue::new(1),
        );
        let v2 = VersionedUnshieldEvent::V2(V2UnshieldEvent::new(
            tx_hash(5),
            BlockNumber::new(13),
            EventLogIndex::new(6),
            payload.clone(),
        ));
        let v3 = VersionedUnshieldEvent::V3(V3UnshieldEvent::new(
            tx_hash(6),
            BlockNumber::new(14),
            AccumulatorTransactionIndex::new(2),
            railgun_txid(7),
            payload.clone(),
        ));

        let VersionedUnshieldEvent::V2(v2) = v2 else {
            panic!("expected v2 unshield event");
        };
        assert_eq!(v2.event_log_index().get(), 6);
        assert_eq!(v2.data(), &payload);

        let VersionedUnshieldEvent::V3(v3) = v3 else {
            panic!("expected v3 unshield event");
        };
        assert_eq!(v3.transact_index().get(), 2);
        assert_eq!(v3.data(), &payload);
    }

    #[test]
    fn v3_transaction_event_preserves_grouped_transaction_data() {
        let transaction = V3TransactionEvent::new(
            tx_hash(8),
            BlockNumber::new(15),
            vec![note_commitment("31"), note_commitment("32")],
            vec![nullifier("41")],
            bound_params_hash(9),
            Some(V3TransactionUnshieldData::new(
                Address::new([0x33; 20]),
                token_data(),
                NoteValue::new(55),
            )),
            UtxoTreeCoordinate::in_tree(0),
            UtxoTreeCoordinate::unshield_event_hardcoded(),
            UtxoLeafCoordinate::unshield_event_hardcoded(),
            Some(verification_hash(10)),
        );

        assert_eq!(transaction.block_number().get(), 15);
        assert_eq!(transaction.commitments().len(), 2);
        assert_eq!(transaction.nullifiers().len(), 1);
        assert_eq!(transaction.bound_params_hash(), &bound_params_hash(9));
        assert_eq!(transaction.utxo_tree_out(), UtxoTreeCoordinate::unshield_event_hardcoded());
        assert_eq!(
            transaction.utxo_batch_start_position_out(),
            UtxoLeafCoordinate::unshield_event_hardcoded()
        );
        assert_eq!(transaction.verification_hash(), Some(&verification_hash(10)));
        assert_eq!(transaction.unshield().map(|unshield| unshield.value().get()), Some(55));
    }

    #[test]
    fn versioned_commitment_events_remain_distinct() {
        let v2 = VersionedCommitmentEvent::V2(V2CommitmentEvent::new(
            tx_hash(1),
            UtxoTreeCoordinate::in_tree(0),
            CommitmentLeafPosition::new(0),
            Vec::new(),
            BlockNumber::new(1),
        ));
        let v3 = VersionedCommitmentEvent::V3(V3CommitmentEvent::new(
            tx_hash(1),
            UtxoTreeCoordinate::in_tree(0),
            CommitmentLeafPosition::new(0),
            Vec::new(),
            BlockNumber::new(1),
        ));

        assert_ne!(v2, v3);
    }

    #[test]
    fn fixture_scalars_fit_domain_bounds() {
        assert!(scalar_from_hex("41") < bn254_scalar_field_modulus());
        assert!(scalar_from_hex("32") < bn254_scalar_field_modulus());
        assert_eq!(V2CiphertextBlock::LENGTH, 32);
    }
}
