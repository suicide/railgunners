use crate::{TxHash, VersionedCommitmentEvent, VersionedNullifierEvent, VersionedUnshieldEvent};

/// Provider-agnostic transaction receipt status.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TransactionReceiptStatus {
    /// The transaction executed successfully.
    Success,
    /// The transaction reverted or otherwise failed.
    Failure,
}

impl TransactionReceiptStatus {
    /// Returns whether the receipt represents a successful transaction.
    #[must_use]
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Success)
    }
}

/// Minimal provider-agnostic transaction receipt context.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RawTransactionReceipt {
    status: TransactionReceiptStatus,
    transaction_hash: TxHash,
}

impl RawTransactionReceipt {
    /// Creates a minimal typed transaction receipt context.
    #[must_use]
    pub const fn new(status: TransactionReceiptStatus, transaction_hash: TxHash) -> Self {
        Self { status, transaction_hash }
    }

    /// Returns the receipt execution status.
    #[must_use]
    pub const fn status(&self) -> TransactionReceiptStatus {
        self.status
    }

    /// Returns the receipt transaction hash.
    #[must_use]
    pub const fn transaction_hash(&self) -> TxHash {
        self.transaction_hash
    }
}

/// Stable public Railgun event discriminator preserved in receipt order.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PublicRailgunEventKind {
    /// Commitment-oriented event.
    Commitment,
    /// Nullifier-oriented event.
    Nullifier,
    /// Unshield-oriented event.
    Unshield,
}

/// Typed transaction-local summary of the public Railgun outcome of one receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicRailgunTransactionSummary {
    status: TransactionReceiptStatus,
    transaction_hash: TxHash,
    event_kinds_in_order: Vec<PublicRailgunEventKind>,
    commitment_events: Vec<VersionedCommitmentEvent>,
    nullifier_events: Vec<VersionedNullifierEvent>,
    unshield_events: Vec<VersionedUnshieldEvent>,
}

impl PublicRailgunTransactionSummary {
    /// Creates a transaction-local public summary.
    #[must_use]
    pub fn new(
        status: TransactionReceiptStatus,
        transaction_hash: TxHash,
        event_kinds_in_order: Vec<PublicRailgunEventKind>,
        commitment_events: Vec<VersionedCommitmentEvent>,
        nullifier_events: Vec<VersionedNullifierEvent>,
        unshield_events: Vec<VersionedUnshieldEvent>,
    ) -> Self {
        Self {
            status,
            transaction_hash,
            event_kinds_in_order,
            commitment_events,
            nullifier_events,
            unshield_events,
        }
    }

    /// Returns the receipt execution status.
    #[must_use]
    pub const fn status(&self) -> TransactionReceiptStatus {
        self.status
    }

    /// Returns the receipt transaction hash.
    #[must_use]
    pub const fn transaction_hash(&self) -> TxHash {
        self.transaction_hash
    }

    /// Returns the decoded Railgun event kinds in deterministic emitted order.
    #[must_use]
    pub fn event_kinds_in_order(&self) -> &[PublicRailgunEventKind] {
        &self.event_kinds_in_order
    }

    /// Returns decoded public commitment events present in the receipt.
    #[must_use]
    pub fn commitment_events(&self) -> &[VersionedCommitmentEvent] {
        &self.commitment_events
    }

    /// Returns decoded public nullifier events present in the receipt.
    #[must_use]
    pub fn nullifier_events(&self) -> &[VersionedNullifierEvent] {
        &self.nullifier_events
    }

    /// Returns decoded public unshield events present in the receipt.
    #[must_use]
    pub fn unshield_events(&self) -> &[VersionedUnshieldEvent] {
        &self.unshield_events
    }
}
