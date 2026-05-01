use crate::{NoteCommitment, V2CiphertextBlock, VersionedCommitmentCiphertext};

/// Canonical txid-version discriminator for decoded transaction structs.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TxidVersion {
    /// V2 Poseidon Merkle txid format.
    V2PoseidonMerkle,
    /// V3 Poseidon Merkle txid format.
    V3PoseidonMerkle,
}

/// Raw decoded V2 commitment ciphertext entry before normalization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedCommitmentCiphertextV2 {
    ciphertext: [[u8; V2CiphertextBlock::LENGTH]; 4],
    blinded_sender_viewing_key: [u8; 32],
    blinded_receiver_viewing_key: [u8; 32],
    annotation_data: Vec<u8>,
    memo: Vec<u8>,
}

impl DecodedCommitmentCiphertextV2 {
    /// Creates a raw decoded V2 commitment ciphertext entry.
    #[must_use]
    pub fn new(
        ciphertext: [[u8; V2CiphertextBlock::LENGTH]; 4],
        blinded_sender_viewing_key: [u8; 32],
        blinded_receiver_viewing_key: [u8; 32],
        annotation_data: Vec<u8>,
        memo: Vec<u8>,
    ) -> Self {
        Self {
            ciphertext,
            blinded_sender_viewing_key,
            blinded_receiver_viewing_key,
            annotation_data,
            memo,
        }
    }

    /// Returns the four decoded V2 ciphertext words.
    #[must_use]
    pub const fn ciphertext(&self) -> &[[u8; V2CiphertextBlock::LENGTH]; 4] {
        &self.ciphertext
    }

    /// Returns the blinded sender viewing key bytes.
    #[must_use]
    pub const fn blinded_sender_viewing_key(&self) -> &[u8; 32] {
        &self.blinded_sender_viewing_key
    }

    /// Returns the blinded receiver viewing key bytes.
    #[must_use]
    pub const fn blinded_receiver_viewing_key(&self) -> &[u8; 32] {
        &self.blinded_receiver_viewing_key
    }

    /// Returns the annotation-data bytes.
    #[must_use]
    pub fn annotation_data(&self) -> &[u8] {
        &self.annotation_data
    }

    /// Returns the memo bytes.
    #[must_use]
    pub fn memo(&self) -> &[u8] {
        &self.memo
    }
}

/// Raw decoded V3 commitment ciphertext entry before normalization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedCommitmentCiphertextV3 {
    ciphertext: Vec<u8>,
    blinded_sender_viewing_key: [u8; 32],
    blinded_receiver_viewing_key: [u8; 32],
}

impl DecodedCommitmentCiphertextV3 {
    /// Creates a raw decoded V3 commitment ciphertext entry.
    #[must_use]
    pub fn new(
        ciphertext: Vec<u8>,
        blinded_sender_viewing_key: [u8; 32],
        blinded_receiver_viewing_key: [u8; 32],
    ) -> Self {
        Self { ciphertext, blinded_sender_viewing_key, blinded_receiver_viewing_key }
    }

    /// Returns the concatenated `nonce | bundle` ciphertext bytes.
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Returns the blinded sender viewing key bytes.
    #[must_use]
    pub const fn blinded_sender_viewing_key(&self) -> &[u8; 32] {
        &self.blinded_sender_viewing_key
    }

    /// Returns the blinded receiver viewing key bytes.
    #[must_use]
    pub const fn blinded_receiver_viewing_key(&self) -> &[u8; 32] {
        &self.blinded_receiver_viewing_key
    }
}

/// Minimal decoded V2 bound params shape needed for commitment-summary extraction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct V2TransactionBoundParams {
    commitment_ciphertext: Vec<DecodedCommitmentCiphertextV2>,
}

impl V2TransactionBoundParams {
    /// Creates the minimal decoded V2 bound params view.
    #[must_use]
    pub fn new(commitment_ciphertext: Vec<DecodedCommitmentCiphertextV2>) -> Self {
        Self { commitment_ciphertext }
    }

    /// Returns decoded commitment ciphertext entries in deterministic batch order.
    #[must_use]
    pub fn commitment_ciphertext(&self) -> &[DecodedCommitmentCiphertextV2] {
        &self.commitment_ciphertext
    }
}

/// Minimal decoded V3 local bound params shape needed for commitment-summary extraction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct V3TransactionBoundParamsLocal {
    commitment_ciphertext: Vec<DecodedCommitmentCiphertextV3>,
}

impl V3TransactionBoundParamsLocal {
    /// Creates the minimal decoded V3 local bound params view.
    #[must_use]
    pub fn new(commitment_ciphertext: Vec<DecodedCommitmentCiphertextV3>) -> Self {
        Self { commitment_ciphertext }
    }

    /// Returns decoded local commitment ciphertext entries in deterministic batch order.
    #[must_use]
    pub fn commitment_ciphertext(&self) -> &[DecodedCommitmentCiphertextV3] {
        &self.commitment_ciphertext
    }
}

/// Minimal decoded V3 bound params shape needed for commitment-summary extraction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct V3TransactionBoundParams {
    local: V3TransactionBoundParamsLocal,
}

impl V3TransactionBoundParams {
    /// Creates the minimal decoded V3 bound params view.
    #[must_use]
    pub const fn new(local: V3TransactionBoundParamsLocal) -> Self {
        Self { local }
    }

    /// Returns the decoded local V3 bound params.
    #[must_use]
    pub const fn local(&self) -> &V3TransactionBoundParamsLocal {
        &self.local
    }
}

/// Minimal decoded V2 transaction struct needed for commitment-summary extraction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct V2Transaction {
    txid_version: TxidVersion,
    commitments: Vec<NoteCommitment>,
    bound_params: V2TransactionBoundParams,
}

impl V2Transaction {
    /// Creates a decoded V2 transaction view.
    #[must_use]
    pub fn new(
        txid_version: TxidVersion,
        commitments: Vec<NoteCommitment>,
        bound_params: V2TransactionBoundParams,
    ) -> Self {
        Self { txid_version, commitments, bound_params }
    }

    /// Returns the txid-version discriminator.
    #[must_use]
    pub const fn txid_version(&self) -> TxidVersion {
        self.txid_version
    }

    /// Returns commitment hashes in canonical batch order.
    #[must_use]
    pub fn commitments(&self) -> &[NoteCommitment] {
        &self.commitments
    }

    /// Returns the decoded minimal V2 bound params view.
    #[must_use]
    pub const fn bound_params(&self) -> &V2TransactionBoundParams {
        &self.bound_params
    }
}

/// Minimal decoded V3 transaction struct needed for commitment-summary extraction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct V3Transaction {
    txid_version: TxidVersion,
    commitments: Vec<NoteCommitment>,
    bound_params: V3TransactionBoundParams,
}

impl V3Transaction {
    /// Creates a decoded V3 transaction view.
    #[must_use]
    pub fn new(
        txid_version: TxidVersion,
        commitments: Vec<NoteCommitment>,
        bound_params: V3TransactionBoundParams,
    ) -> Self {
        Self { txid_version, commitments, bound_params }
    }

    /// Returns the txid-version discriminator.
    #[must_use]
    pub const fn txid_version(&self) -> TxidVersion {
        self.txid_version
    }

    /// Returns commitment hashes in canonical batch order.
    #[must_use]
    pub fn commitments(&self) -> &[NoteCommitment] {
        &self.commitments
    }

    /// Returns the decoded minimal V3 bound params view.
    #[must_use]
    pub const fn bound_params(&self) -> &V3TransactionBoundParams {
        &self.bound_params
    }
}

/// Version-aware decoded transaction view used by extraction helpers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VersionedTransaction {
    /// Decoded V2 transaction view.
    V2(V2Transaction),
    /// Decoded V3 transaction view.
    V3(V3Transaction),
}

impl VersionedTransaction {
    /// Returns the required txid-version discriminator.
    #[must_use]
    pub const fn txid_version(&self) -> TxidVersion {
        match self {
            Self::V2(transaction) => transaction.txid_version(),
            Self::V3(transaction) => transaction.txid_version(),
        }
    }
}

/// Canonical normalized commitment summary extracted from a decoded transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitmentSummary {
    commitment_hash: NoteCommitment,
    commitment_ciphertext: VersionedCommitmentCiphertext,
}

impl CommitmentSummary {
    /// Creates a normalized commitment summary.
    #[must_use]
    pub const fn new(
        commitment_hash: NoteCommitment,
        commitment_ciphertext: VersionedCommitmentCiphertext,
    ) -> Self {
        Self { commitment_hash, commitment_ciphertext }
    }

    /// Returns the extracted commitment hash.
    #[must_use]
    pub const fn commitment_hash(&self) -> &NoteCommitment {
        &self.commitment_hash
    }

    /// Returns the parsed version-aware commitment ciphertext.
    #[must_use]
    pub const fn commitment_ciphertext(&self) -> &VersionedCommitmentCiphertext {
        &self.commitment_ciphertext
    }
}

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;

    use super::{
        CommitmentSummary, DecodedCommitmentCiphertextV2, DecodedCommitmentCiphertextV3,
        TxidVersion, V2Transaction, V2TransactionBoundParams, V3Transaction,
        V3TransactionBoundParams, V3TransactionBoundParamsLocal, VersionedTransaction,
    };
    use crate::{
        BlindedViewingPublicKey, CommitmentCiphertextV2, NoteCommitment, V2CiphertextBlock,
        V2CiphertextBundle, V3CiphertextBundle, V3StoredNonce, VersionedCommitmentCiphertext,
    };

    #[test]
    fn txid_versions_remain_distinct() {
        assert_ne!(TxidVersion::V2PoseidonMerkle, TxidVersion::V3PoseidonMerkle);
    }

    #[test]
    fn v2_transaction_preserves_minimal_decoded_fields() {
        let transaction = V2Transaction::new(
            TxidVersion::V2PoseidonMerkle,
            vec![
                NoteCommitment::new(BigUint::from(1_u8))
                    .unwrap_or_else(|error| panic!("commitment should validate: {error}")),
            ],
            V2TransactionBoundParams::new(vec![DecodedCommitmentCiphertextV2::new(
                [[1_u8; 32], [2_u8; 32], [3_u8; 32], [4_u8; 32]],
                [5_u8; 32],
                [6_u8; 32],
                vec![7_u8],
                vec![8_u8],
            )]),
        );

        assert_eq!(transaction.txid_version(), TxidVersion::V2PoseidonMerkle);
        assert_eq!(transaction.commitments().len(), 1);
        assert_eq!(transaction.bound_params().commitment_ciphertext().len(), 1);
    }

    #[test]
    fn v3_transaction_preserves_minimal_decoded_fields() {
        let transaction = V3Transaction::new(
            TxidVersion::V3PoseidonMerkle,
            vec![
                NoteCommitment::new(BigUint::from(1_u8))
                    .unwrap_or_else(|error| panic!("commitment should validate: {error}")),
            ],
            V3TransactionBoundParams::new(V3TransactionBoundParamsLocal::new(vec![
                DecodedCommitmentCiphertextV3::new(vec![9_u8; 17], [10_u8; 32], [11_u8; 32]),
            ])),
        );

        assert_eq!(transaction.txid_version(), TxidVersion::V3PoseidonMerkle);
        assert_eq!(transaction.commitments().len(), 1);
        assert_eq!(transaction.bound_params().local().commitment_ciphertext().len(), 1);
    }

    #[test]
    fn versioned_transaction_exposes_required_txid_version() {
        let transaction = VersionedTransaction::V2(V2Transaction::new(
            TxidVersion::V2PoseidonMerkle,
            Vec::new(),
            V2TransactionBoundParams::new(Vec::new()),
        ));

        assert_eq!(transaction.txid_version(), TxidVersion::V2PoseidonMerkle);
    }

    #[test]
    fn commitment_summary_preserves_hash_and_versioned_ciphertext() {
        let summary = CommitmentSummary::new(
            NoteCommitment::new(BigUint::from(1_u8))
                .unwrap_or_else(|error| panic!("commitment should validate: {error}")),
            VersionedCommitmentCiphertext::V2(CommitmentCiphertextV2::new(
                V2CiphertextBundle::new(
                    V2CiphertextBlock::new([1_u8; 32]),
                    [
                        V2CiphertextBlock::new([2_u8; 32]),
                        V2CiphertextBlock::new([3_u8; 32]),
                        V2CiphertextBlock::new([4_u8; 32]),
                    ],
                    Vec::new(),
                    Vec::new(),
                ),
                BlindedViewingPublicKey::new([5_u8; 32]),
                BlindedViewingPublicKey::new([6_u8; 32]),
            )),
        );

        assert_eq!(summary.commitment_hash().value(), &BigUint::from(1_u8));
        assert!(matches!(summary.commitment_ciphertext(), VersionedCommitmentCiphertext::V2(_)));
    }

    #[test]
    fn v3_decoded_ciphertext_preserves_nonce_prefixed_payload() {
        let decoded = DecodedCommitmentCiphertextV3::new(
            [V3StoredNonce::new([1_u8; 16]).as_bytes().as_slice(), &[2_u8; 3]].concat(),
            [3_u8; 32],
            [4_u8; 32],
        );

        assert_eq!(decoded.ciphertext().len(), 19);
    }

    #[test]
    fn parsed_v3_summary_shape_remains_available() {
        let parsed = VersionedCommitmentCiphertext::V3(crate::CommitmentCiphertextV3::new(
            V3CiphertextBundle::new(V3StoredNonce::new([1_u8; 16]), vec![2_u8; 3], Vec::new()),
            BlindedViewingPublicKey::new([3_u8; 32]),
            BlindedViewingPublicKey::new([4_u8; 32]),
        ));

        assert!(matches!(parsed, VersionedCommitmentCiphertext::V3(_)));
    }
}
