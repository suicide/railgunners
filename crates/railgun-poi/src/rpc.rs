//! Typed POI JSON-RPC payload models and helpers.

use std::{collections::HashMap, str::FromStr};

use num_bigint::BigUint;
use railgun_types::{
    ChainId, ChainType, Groth16Proof, MerkleProofElement, MerkleRoot, RailgunTxid, TxidVersion,
};
use serde::{Deserialize, Serialize};

use crate::{
    BlindedCommitment, PoiError, PoiEventLengths, PoiListKey, PoiListStatus, TransactProofData,
    TxidMerklerootIndex,
};

const JSON_RPC_VERSION: &str = "2.0";

/// Supported POI JSON-RPC methods.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PoiJsonRpcMethod {
    /// Health check method.
    Health,
    /// Node status method.
    NodeStatus,
    /// POI synced events method.
    PoiEvents,
    /// POI merkletree leaves method.
    PoiMerkletreeLeaves,
    /// Transact proofs method.
    TransactProofs,
    /// Merkle proofs method.
    MerkleProofs,
    /// Latest validated txid status method.
    ValidatedTxid,
    /// Txid merkleroot validation method.
    ValidateTxidMerkleroot,
    /// POI merkleroot validation method.
    ValidatePoiMerkleroots,
    /// Submit transact proof method.
    SubmitTransactProof,
}

impl PoiJsonRpcMethod {
    fn as_wire(self) -> &'static str {
        match self {
            Self::Health => "ppoi_health",
            Self::NodeStatus => "ppoi_node_status",
            Self::PoiEvents => "ppoi_poi_events",
            Self::PoiMerkletreeLeaves => "ppoi_poi_merkletree_leaves",
            Self::TransactProofs => "ppoi_transact_proofs",
            Self::MerkleProofs => "ppoi_merkle_proofs",
            Self::ValidatedTxid => "ppoi_validated_txid",
            Self::ValidateTxidMerkleroot => "ppoi_validate_txid_merkleroot",
            Self::ValidatePoiMerkleroots => "ppoi_validate_poi_merkleroots",
            Self::SubmitTransactProof => "ppoi_submit_transact_proof",
        }
    }
}

impl FromStr for PoiJsonRpcMethod {
    type Err = PoiError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "ppoi_health" => Ok(Self::Health),
            "ppoi_node_status" => Ok(Self::NodeStatus),
            "ppoi_poi_events" => Ok(Self::PoiEvents),
            "ppoi_poi_merkletree_leaves" => Ok(Self::PoiMerkletreeLeaves),
            "ppoi_transact_proofs" => Ok(Self::TransactProofs),
            "ppoi_merkle_proofs" => Ok(Self::MerkleProofs),
            "ppoi_validated_txid" => Ok(Self::ValidatedTxid),
            "ppoi_validate_txid_merkleroot" => Ok(Self::ValidateTxidMerkleroot),
            "ppoi_validate_poi_merkleroots" => Ok(Self::ValidatePoiMerkleroots),
            "ppoi_submit_transact_proof" => Ok(Self::SubmitTransactProof),
            unknown => Err(PoiError::UnknownPoiJsonRpcMethod(unknown.to_owned())),
        }
    }
}

/// Shared typed chain params for POI JSON-RPC requests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PoiChainParams {
    chain_type: ChainType,
    chain_id: ChainId,
    txid_version: TxidVersion,
}

impl PoiChainParams {
    /// Creates shared typed chain params.
    #[must_use]
    pub const fn new(chain_type: ChainType, chain_id: ChainId, txid_version: TxidVersion) -> Self {
        Self { chain_type, chain_id, txid_version }
    }

    /// Returns the chain type.
    #[must_use]
    pub const fn chain_type(self) -> ChainType {
        self.chain_type
    }

    /// Returns the chain id.
    #[must_use]
    pub const fn chain_id(self) -> ChainId {
        self.chain_id
    }

    /// Returns the txid version.
    #[must_use]
    pub const fn txid_version(self) -> TxidVersion {
        self.txid_version
    }
}

/// Params for `ppoi_poi_events`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PoiEventsParams {
    chain_params: PoiChainParams,
    list_key: PoiListKey,
    start_index: u64,
    end_index: u64,
}

impl PoiEventsParams {
    /// Creates typed `ppoi_poi_events` params.
    ///
    /// # Errors
    ///
    /// Returns an error if `end_index` is less than `start_index`.
    pub fn new(
        chain_params: PoiChainParams,
        list_key: PoiListKey,
        start_index: u64,
        end_index: u64,
    ) -> Result<Self, PoiError> {
        if end_index < start_index {
            return Err(PoiError::InvalidPoiJsonRpcRequest(
                "ppoi_poi_events endIndex must be greater than or equal to startIndex",
            ));
        }

        Ok(Self { chain_params, list_key, start_index, end_index })
    }

    /// Returns the shared chain params.
    #[must_use]
    pub const fn chain_params(&self) -> PoiChainParams {
        self.chain_params
    }

    /// Returns the typed list key.
    #[must_use]
    pub const fn list_key(&self) -> &PoiListKey {
        &self.list_key
    }

    /// Returns the inclusive start index.
    #[must_use]
    pub const fn start_index(&self) -> u64 {
        self.start_index
    }

    /// Returns the inclusive end index.
    #[must_use]
    pub const fn end_index(&self) -> u64 {
        self.end_index
    }
}

/// Params for `ppoi_poi_merkletree_leaves`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PoiMerkletreeLeavesParams {
    chain_params: PoiChainParams,
    list_key: PoiListKey,
    start_index: u64,
    end_index: u64,
}

impl PoiMerkletreeLeavesParams {
    /// Creates typed `ppoi_poi_merkletree_leaves` params.
    ///
    /// # Errors
    ///
    /// Returns an error if `end_index` is less than `start_index`.
    pub fn new(
        chain_params: PoiChainParams,
        list_key: PoiListKey,
        start_index: u64,
        end_index: u64,
    ) -> Result<Self, PoiError> {
        if end_index < start_index {
            return Err(PoiError::InvalidPoiJsonRpcRequest(
                "ppoi_poi_merkletree_leaves endIndex must be greater than or equal to startIndex",
            ));
        }

        Ok(Self { chain_params, list_key, start_index, end_index })
    }

    /// Returns the shared chain params.
    #[must_use]
    pub const fn chain_params(&self) -> PoiChainParams {
        self.chain_params
    }

    /// Returns the typed list key.
    #[must_use]
    pub const fn list_key(&self) -> &PoiListKey {
        &self.list_key
    }

    /// Returns the inclusive start index.
    #[must_use]
    pub const fn start_index(&self) -> u64 {
        self.start_index
    }

    /// Returns the inclusive end index.
    #[must_use]
    pub const fn end_index(&self) -> u64 {
        self.end_index
    }
}

/// Params for `ppoi_transact_proofs`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PoiTransactProofsParams {
    chain_params: PoiChainParams,
    list_key: PoiListKey,
    bloom_filter_serialized: String,
}

impl PoiTransactProofsParams {
    /// Creates typed `ppoi_transact_proofs` params.
    ///
    /// # Errors
    ///
    /// Returns an error if the bloom filter is empty.
    pub fn new(
        chain_params: PoiChainParams,
        list_key: PoiListKey,
        bloom_filter_serialized: String,
    ) -> Result<Self, PoiError> {
        if bloom_filter_serialized.is_empty() {
            return Err(PoiError::InvalidPoiJsonRpcRequest(
                "ppoi_transact_proofs bloomFilterSerialized must not be empty",
            ));
        }

        Ok(Self { chain_params, list_key, bloom_filter_serialized })
    }

    /// Returns the shared chain params.
    #[must_use]
    pub const fn chain_params(&self) -> PoiChainParams {
        self.chain_params
    }

    /// Returns the typed list key.
    #[must_use]
    pub const fn list_key(&self) -> &PoiListKey {
        &self.list_key
    }

    /// Returns the serialized bloom filter string.
    #[must_use]
    pub fn bloom_filter_serialized(&self) -> &str {
        &self.bloom_filter_serialized
    }
}

/// Params for `ppoi_merkle_proofs`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PoiMerkleProofsParams {
    chain_params: PoiChainParams,
    list_key: PoiListKey,
    blinded_commitments: Vec<BlindedCommitment>,
}

impl PoiMerkleProofsParams {
    /// Creates typed `ppoi_merkle_proofs` params.
    ///
    /// # Errors
    ///
    /// Returns an error if no blinded commitments are provided.
    pub fn new(
        chain_params: PoiChainParams,
        list_key: PoiListKey,
        blinded_commitments: Vec<BlindedCommitment>,
    ) -> Result<Self, PoiError> {
        if blinded_commitments.is_empty() {
            return Err(PoiError::InvalidPoiJsonRpcRequest(
                "ppoi_merkle_proofs blindedCommitments must not be empty",
            ));
        }

        Ok(Self { chain_params, list_key, blinded_commitments })
    }

    /// Returns the shared chain params.
    #[must_use]
    pub const fn chain_params(&self) -> PoiChainParams {
        self.chain_params
    }

    /// Returns the typed list key.
    #[must_use]
    pub const fn list_key(&self) -> &PoiListKey {
        &self.list_key
    }

    /// Returns the requested blinded commitments.
    #[must_use]
    pub fn blinded_commitments(&self) -> &[BlindedCommitment] {
        &self.blinded_commitments
    }
}

/// Params for `ppoi_validate_txid_merkleroot`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PoiValidateTxidMerklerootParams {
    chain_params: PoiChainParams,
    tree: u64,
    index: u64,
    merkleroot: MerkleRoot,
}

impl PoiValidateTxidMerklerootParams {
    /// Creates typed `ppoi_validate_txid_merkleroot` params.
    #[must_use]
    pub const fn new(
        chain_params: PoiChainParams,
        tree: u64,
        index: u64,
        merkleroot: MerkleRoot,
    ) -> Self {
        Self { chain_params, tree, index, merkleroot }
    }

    /// Returns the shared chain params.
    #[must_use]
    pub const fn chain_params(&self) -> PoiChainParams {
        self.chain_params
    }

    /// Returns the txid tree index.
    #[must_use]
    pub const fn tree(&self) -> u64 {
        self.tree
    }

    /// Returns the leaf index.
    #[must_use]
    pub const fn index(&self) -> u64 {
        self.index
    }

    /// Returns the merkleroot.
    #[must_use]
    pub const fn merkleroot(&self) -> &MerkleRoot {
        &self.merkleroot
    }
}

/// Params for `ppoi_validate_poi_merkleroots`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PoiValidatePoiMerklerootsParams {
    chain_params: PoiChainParams,
    list_key: PoiListKey,
    poi_merkleroots: Vec<MerkleRoot>,
}

impl PoiValidatePoiMerklerootsParams {
    /// Creates typed `ppoi_validate_poi_merkleroots` params.
    ///
    /// # Errors
    ///
    /// Returns an error if no POI merkleroots are provided.
    pub fn new(
        chain_params: PoiChainParams,
        list_key: PoiListKey,
        poi_merkleroots: Vec<MerkleRoot>,
    ) -> Result<Self, PoiError> {
        if poi_merkleroots.is_empty() {
            return Err(PoiError::InvalidPoiJsonRpcRequest(
                "ppoi_validate_poi_merkleroots poiMerkleroots must not be empty",
            ));
        }

        Ok(Self { chain_params, list_key, poi_merkleroots })
    }

    /// Returns the shared chain params.
    #[must_use]
    pub const fn chain_params(&self) -> PoiChainParams {
        self.chain_params
    }

    /// Returns the typed list key.
    #[must_use]
    pub const fn list_key(&self) -> &PoiListKey {
        &self.list_key
    }

    /// Returns the POI merkleroots to validate.
    #[must_use]
    pub fn poi_merkleroots(&self) -> &[MerkleRoot] {
        &self.poi_merkleroots
    }
}

/// Params for `ppoi_submit_transact_proof`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PoiSubmitTransactProofParams {
    chain_params: PoiChainParams,
    list_key: PoiListKey,
    transact_proof_data: TransactProofData,
}

impl PoiSubmitTransactProofParams {
    /// Creates typed `ppoi_submit_transact_proof` params.
    #[must_use]
    pub fn new(
        chain_params: PoiChainParams,
        list_key: PoiListKey,
        transact_proof_data: TransactProofData,
    ) -> Self {
        Self { chain_params, list_key, transact_proof_data }
    }

    /// Returns the shared chain params.
    #[must_use]
    pub const fn chain_params(&self) -> PoiChainParams {
        self.chain_params
    }

    /// Returns the typed list key.
    #[must_use]
    pub const fn list_key(&self) -> &PoiListKey {
        &self.list_key
    }

    /// Returns the transact proof payload.
    #[must_use]
    pub const fn transact_proof_data(&self) -> &TransactProofData {
        &self.transact_proof_data
    }
}

/// Opaque POI synced event payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PoiSyncedListEvent(serde_json::Value);

impl PoiSyncedListEvent {
    /// Creates an opaque synced-event wrapper.
    #[must_use]
    pub fn new(value: serde_json::Value) -> Self {
        Self(value)
    }

    /// Returns the raw event JSON value.
    #[must_use]
    pub const fn raw(&self) -> &serde_json::Value {
        &self.0
    }
}

/// Typed health response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PoiHealthResponse {
    status: String,
}

impl PoiHealthResponse {
    /// Creates a typed health response.
    ///
    /// # Errors
    ///
    /// Returns an error if the response string is empty.
    pub fn new(status: String) -> Result<Self, PoiError> {
        if status.is_empty() {
            return Err(PoiError::InvalidPoiJsonRpcResponse(
                "ppoi_health result must not be empty",
            ));
        }

        Ok(Self { status })
    }

    /// Returns the remote health status string.
    #[must_use]
    pub fn status(&self) -> &str {
        &self.status
    }
}

/// Typed txid sync status for one network.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PoiTxidStatus {
    current_txid_index: Option<u64>,
    current_merkleroot: Option<MerkleRoot>,
    validated_txid_index: Option<u64>,
    validated_merkleroot: Option<MerkleRoot>,
}

impl PoiTxidStatus {
    /// Creates typed txid sync status.
    #[must_use]
    pub const fn new(
        current_txid_index: Option<u64>,
        current_merkleroot: Option<MerkleRoot>,
        validated_txid_index: Option<u64>,
        validated_merkleroot: Option<MerkleRoot>,
    ) -> Self {
        Self { current_txid_index, current_merkleroot, validated_txid_index, validated_merkleroot }
    }

    /// Returns the current txid index when available.
    #[must_use]
    pub const fn current_txid_index(&self) -> Option<u64> {
        self.current_txid_index
    }

    /// Returns the current merkleroot when available.
    #[must_use]
    pub const fn current_merkleroot(&self) -> Option<&MerkleRoot> {
        self.current_merkleroot.as_ref()
    }

    /// Returns the latest validated txid index when available.
    #[must_use]
    pub const fn validated_txid_index(&self) -> Option<u64> {
        self.validated_txid_index
    }

    /// Returns the latest validated merkleroot when available.
    #[must_use]
    pub const fn validated_merkleroot(&self) -> Option<&MerkleRoot> {
        self.validated_merkleroot.as_ref()
    }
}

/// Typed shield-queue status for one network.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PoiShieldQueueStatus {
    unknown: u64,
    pending: u64,
    allowed: u64,
    blocked: u64,
    added_poi: u64,
    latest_shield: Option<MerkleRoot>,
}

impl PoiShieldQueueStatus {
    /// Creates typed shield-queue status.
    #[must_use]
    pub const fn new(
        unknown: u64,
        pending: u64,
        allowed: u64,
        blocked: u64,
        added_poi: u64,
        latest_shield: Option<MerkleRoot>,
    ) -> Self {
        Self { unknown, pending, allowed, blocked, added_poi, latest_shield }
    }

    /// Returns the unknown shield count.
    #[must_use]
    pub const fn unknown(&self) -> u64 {
        self.unknown
    }

    /// Returns the pending shield count.
    #[must_use]
    pub const fn pending(&self) -> u64 {
        self.pending
    }

    /// Returns the allowed shield count.
    #[must_use]
    pub const fn allowed(&self) -> u64 {
        self.allowed
    }

    /// Returns the blocked shield count.
    #[must_use]
    pub const fn blocked(&self) -> u64 {
        self.blocked
    }

    /// Returns the added-POI shield count.
    #[must_use]
    pub const fn added_poi(&self) -> u64 {
        self.added_poi
    }

    /// Returns the latest shield hash when available.
    #[must_use]
    pub const fn latest_shield(&self) -> Option<&MerkleRoot> {
        self.latest_shield.as_ref()
    }
}

/// Typed node status for one network.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PoiNodeStatusForNetwork {
    txid_status: PoiTxidStatus,
    shield_queue_status: PoiShieldQueueStatus,
    list_statuses: HashMap<PoiListKey, PoiListStatus>,
    legacy_transact_proofs: u64,
}

impl PoiNodeStatusForNetwork {
    /// Creates typed node status for one network.
    #[must_use]
    pub fn new(
        txid_status: PoiTxidStatus,
        shield_queue_status: PoiShieldQueueStatus,
        list_statuses: HashMap<PoiListKey, PoiListStatus>,
        legacy_transact_proofs: u64,
    ) -> Self {
        Self { txid_status, shield_queue_status, list_statuses, legacy_transact_proofs }
    }

    /// Returns the txid sync status.
    #[must_use]
    pub const fn txid_status(&self) -> &PoiTxidStatus {
        &self.txid_status
    }

    /// Returns the shield queue status.
    #[must_use]
    pub const fn shield_queue_status(&self) -> &PoiShieldQueueStatus {
        &self.shield_queue_status
    }

    /// Returns the typed per-list statuses.
    #[must_use]
    pub fn list_statuses(&self) -> &HashMap<PoiListKey, PoiListStatus> {
        &self.list_statuses
    }

    /// Returns the count of legacy transact proofs.
    #[must_use]
    pub const fn legacy_transact_proofs(&self) -> u64 {
        self.legacy_transact_proofs
    }
}

/// Typed node status response payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PoiNodeStatusResponse {
    list_keys: Vec<PoiListKey>,
    for_network: HashMap<String, PoiNodeStatusForNetwork>,
}

impl PoiNodeStatusResponse {
    /// Creates typed node status response payload.
    #[must_use]
    pub fn new(
        list_keys: Vec<PoiListKey>,
        for_network: HashMap<String, PoiNodeStatusForNetwork>,
    ) -> Self {
        Self { list_keys, for_network }
    }

    /// Returns the configured list keys.
    #[must_use]
    pub fn list_keys(&self) -> &[PoiListKey] {
        &self.list_keys
    }

    /// Returns the per-network statuses keyed by upstream network name.
    #[must_use]
    pub fn for_network(&self) -> &HashMap<String, PoiNodeStatusForNetwork> {
        &self.for_network
    }
}

/// Typed latest validated txid response payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PoiValidatedTxidStatus {
    validated_txid_index: Option<u64>,
    validated_merkleroot: Option<MerkleRoot>,
}

impl PoiValidatedTxidStatus {
    /// Creates typed validated txid status.
    #[must_use]
    pub const fn new(
        validated_txid_index: Option<u64>,
        validated_merkleroot: Option<MerkleRoot>,
    ) -> Self {
        Self { validated_txid_index, validated_merkleroot }
    }

    /// Returns the latest validated txid index when available.
    #[must_use]
    pub const fn validated_txid_index(&self) -> Option<u64> {
        self.validated_txid_index
    }

    /// Returns the latest validated merkleroot when available.
    #[must_use]
    pub const fn validated_merkleroot(&self) -> Option<&MerkleRoot> {
        self.validated_merkleroot.as_ref()
    }
}

/// Typed POI merkle proof payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PoiMerkleProof {
    leaf: BlindedCommitment,
    elements: Vec<MerkleProofElement>,
    indices: String,
    root: MerkleRoot,
}

impl PoiMerkleProof {
    /// Creates a typed POI merkle proof.
    ///
    /// # Errors
    ///
    /// Returns an error if the encoded indices string is empty.
    pub fn new(
        leaf: BlindedCommitment,
        elements: Vec<MerkleProofElement>,
        indices: String,
        root: MerkleRoot,
    ) -> Result<Self, PoiError> {
        if indices.is_empty() {
            return Err(PoiError::InvalidPoiJsonRpcResponse(
                "POI merkle proof indices must not be empty",
            ));
        }

        Ok(Self { leaf, elements, indices, root })
    }

    /// Returns the proof leaf.
    #[must_use]
    pub const fn leaf(&self) -> &BlindedCommitment {
        &self.leaf
    }

    /// Returns the proof path elements.
    #[must_use]
    pub fn elements(&self) -> &[MerkleProofElement] {
        &self.elements
    }

    /// Returns the encoded proof indices string.
    #[must_use]
    pub fn indices(&self) -> &str {
        &self.indices
    }

    /// Returns the proof root.
    #[must_use]
    pub const fn root(&self) -> &MerkleRoot {
        &self.root
    }
}

/// Method-safe POI JSON-RPC request builder input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PoiJsonRpcRequest {
    /// Builds a `ppoi_health` request.
    Health {
        /// JSON-RPC request id.
        id: u64,
    },
    /// Builds a `ppoi_node_status` request.
    NodeStatus {
        /// JSON-RPC request id.
        id: u64,
    },
    /// Builds a `ppoi_poi_events` request.
    PoiEvents {
        /// JSON-RPC request id.
        id: u64,
        /// Method-specific typed params.
        params: Box<PoiEventsParams>,
    },
    /// Builds a `ppoi_poi_merkletree_leaves` request.
    PoiMerkletreeLeaves {
        /// JSON-RPC request id.
        id: u64,
        /// Method-specific typed params.
        params: Box<PoiMerkletreeLeavesParams>,
    },
    /// Builds a `ppoi_transact_proofs` request.
    TransactProofs {
        /// JSON-RPC request id.
        id: u64,
        /// Method-specific typed params.
        params: Box<PoiTransactProofsParams>,
    },
    /// Builds a `ppoi_merkle_proofs` request.
    MerkleProofs {
        /// JSON-RPC request id.
        id: u64,
        /// Method-specific typed params.
        params: Box<PoiMerkleProofsParams>,
    },
    /// Builds a `ppoi_validated_txid` request.
    ValidatedTxid {
        /// JSON-RPC request id.
        id: u64,
        /// Method-specific typed params.
        params: PoiChainParams,
    },
    /// Builds a `ppoi_validate_txid_merkleroot` request.
    ValidateTxidMerkleroot {
        /// JSON-RPC request id.
        id: u64,
        /// Method-specific typed params.
        params: Box<PoiValidateTxidMerklerootParams>,
    },
    /// Builds a `ppoi_validate_poi_merkleroots` request.
    ValidatePoiMerkleroots {
        /// JSON-RPC request id.
        id: u64,
        /// Method-specific typed params.
        params: Box<PoiValidatePoiMerklerootsParams>,
    },
    /// Builds a `ppoi_submit_transact_proof` request.
    SubmitTransactProof {
        /// JSON-RPC request id.
        id: u64,
        /// Method-specific typed params.
        params: Box<PoiSubmitTransactProofParams>,
    },
}

impl PoiJsonRpcRequest {
    /// Returns the request method.
    #[must_use]
    pub const fn method(&self) -> PoiJsonRpcMethod {
        match self {
            Self::Health { .. } => PoiJsonRpcMethod::Health,
            Self::NodeStatus { .. } => PoiJsonRpcMethod::NodeStatus,
            Self::PoiEvents { .. } => PoiJsonRpcMethod::PoiEvents,
            Self::PoiMerkletreeLeaves { .. } => PoiJsonRpcMethod::PoiMerkletreeLeaves,
            Self::TransactProofs { .. } => PoiJsonRpcMethod::TransactProofs,
            Self::MerkleProofs { .. } => PoiJsonRpcMethod::MerkleProofs,
            Self::ValidatedTxid { .. } => PoiJsonRpcMethod::ValidatedTxid,
            Self::ValidateTxidMerkleroot { .. } => PoiJsonRpcMethod::ValidateTxidMerkleroot,
            Self::ValidatePoiMerkleroots { .. } => PoiJsonRpcMethod::ValidatePoiMerkleroots,
            Self::SubmitTransactProof { .. } => PoiJsonRpcMethod::SubmitTransactProof,
        }
    }

    /// Returns the JSON-RPC id.
    #[must_use]
    pub const fn id(&self) -> u64 {
        match self {
            Self::Health { id }
            | Self::NodeStatus { id }
            | Self::PoiEvents { id, .. }
            | Self::PoiMerkletreeLeaves { id, .. }
            | Self::TransactProofs { id, .. }
            | Self::MerkleProofs { id, .. }
            | Self::ValidatedTxid { id, .. }
            | Self::ValidateTxidMerkleroot { id, .. }
            | Self::ValidatePoiMerkleroots { id, .. }
            | Self::SubmitTransactProof { id, .. } => *id,
        }
    }
}

#[derive(Debug, Serialize)]
struct JsonRpcRequestWire<T> {
    jsonrpc: &'static str,
    method: &'static str,
    params: T,
    id: u64,
}

#[derive(Debug, Deserialize)]
struct JsonRpcResponseWire<T> {
    jsonrpc: String,
    result: Option<T>,
    error: Option<JsonRpcErrorWire>,
}

#[derive(Debug, Deserialize)]
struct JsonRpcErrorWire {
    code: i64,
    message: String,
}

#[derive(Debug, Serialize)]
struct ChainParamsWire {
    #[serde(rename = "chainType")]
    chain_type: String,
    #[serde(rename = "chainID")]
    chain_id: String,
    #[serde(rename = "txidVersion")]
    txid_version: &'static str,
}

#[derive(Debug, Serialize)]
struct PoiEventsParamsWire {
    #[serde(flatten)]
    chain: ChainParamsWire,
    #[serde(rename = "listKey")]
    list_key: String,
    #[serde(rename = "startIndex")]
    start_index: u64,
    #[serde(rename = "endIndex")]
    end_index: u64,
}

#[derive(Debug, Serialize)]
struct PoiMerkletreeLeavesParamsWire {
    #[serde(flatten)]
    chain: ChainParamsWire,
    #[serde(rename = "listKey")]
    list_key: String,
    #[serde(rename = "startIndex")]
    start_index: u64,
    #[serde(rename = "endIndex")]
    end_index: u64,
}

#[derive(Debug, Serialize)]
struct PoiTransactProofsParamsWire {
    #[serde(flatten)]
    chain: ChainParamsWire,
    #[serde(rename = "listKey")]
    list_key: String,
    #[serde(rename = "bloomFilterSerialized")]
    bloom_filter_serialized: String,
}

#[derive(Debug, Serialize)]
struct PoiMerkleProofsParamsWire {
    #[serde(flatten)]
    chain: ChainParamsWire,
    #[serde(rename = "listKey")]
    list_key: String,
    #[serde(rename = "blindedCommitments")]
    blinded_commitments: Vec<String>,
}

#[derive(Debug, Serialize)]
struct PoiValidateTxidMerklerootParamsWire {
    #[serde(flatten)]
    chain: ChainParamsWire,
    tree: u64,
    index: u64,
    merkleroot: String,
}

#[derive(Debug, Serialize)]
struct PoiValidatePoiMerklerootsParamsWire {
    #[serde(flatten)]
    chain: ChainParamsWire,
    #[serde(rename = "listKey")]
    list_key: String,
    #[serde(rename = "poiMerkleroots")]
    poi_merkleroots: Vec<String>,
}

#[derive(Debug, Serialize)]
struct PoiSubmitTransactProofParamsWire {
    #[serde(flatten)]
    chain: ChainParamsWire,
    #[serde(rename = "listKey")]
    list_key: String,
    #[serde(rename = "transactProofData")]
    transact_proof_data: TransactProofDataWire,
}

#[allow(clippy::struct_field_names)]
#[derive(Clone, Debug, Deserialize, Serialize)]
struct Groth16ProofWire {
    pi_a: [String; 2],
    pi_b: [[String; 2]; 2],
    pi_c: [String; 2],
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct TransactProofDataWire {
    #[serde(rename = "snarkProof")]
    snark_proof: Groth16ProofWire,
    #[serde(rename = "poiMerkleroots")]
    poi_merkleroots: Vec<String>,
    #[serde(rename = "txidMerkleroot")]
    txid_merkleroot: String,
    #[serde(rename = "txidMerklerootIndex")]
    txid_merkleroot_index: u64,
    #[serde(rename = "blindedCommitmentsOut")]
    blinded_commitments_out: Vec<String>,
    #[serde(rename = "railgunTxidIfHasUnshield")]
    railgun_txid_if_has_unshield: String,
}

#[derive(Debug, Deserialize)]
struct PoiNodeStatusResponseWire {
    #[serde(rename = "listKeys")]
    list_keys: Vec<String>,
    #[serde(rename = "forNetwork")]
    for_network: HashMap<String, PoiNodeStatusForNetworkWire>,
}

#[derive(Debug, Deserialize)]
struct PoiNodeStatusForNetworkWire {
    #[serde(rename = "txidStatus")]
    txid_status: PoiTxidStatusWire,
    #[serde(rename = "shieldQueueStatus")]
    shield_queue_status: PoiShieldQueueStatusWire,
    #[serde(rename = "listStatuses")]
    list_statuses: HashMap<String, PoiListStatusWire>,
    #[serde(rename = "legacyTransactProofs")]
    legacy_transact_proofs: u64,
}

#[derive(Debug, Deserialize)]
struct PoiTxidStatusWire {
    #[serde(rename = "currentTxidIndex")]
    current_txid_index: Option<u64>,
    #[serde(rename = "currentMerkleroot")]
    current_merkleroot: Option<String>,
    #[serde(rename = "validatedTxidIndex")]
    validated_txid_index: Option<u64>,
    #[serde(rename = "validatedMerkleroot")]
    validated_merkleroot: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PoiShieldQueueStatusWire {
    unknown: u64,
    pending: u64,
    allowed: u64,
    blocked: u64,
    #[serde(rename = "addedPOI")]
    added_poi: u64,
    #[serde(rename = "latestShield")]
    latest_shield: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PoiListStatusWire {
    #[serde(rename = "poiEventLengths")]
    poi_event_lengths: PoiEventLengthsWire,
    #[serde(rename = "listProviderPOIEventQueueLength")]
    list_provider_poi_event_queue_length: Option<u64>,
    #[serde(rename = "pendingTransactProofs")]
    pending_transact_proofs: u64,
    #[serde(rename = "blockedShields")]
    blocked_shields: u64,
    #[serde(rename = "historicalMerklerootsLength")]
    historical_merkleroots_length: u64,
    #[serde(rename = "latestHistoricalMerkleroot")]
    latest_historical_merkleroot: String,
}

#[derive(Debug, Deserialize)]
struct PoiEventLengthsWire {
    #[serde(rename = "Shield")]
    shield: u64,
    #[serde(rename = "Transact")]
    transact: u64,
    #[serde(rename = "Unshield")]
    unshield: u64,
    #[serde(rename = "LegacyTransact")]
    legacy_transact: u64,
}

#[derive(Debug, Deserialize)]
struct PoiValidatedTxidStatusWire {
    #[serde(rename = "validatedTxidIndex")]
    validated_txid_index: Option<u64>,
    #[serde(rename = "validatedMerkleroot")]
    validated_merkleroot: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PoiMerkleProofWire {
    leaf: String,
    elements: Vec<String>,
    indices: String,
    root: String,
}

fn serialize_txid_version(value: TxidVersion) -> &'static str {
    match value {
        TxidVersion::V2PoseidonMerkle => "V2_PoseidonMerkle",
        TxidVersion::V3PoseidonMerkle => "V3_PoseidonMerkle",
    }
}

fn encode_bytes_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn parse_root(value: &str) -> Result<MerkleRoot, PoiError> {
    let bytes = decode_fixed_hex::<32>(value, "POI merkleroot must be exactly 32 bytes of hex")?;
    MerkleRoot::from_slice(&bytes).map_err(|_| {
        PoiError::InvalidPoiJsonRpcResponse("POI merkleroot must be exactly 32 bytes of hex")
    })
}

fn parse_proof_element(value: &str) -> Result<MerkleProofElement, PoiError> {
    let bytes =
        decode_fixed_hex::<32>(value, "POI merkle proof element must be exactly 32 bytes of hex")?;
    MerkleProofElement::from_slice(&bytes).map_err(|_| {
        PoiError::InvalidPoiJsonRpcResponse(
            "POI merkle proof element must be exactly 32 bytes of hex",
        )
    })
}

fn parse_list_key_response(value: &str) -> Result<PoiListKey, PoiError> {
    PoiListKey::parse(value).map_err(|_| {
        PoiError::InvalidPoiJsonRpcResponse(
            "POI list key must be canonical 32-byte hex in JSON-RPC response",
        )
    })
}

fn parse_blinded_commitment_response(value: &str) -> Result<BlindedCommitment, PoiError> {
    BlindedCommitment::parse(value).map_err(|_| {
        PoiError::InvalidPoiJsonRpcResponse(
            "blinded commitment must be canonical 32-byte field hex in JSON-RPC response",
        )
    })
}

fn parse_railgun_txid_response(value: &str) -> Result<RailgunTxid, PoiError> {
    let bytes = decode_fixed_hex::<32>(
        value,
        "railgun txid must be exactly 32 bytes of hex in JSON-RPC response",
    )?;
    RailgunTxid::new(BigUint::from_bytes_be(&bytes)).map_err(|_| {
        PoiError::InvalidPoiJsonRpcResponse(
            "railgun txid must be canonical 32-byte field hex in JSON-RPC response",
        )
    })
}

fn encode_field_hex(value: &BigUint) -> String {
    let bytes = value.to_bytes_be();
    let mut padded = [0_u8; 32];
    let start = 32 - bytes.len();
    padded[start..].copy_from_slice(&bytes);
    encode_bytes_hex(&padded)
}

fn decode_fixed_hex<const N: usize>(
    value: &str,
    message: &'static str,
) -> Result<[u8; N], PoiError> {
    let trimmed = value.strip_prefix("0x").unwrap_or(value);
    let bytes = hex::decode(trimmed).map_err(|_| PoiError::InvalidHexEncoding(message))?;
    bytes.try_into().map_err(|_| PoiError::InvalidHexEncoding(message))
}

impl From<PoiChainParams> for ChainParamsWire {
    fn from(value: PoiChainParams) -> Self {
        Self {
            chain_type: value.chain_type().get().to_string(),
            chain_id: value.chain_id().get().to_string(),
            txid_version: serialize_txid_version(value.txid_version()),
        }
    }
}

impl From<&TransactProofData> for TransactProofDataWire {
    fn from(value: &TransactProofData) -> Self {
        Self {
            snark_proof: Groth16ProofWire {
                pi_a: value.snark_proof().pi_a().clone(),
                pi_b: value.snark_proof().pi_b().clone(),
                pi_c: value.snark_proof().pi_c().clone(),
            },
            poi_merkleroots: value
                .poi_merkleroots()
                .iter()
                .map(|root| encode_bytes_hex(root.as_bytes()))
                .collect(),
            txid_merkleroot: encode_bytes_hex(value.txid_merkleroot().as_bytes()),
            txid_merkleroot_index: value.txid_merkleroot_index().get(),
            blinded_commitments_out: value
                .blinded_commitments_out()
                .iter()
                .map(|commitment| encode_field_hex(commitment.value()))
                .collect(),
            railgun_txid_if_has_unshield: encode_field_hex(
                value.railgun_txid_if_has_unshield().value(),
            ),
        }
    }
}

impl TryFrom<TransactProofDataWire> for TransactProofData {
    type Error = PoiError;

    fn try_from(value: TransactProofDataWire) -> Result<Self, Self::Error> {
        let poi_merkleroots = value
            .poi_merkleroots
            .iter()
            .map(|root| parse_root(root))
            .collect::<Result<Vec<_>, _>>()?;
        let blinded_commitments_out = value
            .blinded_commitments_out
            .iter()
            .map(|commitment| parse_blinded_commitment_response(commitment))
            .collect::<Result<Vec<_>, _>>()?;

        TransactProofData::new(
            Groth16Proof::new(
                value.snark_proof.pi_a,
                value.snark_proof.pi_b,
                value.snark_proof.pi_c,
            ),
            poi_merkleroots,
            parse_root(&value.txid_merkleroot)?,
            TxidMerklerootIndex::new(value.txid_merkleroot_index),
            blinded_commitments_out,
            parse_railgun_txid_response(&value.railgun_txid_if_has_unshield)?,
        )
    }
}

impl TryFrom<PoiListStatusWire> for PoiListStatus {
    type Error = PoiError;

    fn try_from(value: PoiListStatusWire) -> Result<Self, Self::Error> {
        Ok(Self::new(
            PoiEventLengths::new(
                value.poi_event_lengths.shield,
                value.poi_event_lengths.transact,
                value.poi_event_lengths.unshield,
                value.poi_event_lengths.legacy_transact,
            ),
            value.list_provider_poi_event_queue_length,
            value.pending_transact_proofs,
            value.blocked_shields,
            value.historical_merkleroots_length,
            parse_root(&value.latest_historical_merkleroot)?,
        ))
    }
}

impl TryFrom<PoiNodeStatusForNetworkWire> for PoiNodeStatusForNetwork {
    type Error = PoiError;

    fn try_from(value: PoiNodeStatusForNetworkWire) -> Result<Self, Self::Error> {
        let list_statuses = value
            .list_statuses
            .into_iter()
            .map(|(key, status)| Ok((parse_list_key_response(&key)?, status.try_into()?)))
            .collect::<Result<HashMap<_, _>, PoiError>>()?;

        Ok(Self::new(
            PoiTxidStatus::new(
                value.txid_status.current_txid_index,
                value.txid_status.current_merkleroot.as_deref().map(parse_root).transpose()?,
                value.txid_status.validated_txid_index,
                value.txid_status.validated_merkleroot.as_deref().map(parse_root).transpose()?,
            ),
            PoiShieldQueueStatus::new(
                value.shield_queue_status.unknown,
                value.shield_queue_status.pending,
                value.shield_queue_status.allowed,
                value.shield_queue_status.blocked,
                value.shield_queue_status.added_poi,
                value.shield_queue_status.latest_shield.as_deref().map(parse_root).transpose()?,
            ),
            list_statuses,
            value.legacy_transact_proofs,
        ))
    }
}

impl TryFrom<PoiNodeStatusResponseWire> for PoiNodeStatusResponse {
    type Error = PoiError;

    fn try_from(value: PoiNodeStatusResponseWire) -> Result<Self, Self::Error> {
        let list_keys = value
            .list_keys
            .iter()
            .map(|key| parse_list_key_response(key))
            .collect::<Result<Vec<_>, _>>()?;
        let for_network = value
            .for_network
            .into_iter()
            .map(|(name, status)| Ok((name, status.try_into()?)))
            .collect::<Result<HashMap<_, _>, PoiError>>()?;

        Ok(Self::new(list_keys, for_network))
    }
}

impl TryFrom<PoiValidatedTxidStatusWire> for PoiValidatedTxidStatus {
    type Error = PoiError;

    fn try_from(value: PoiValidatedTxidStatusWire) -> Result<Self, Self::Error> {
        Ok(Self::new(
            value.validated_txid_index,
            value.validated_merkleroot.as_deref().map(parse_root).transpose()?,
        ))
    }
}

impl TryFrom<PoiMerkleProofWire> for PoiMerkleProof {
    type Error = PoiError;

    fn try_from(value: PoiMerkleProofWire) -> Result<Self, Self::Error> {
        let elements = value
            .elements
            .iter()
            .map(|element| parse_proof_element(element))
            .collect::<Result<Vec<_>, _>>()?;

        Self::new(
            parse_blinded_commitment_response(&value.leaf)?,
            elements,
            value.indices,
            parse_root(&value.root)?,
        )
    }
}

fn serialize_request<T: Serialize>(
    method: PoiJsonRpcMethod,
    params: T,
    id: u64,
) -> Result<String, PoiError> {
    serde_json::to_string(&JsonRpcRequestWire {
        jsonrpc: JSON_RPC_VERSION,
        method: method.as_wire(),
        params,
        id,
    })
    .map_err(|_| PoiError::InvalidPoiJsonRpcRequestJson)
}

fn parse_response_result<T: for<'de> Deserialize<'de>>(payload: &str) -> Result<T, PoiError> {
    let response: JsonRpcResponseWire<T> =
        serde_json::from_str(payload).map_err(|_| PoiError::InvalidPoiJsonRpcResponseJson)?;
    if response.jsonrpc != JSON_RPC_VERSION {
        return Err(PoiError::InvalidPoiJsonRpcResponse(
            "POI JSON-RPC response must declare jsonrpc version 2.0",
        ));
    }
    if let Some(error) = response.error {
        return Err(PoiError::PoiJsonRpcRemoteError { code: error.code, message: error.message });
    }
    response.result.ok_or(PoiError::InvalidPoiJsonRpcResponse(
        "POI JSON-RPC response must contain a result when no error is present",
    ))
}

/// Serializes a method-safe typed POI JSON-RPC request into canonical JSON.
///
/// # Errors
///
/// Returns an error if request serialization fails unexpectedly.
pub fn serialize_poi_json_rpc_request(payload: &PoiJsonRpcRequest) -> Result<String, PoiError> {
    match payload {
        PoiJsonRpcRequest::Health { id } => {
            serialize_request(PoiJsonRpcMethod::Health, [(); 0], *id)
        }
        PoiJsonRpcRequest::NodeStatus { id } => {
            serialize_request(PoiJsonRpcMethod::NodeStatus, serde_json::json!({}), *id)
        }
        PoiJsonRpcRequest::PoiEvents { id, params } => serialize_request(
            PoiJsonRpcMethod::PoiEvents,
            PoiEventsParamsWire {
                chain: params.chain_params().into(),
                list_key: params.list_key().to_string(),
                start_index: params.start_index(),
                end_index: params.end_index(),
            },
            *id,
        ),
        PoiJsonRpcRequest::PoiMerkletreeLeaves { id, params } => serialize_request(
            PoiJsonRpcMethod::PoiMerkletreeLeaves,
            PoiMerkletreeLeavesParamsWire {
                chain: params.chain_params().into(),
                list_key: params.list_key().to_string(),
                start_index: params.start_index(),
                end_index: params.end_index(),
            },
            *id,
        ),
        PoiJsonRpcRequest::TransactProofs { id, params } => serialize_request(
            PoiJsonRpcMethod::TransactProofs,
            PoiTransactProofsParamsWire {
                chain: params.chain_params().into(),
                list_key: params.list_key().to_string(),
                bloom_filter_serialized: params.bloom_filter_serialized().to_owned(),
            },
            *id,
        ),
        PoiJsonRpcRequest::MerkleProofs { id, params } => serialize_request(
            PoiJsonRpcMethod::MerkleProofs,
            PoiMerkleProofsParamsWire {
                chain: params.chain_params().into(),
                list_key: params.list_key().to_string(),
                blinded_commitments: params
                    .blinded_commitments()
                    .iter()
                    .map(|commitment| encode_field_hex(commitment.value()))
                    .collect(),
            },
            *id,
        ),
        PoiJsonRpcRequest::ValidatedTxid { id, params } => {
            serialize_request(PoiJsonRpcMethod::ValidatedTxid, ChainParamsWire::from(*params), *id)
        }
        PoiJsonRpcRequest::ValidateTxidMerkleroot { id, params } => serialize_request(
            PoiJsonRpcMethod::ValidateTxidMerkleroot,
            PoiValidateTxidMerklerootParamsWire {
                chain: params.chain_params().into(),
                tree: params.tree(),
                index: params.index(),
                merkleroot: encode_bytes_hex(params.merkleroot().as_bytes()),
            },
            *id,
        ),
        PoiJsonRpcRequest::ValidatePoiMerkleroots { id, params } => serialize_request(
            PoiJsonRpcMethod::ValidatePoiMerkleroots,
            PoiValidatePoiMerklerootsParamsWire {
                chain: params.chain_params().into(),
                list_key: params.list_key().to_string(),
                poi_merkleroots: params
                    .poi_merkleroots()
                    .iter()
                    .map(|root| encode_bytes_hex(root.as_bytes()))
                    .collect(),
            },
            *id,
        ),
        PoiJsonRpcRequest::SubmitTransactProof { id, params } => serialize_request(
            PoiJsonRpcMethod::SubmitTransactProof,
            PoiSubmitTransactProofParamsWire {
                chain: params.chain_params().into(),
                list_key: params.list_key().to_string(),
                transact_proof_data: params.transact_proof_data().into(),
            },
            *id,
        ),
    }
}

/// Parses a canonical POI JSON-RPC health response.
///
/// # Errors
///
/// Returns an error if the JSON-RPC response is malformed.
pub fn parse_poi_health_response_payload(payload: &str) -> Result<PoiHealthResponse, PoiError> {
    PoiHealthResponse::new(parse_response_result::<String>(payload)?)
}

/// Parses a canonical POI JSON-RPC node status response.
///
/// # Errors
///
/// Returns an error if the JSON-RPC response is malformed.
pub fn parse_poi_node_status_response_payload(
    payload: &str,
) -> Result<PoiNodeStatusResponse, PoiError> {
    parse_response_result::<PoiNodeStatusResponseWire>(payload)?.try_into()
}

/// Parses a canonical POI JSON-RPC events response.
///
/// # Errors
///
/// Returns an error if the JSON-RPC response is malformed.
pub fn parse_poi_events_response_payload(
    payload: &str,
) -> Result<Vec<PoiSyncedListEvent>, PoiError> {
    Ok(parse_response_result::<Vec<serde_json::Value>>(payload)?
        .into_iter()
        .map(PoiSyncedListEvent::new)
        .collect())
}

/// Parses a canonical POI JSON-RPC merkletree leaves response.
///
/// # Errors
///
/// Returns an error if the JSON-RPC response is malformed.
pub fn parse_poi_merkletree_leaves_response_payload(
    payload: &str,
) -> Result<Vec<MerkleRoot>, PoiError> {
    parse_response_result::<Vec<String>>(payload)?.iter().map(|leaf| parse_root(leaf)).collect()
}

/// Parses a canonical POI JSON-RPC transact proofs response.
///
/// # Errors
///
/// Returns an error if the JSON-RPC response is malformed.
pub fn parse_poi_transact_proofs_response_payload(
    payload: &str,
) -> Result<Vec<TransactProofData>, PoiError> {
    parse_response_result::<Vec<TransactProofDataWire>>(payload)?
        .into_iter()
        .map(TryInto::try_into)
        .collect()
}

/// Parses a canonical POI JSON-RPC merkle proofs response.
///
/// # Errors
///
/// Returns an error if the JSON-RPC response is malformed.
pub fn parse_poi_merkle_proofs_response_payload(
    payload: &str,
) -> Result<Vec<PoiMerkleProof>, PoiError> {
    parse_response_result::<Vec<PoiMerkleProofWire>>(payload)?
        .into_iter()
        .map(TryInto::try_into)
        .collect()
}

/// Parses a canonical POI JSON-RPC latest validated txid response.
///
/// # Errors
///
/// Returns an error if the JSON-RPC response is malformed.
pub fn parse_poi_validated_txid_response_payload(
    payload: &str,
) -> Result<PoiValidatedTxidStatus, PoiError> {
    parse_response_result::<PoiValidatedTxidStatusWire>(payload)?.try_into()
}

/// Parses a canonical POI JSON-RPC boolean validation response.
///
/// # Errors
///
/// Returns an error if the JSON-RPC response is malformed.
pub fn parse_poi_validation_response_payload(payload: &str) -> Result<bool, PoiError> {
    parse_response_result(payload)
}

/// Parses a canonical POI JSON-RPC success response for proof submission.
///
/// # Errors
///
/// Returns an error if the JSON-RPC response is malformed.
pub fn parse_poi_submit_transact_proof_response_payload(payload: &str) -> Result<(), PoiError> {
    let response: JsonRpcResponseWire<serde_json::Value> =
        serde_json::from_str(payload).map_err(|_| PoiError::InvalidPoiJsonRpcResponseJson)?;
    if response.jsonrpc != JSON_RPC_VERSION {
        return Err(PoiError::InvalidPoiJsonRpcResponse(
            "POI JSON-RPC response must declare jsonrpc version 2.0",
        ));
    }
    if let Some(error) = response.error {
        return Err(PoiError::PoiJsonRpcRemoteError { code: error.code, message: error.message });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;
    use railgun_types::{
        ChainId, ChainType, Groth16Proof, MerkleNodeHash, MerkleRoot, RailgunTxid, TxidVersion,
    };

    use super::{
        PoiChainParams, PoiError, PoiEventsParams, PoiJsonRpcMethod, PoiJsonRpcRequest,
        PoiMerkleProofsParams, PoiSubmitTransactProofParams, PoiTransactProofsParams,
        PoiValidatePoiMerklerootsParams, PoiValidateTxidMerklerootParams,
        parse_poi_health_response_payload, parse_poi_merkle_proofs_response_payload,
        parse_poi_node_status_response_payload, parse_poi_submit_transact_proof_response_payload,
        parse_poi_transact_proofs_response_payload, parse_poi_validated_txid_response_payload,
        parse_poi_validation_response_payload, serialize_poi_json_rpc_request,
    };
    use crate::{BlindedCommitment, PoiListKey, TransactProofData, TxidMerklerootIndex};

    fn chain_params() -> PoiChainParams {
        PoiChainParams::new(
            ChainType::new(0),
            ChainId::new(1)
                .unwrap_or_else(|error| panic!("test chain id should validate: {error}")),
            TxidVersion::V2PoseidonMerkle,
        )
    }

    fn list_key() -> PoiListKey {
        PoiListKey::parse("efc6ddb59c098a13fb2b618fdae94c1c3a807abc8fb1837c93620c9143ee9e88")
            .unwrap_or_else(|error| panic!("test list key should parse: {error}"))
    }

    fn root(byte: u8) -> MerkleRoot {
        MerkleRoot::new([byte; 32])
    }

    fn blinded(byte: u8) -> BlindedCommitment {
        BlindedCommitment::new(BigUint::from(byte))
            .unwrap_or_else(|error| panic!("test blinded commitment should validate: {error}"))
    }

    fn txid(byte: u8) -> RailgunTxid {
        RailgunTxid::new(BigUint::from(byte))
            .unwrap_or_else(|error| panic!("test txid should validate: {error}"))
    }

    fn transact_proof_data() -> TransactProofData {
        TransactProofData::new(
            Groth16Proof::new(
                ["a0".to_owned(), "a1".to_owned()],
                [["b00".to_owned(), "b01".to_owned()], ["b10".to_owned(), "b11".to_owned()]],
                ["c0".to_owned(), "c1".to_owned()],
            ),
            vec![root(2), root(3)],
            root(4),
            TxidMerklerootIndex::new(9),
            vec![blinded(7)],
            txid(11),
        )
        .unwrap_or_else(|error| panic!("test transact proof data should construct: {error}"))
    }

    #[test]
    fn method_parser_accepts_supported_values() {
        assert_eq!("ppoi_health".parse::<PoiJsonRpcMethod>(), Ok(PoiJsonRpcMethod::Health));
        assert_eq!(
            "ppoi_merkle_proofs".parse::<PoiJsonRpcMethod>(),
            Ok(PoiJsonRpcMethod::MerkleProofs)
        );
    }

    #[test]
    fn method_parser_rejects_unknown_values() {
        assert_eq!(
            "ppoi_unknown".parse::<PoiJsonRpcMethod>(),
            Err(PoiError::UnknownPoiJsonRpcMethod("ppoi_unknown".to_owned()))
        );
    }

    #[test]
    fn chain_params_serialize_with_canonical_string_fields() {
        let payload = serialize_poi_json_rpc_request(&PoiJsonRpcRequest::ValidatedTxid {
            id: 7,
            params: chain_params(),
        })
        .unwrap_or_else(|error| panic!("validated txid request should serialize: {error}"));

        assert_eq!(
            payload,
            r#"{"jsonrpc":"2.0","method":"ppoi_validated_txid","params":{"chainType":"0","chainID":"1","txidVersion":"V2_PoseidonMerkle"},"id":7}"#
        );
    }

    #[test]
    fn validate_txid_merkleroot_request_matches_canonical_shape() {
        let payload = serialize_poi_json_rpc_request(&PoiJsonRpcRequest::ValidateTxidMerkleroot {
            id: 9,
            params: Box::new(PoiValidateTxidMerklerootParams::new(chain_params(), 3, 4, root(5))),
        })
        .unwrap_or_else(|error| {
            panic!("validate txid merkleroot request should serialize: {error}")
        });

        assert_eq!(
            payload,
            r#"{"jsonrpc":"2.0","method":"ppoi_validate_txid_merkleroot","params":{"chainType":"0","chainID":"1","txidVersion":"V2_PoseidonMerkle","tree":3,"index":4,"merkleroot":"0x0505050505050505050505050505050505050505050505050505050505050505"},"id":9}"#
        );
    }

    #[test]
    fn submit_transact_proof_request_nests_transact_proof_data() {
        let payload = serialize_poi_json_rpc_request(&PoiJsonRpcRequest::SubmitTransactProof {
            id: 11,
            params: Box::new(PoiSubmitTransactProofParams::new(
                chain_params(),
                list_key(),
                transact_proof_data(),
            )),
        })
        .unwrap_or_else(|error| panic!("submit transact proof request should serialize: {error}"));

        assert!(payload.contains(r#""method":"ppoi_submit_transact_proof""#));
        assert!(payload.contains(
            r#""listKey":"efc6ddb59c098a13fb2b618fdae94c1c3a807abc8fb1837c93620c9143ee9e88""#
        ));
        assert!(payload.contains(r#""transactProofData":{"snarkProof""#));
    }

    #[test]
    fn transact_proofs_request_requires_non_empty_bloom_filter() {
        let Err(error) = PoiTransactProofsParams::new(chain_params(), list_key(), String::new())
        else {
            panic!("empty bloom filter should fail");
        };

        assert_eq!(
            error,
            PoiError::InvalidPoiJsonRpcRequest(
                "ppoi_transact_proofs bloomFilterSerialized must not be empty"
            )
        );
    }

    #[test]
    fn merkle_proofs_request_requires_blinded_commitments() {
        let Err(error) = PoiMerkleProofsParams::new(chain_params(), list_key(), Vec::new()) else {
            panic!("empty blinded commitments should fail");
        };

        assert_eq!(
            error,
            PoiError::InvalidPoiJsonRpcRequest(
                "ppoi_merkle_proofs blindedCommitments must not be empty"
            )
        );
    }

    #[test]
    fn poi_events_request_rejects_reverse_range() {
        let Err(error) = PoiEventsParams::new(chain_params(), list_key(), 5, 4) else {
            panic!("reverse range should fail");
        };

        assert_eq!(
            error,
            PoiError::InvalidPoiJsonRpcRequest(
                "ppoi_poi_events endIndex must be greater than or equal to startIndex"
            )
        );
    }

    #[test]
    fn parses_health_response() {
        let response =
            parse_poi_health_response_payload(r#"{"jsonrpc":"2.0","result":"ok","id":1}"#)
                .unwrap_or_else(|error| panic!("health response should parse: {error}"));

        assert_eq!(response.status(), "ok");
    }

    #[test]
    fn parses_validated_txid_response() {
        let response = parse_poi_validated_txid_response_payload(
            r#"{"jsonrpc":"2.0","result":{"validatedTxidIndex":42,"validatedMerkleroot":"0x0909090909090909090909090909090909090909090909090909090909090909"},"id":1}"#,
        )
        .unwrap_or_else(|error| panic!("validated txid response should parse: {error}"));

        assert_eq!(response.validated_txid_index(), Some(42));
        assert_eq!(response.validated_merkleroot(), Some(&root(9)));
    }

    #[test]
    fn parses_node_status_response() {
        let response = parse_poi_node_status_response_payload(
            r#"{"jsonrpc":"2.0","result":{"listKeys":["efc6ddb59c098a13fb2b618fdae94c1c3a807abc8fb1837c93620c9143ee9e88"],"forNetwork":{"Ethereum":{"txidStatus":{"currentTxidIndex":10,"currentMerkleroot":"0x0101010101010101010101010101010101010101010101010101010101010101","validatedTxidIndex":9,"validatedMerkleroot":"0x0202020202020202020202020202020202020202020202020202020202020202"},"shieldQueueStatus":{"unknown":1,"pending":2,"allowed":3,"blocked":4,"addedPOI":5,"latestShield":"0x0303030303030303030303030303030303030303030303030303030303030303"},"listStatuses":{"efc6ddb59c098a13fb2b618fdae94c1c3a807abc8fb1837c93620c9143ee9e88":{"poiEventLengths":{"Shield":1,"Transact":2,"Unshield":3,"LegacyTransact":4},"listProviderPOIEventQueueLength":5,"pendingTransactProofs":6,"blockedShields":7,"historicalMerklerootsLength":8,"latestHistoricalMerkleroot":"0x0404040404040404040404040404040404040404040404040404040404040404"}},"legacyTransactProofs":11}}},"id":1}"#,
        )
        .unwrap_or_else(|error| panic!("node status response should parse: {error}"));

        assert_eq!(response.list_keys(), &[list_key()]);
        let network = response
            .for_network()
            .get("Ethereum")
            .unwrap_or_else(|| panic!("expected Ethereum network status"));
        assert_eq!(network.txid_status().current_txid_index(), Some(10));
        assert_eq!(network.shield_queue_status().added_poi(), 5);
    }

    #[test]
    fn parses_transact_proofs_response() {
        let response = parse_poi_transact_proofs_response_payload(
            r#"{"jsonrpc":"2.0","result":[{"snarkProof":{"pi_a":["a0","a1"],"pi_b":[["b00","b01"],["b10","b11"]],"pi_c":["c0","c1"]},"poiMerkleroots":["0x0202020202020202020202020202020202020202020202020202020202020202"],"txidMerkleroot":"0x0404040404040404040404040404040404040404040404040404040404040404","txidMerklerootIndex":9,"blindedCommitmentsOut":["0x0000000000000000000000000000000000000000000000000000000000000007"],"railgunTxidIfHasUnshield":"0x000000000000000000000000000000000000000000000000000000000000000b"}],"id":1}"#,
        )
        .unwrap_or_else(|error| panic!("transact proofs response should parse: {error}"));

        assert_eq!(response.len(), 1);
        assert_eq!(response[0].txid_merkleroot_index().get(), 9);
    }

    #[test]
    fn parses_merkle_proofs_response() {
        let response = parse_poi_merkle_proofs_response_payload(
            r#"{"jsonrpc":"2.0","result":[{"leaf":"0x0000000000000000000000000000000000000000000000000000000000000007","elements":["0x0101010101010101010101010101010101010101010101010101010101010101"],"indices":"0x01","root":"0x0202020202020202020202020202020202020202020202020202020202020202"}],"id":1}"#,
        )
        .unwrap_or_else(|error| panic!("merkle proofs response should parse: {error}"));

        assert_eq!(response.len(), 1);
        assert_eq!(response[0].leaf().value(), &BigUint::from(7_u8));
        assert_eq!(response[0].root(), &root(2));
    }

    #[test]
    fn parses_boolean_validation_response() {
        let result =
            parse_poi_validation_response_payload(r#"{"jsonrpc":"2.0","result":true,"id":1}"#)
                .unwrap_or_else(|error| panic!("validation response should parse: {error}"));

        assert!(result);
    }

    #[test]
    fn parses_submit_transact_proof_response() {
        parse_poi_submit_transact_proof_response_payload(
            r#"{"jsonrpc":"2.0","result":null,"id":1}"#,
        )
        .unwrap_or_else(|error| panic!("submit transact proof response should parse: {error}"));
    }

    #[test]
    fn remote_error_response_fails_deterministically() {
        let Err(error) = parse_poi_validation_response_payload(
            r#"{"jsonrpc":"2.0","error":{"code":-32000,"message":"boom"},"id":1}"#,
        ) else {
            panic!("remote error should fail");
        };

        assert_eq!(
            error,
            PoiError::PoiJsonRpcRemoteError { code: -32000, message: "boom".to_owned() }
        );
    }

    #[test]
    fn malformed_response_json_fails_deterministically() {
        let Err(error) = parse_poi_health_response_payload("not-json") else {
            panic!("malformed response should fail");
        };

        assert_eq!(error, PoiError::InvalidPoiJsonRpcResponseJson);
    }

    #[test]
    fn validate_poi_merkleroots_request_requires_roots() {
        let Err(error) =
            PoiValidatePoiMerklerootsParams::new(chain_params(), list_key(), Vec::new())
        else {
            panic!("missing poi merkleroots should fail");
        };

        assert_eq!(
            error,
            PoiError::InvalidPoiJsonRpcRequest(
                "ppoi_validate_poi_merkleroots poiMerkleroots must not be empty"
            )
        );
    }

    #[test]
    fn list_key_response_rejects_invalid_hex() {
        let Err(error) = parse_poi_node_status_response_payload(
            r#"{"jsonrpc":"2.0","result":{"listKeys":["bad"],"forNetwork":{}},"id":1}"#,
        ) else {
            panic!("invalid list key should fail");
        };

        assert_eq!(
            error,
            PoiError::InvalidPoiJsonRpcResponse(
                "POI list key must be canonical 32-byte hex in JSON-RPC response"
            )
        );
    }

    #[test]
    fn request_method_accessor_matches_variant() {
        let request = PoiJsonRpcRequest::ValidateTxidMerkleroot {
            id: 1,
            params: Box::new(PoiValidateTxidMerklerootParams::new(chain_params(), 0, 0, root(1))),
        };

        assert_eq!(request.method(), PoiJsonRpcMethod::ValidateTxidMerkleroot);
        assert_eq!(request.id(), 1);
    }

    #[test]
    fn parse_events_response_preserves_opaque_payloads() {
        let events = super::parse_poi_events_response_payload(
            r#"{"jsonrpc":"2.0","result":[{"hash":"0x01"}],"id":1}"#,
        )
        .unwrap_or_else(|error| panic!("events response should parse: {error}"));

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].raw()["hash"], serde_json::Value::String("0x01".to_owned()));
    }

    #[test]
    fn parse_merkletree_leaves_response_preserves_hashes() {
        let leaves = super::parse_poi_merkletree_leaves_response_payload(
            r#"{"jsonrpc":"2.0","result":["0x0606060606060606060606060606060606060606060606060606060606060606"],"id":1}"#,
        )
        .unwrap_or_else(|error| panic!("merkletree leaves response should parse: {error}"));

        assert_eq!(leaves, vec![root(6)]);
    }

    #[test]
    fn parse_transact_proofs_rejects_invalid_txid_hex() {
        let Err(error) = parse_poi_transact_proofs_response_payload(
            r#"{"jsonrpc":"2.0","result":[{"snarkProof":{"pi_a":["a0","a1"],"pi_b":[["b00","b01"],["b10","b11"]],"pi_c":["c0","c1"]},"poiMerkleroots":["0x0202020202020202020202020202020202020202020202020202020202020202"],"txidMerkleroot":"0x0404040404040404040404040404040404040404040404040404040404040404","txidMerklerootIndex":9,"blindedCommitmentsOut":["0x0000000000000000000000000000000000000000000000000000000000000007"],"railgunTxidIfHasUnshield":"0x1234"}],"id":1}"#,
        ) else {
            panic!("invalid txid hex should fail");
        };

        assert_eq!(
            error,
            PoiError::InvalidHexEncoding(
                "railgun txid must be exactly 32 bytes of hex in JSON-RPC response"
            )
        );
    }

    #[test]
    fn manual_root_hash_uses_merkle_node_hash_type_in_fixture_path() {
        let hash = MerkleNodeHash::new([1_u8; 32]);
        assert_eq!(hash.as_bytes(), &[1_u8; 32]);
    }
}
