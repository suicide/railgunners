//! Optional typed POI models and validation helpers.

mod error;
mod model;
mod rpc;
mod validation;

pub use error::PoiError;
pub use model::{
    BlindedCommitment, DEFAULT_REQUIRED_POI_LIST_DESCRIPTION, DEFAULT_REQUIRED_POI_LIST_KEY,
    DEFAULT_REQUIRED_POI_LIST_NAME, PoiEventLengths, PoiEventType, PoiList, PoiListKey,
    PoiListStatus, PoiListType, PoiStatus, PreTransactionPoi, PreTransactionPoisPerTxidLeafPerList,
    TransactProofData, TxidLeafHash, TxidMerklerootIndex, default_required_poi_list,
    default_required_poi_list_key, is_required_poi_list_key, required_poi_lists,
};
pub use rpc::{
    PoiChainParams, PoiEventsParams, PoiHealthResponse, PoiJsonRpcMethod, PoiJsonRpcRequest,
    PoiMerkleProof, PoiMerkleProofsParams, PoiMerkletreeLeavesParams, PoiNodeStatusForNetwork,
    PoiNodeStatusResponse, PoiShieldQueueStatus, PoiSubmitTransactProofParams, PoiSyncedListEvent,
    PoiTransactProofsParams, PoiTxidStatus, PoiValidatePoiMerklerootsParams,
    PoiValidateTxidMerklerootParams, PoiValidatedTxidStatus, parse_poi_events_response_payload,
    parse_poi_health_response_payload, parse_poi_merkle_proofs_response_payload,
    parse_poi_merkletree_leaves_response_payload, parse_poi_node_status_response_payload,
    parse_poi_submit_transact_proof_response_payload, parse_poi_transact_proofs_response_payload,
    parse_poi_validated_txid_response_payload, parse_poi_validation_response_payload,
    serialize_poi_json_rpc_request,
};
pub use validation::{
    check_txid_status, check_validated_txid_status, validate_poi_merkleroots_result,
    validate_txid_merkleroot_result,
};
