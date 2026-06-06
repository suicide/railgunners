//! Typed POI client over a pluggable JSON-RPC transport.

use std::sync::atomic::{AtomicU64, Ordering};

use railgunners_types::MerkleRoot;

use crate::PoiListKey;
use crate::{
    PoiChainParams, PoiError, PoiEventsParams, PoiHealthResponse, PoiJsonRpcRequest,
    PoiMerkleProof, PoiMerkleProofsParams, PoiMerkletreeLeavesParams, PoiNodeStatusResponse,
    PoiSubmitTransactProofParams, PoiSyncedListEvent, PoiTransactProofsParams,
    PoiValidatePoiMerklerootsParams, PoiValidateTxidMerklerootParams, PoiValidatedTxidStatus,
    TransactProofData, check_txid_status, check_validated_txid_status,
    parse_poi_events_response_payload, parse_poi_health_response_payload,
    parse_poi_merkle_proofs_response_payload, parse_poi_merkletree_leaves_response_payload,
    parse_poi_node_status_response_payload, parse_poi_submit_transact_proof_response_payload,
    parse_poi_transact_proofs_response_payload, parse_poi_validated_txid_response_payload,
    parse_poi_validation_response_payload, serialize_poi_json_rpc_request,
    validate_poi_merkleroots_result, validate_txid_merkleroot_result,
};

/// Low-level transport capability for issuing serialized POI JSON-RPC requests.
pub trait PoiJsonRpcTransport {
    /// Executes a serialized POI JSON-RPC request and returns the raw response payload.
    ///
    /// # Errors
    ///
    /// Returns a transport-specific error when the request could not be completed.
    fn execute(&self, request_body: &str) -> Result<String, PoiError>;
}

/// Typed POI JSON-RPC client over a caller-supplied transport.
pub struct PoiClient<T> {
    transport: T,
    next_request_id: AtomicU64,
}

impl<T> PoiClient<T> {
    /// Creates a typed POI client with request ids starting at `1`.
    #[must_use]
    pub const fn new(transport: T) -> Self {
        Self::with_starting_request_id(transport, 1)
    }

    /// Creates a typed POI client with an explicit first request id.
    #[must_use]
    pub const fn with_starting_request_id(transport: T, next_request_id: u64) -> Self {
        Self { transport, next_request_id: AtomicU64::new(next_request_id) }
    }

    /// Returns the underlying transport.
    #[must_use]
    pub const fn transport(&self) -> &T {
        &self.transport
    }
}

impl<T: PoiJsonRpcTransport> PoiClient<T> {
    fn allocate_request_id(&self) -> u64 {
        self.next_request_id.fetch_add(1, Ordering::Relaxed)
    }

    fn execute_request(&self, request: &PoiJsonRpcRequest) -> Result<String, PoiError> {
        let request_body = serialize_poi_json_rpc_request(request)?;
        self.transport.execute(&request_body)
    }

    fn request_and_parse<R>(
        &self,
        request: &PoiJsonRpcRequest,
        parser: impl FnOnce(&str) -> Result<R, PoiError>,
    ) -> Result<R, PoiError> {
        let response_body = self.execute_request(request)?;
        parser(&response_body)
    }

    /// Calls `ppoi_health`.
    ///
    /// # Errors
    ///
    /// Returns an error if the transport fails or the response payload is invalid.
    pub fn health(&self) -> Result<PoiHealthResponse, PoiError> {
        self.request_and_parse(
            &PoiJsonRpcRequest::Health { id: self.allocate_request_id() },
            parse_poi_health_response_payload,
        )
    }

    /// Calls `ppoi_node_status`.
    ///
    /// # Errors
    ///
    /// Returns an error if the transport fails, the response payload is invalid, or a returned
    /// txid status payload is internally inconsistent.
    pub fn node_status(&self) -> Result<PoiNodeStatusResponse, PoiError> {
        let response = self.request_and_parse(
            &PoiJsonRpcRequest::NodeStatus { id: self.allocate_request_id() },
            parse_poi_node_status_response_payload,
        )?;
        for status in response.for_network().values() {
            check_txid_status(status.txid_status())?;
        }
        Ok(response)
    }

    /// Calls `ppoi_poi_events`.
    ///
    /// # Errors
    ///
    /// Returns an error if the transport fails or the response payload is invalid.
    pub fn poi_events(
        &self,
        params: &PoiEventsParams,
    ) -> Result<Vec<PoiSyncedListEvent>, PoiError> {
        self.request_and_parse(
            &PoiJsonRpcRequest::PoiEvents {
                id: self.allocate_request_id(),
                params: Box::new(params.clone()),
            },
            parse_poi_events_response_payload,
        )
    }

    /// Calls `ppoi_poi_merkletree_leaves`.
    ///
    /// # Errors
    ///
    /// Returns an error if the transport fails or the response payload is invalid.
    pub fn poi_merkletree_leaves(
        &self,
        params: &PoiMerkletreeLeavesParams,
    ) -> Result<Vec<MerkleRoot>, PoiError> {
        self.request_and_parse(
            &PoiJsonRpcRequest::PoiMerkletreeLeaves {
                id: self.allocate_request_id(),
                params: Box::new(params.clone()),
            },
            parse_poi_merkletree_leaves_response_payload,
        )
    }

    /// Calls `ppoi_transact_proofs`.
    ///
    /// # Errors
    ///
    /// Returns an error if the transport fails or the response payload is invalid.
    pub fn transact_proofs(
        &self,
        params: &PoiTransactProofsParams,
    ) -> Result<Vec<TransactProofData>, PoiError> {
        self.request_and_parse(
            &PoiJsonRpcRequest::TransactProofs {
                id: self.allocate_request_id(),
                params: Box::new(params.clone()),
            },
            parse_poi_transact_proofs_response_payload,
        )
    }

    /// Calls `ppoi_merkle_proofs`.
    ///
    /// # Errors
    ///
    /// Returns an error if the transport fails or the response payload is invalid.
    pub fn merkle_proofs(
        &self,
        params: &PoiMerkleProofsParams,
    ) -> Result<Vec<PoiMerkleProof>, PoiError> {
        self.request_and_parse(
            &PoiJsonRpcRequest::MerkleProofs {
                id: self.allocate_request_id(),
                params: Box::new(params.clone()),
            },
            parse_poi_merkle_proofs_response_payload,
        )
    }

    /// Calls `ppoi_validated_txid`.
    ///
    /// # Errors
    ///
    /// Returns an error if the transport fails, the response payload is invalid, or the returned
    /// status payload is internally inconsistent.
    pub fn validated_txid(
        &self,
        params: PoiChainParams,
    ) -> Result<PoiValidatedTxidStatus, PoiError> {
        let response = self.request_and_parse(
            &PoiJsonRpcRequest::ValidatedTxid { id: self.allocate_request_id(), params },
            parse_poi_validated_txid_response_payload,
        )?;
        check_validated_txid_status(&response)?;
        Ok(response)
    }

    /// Calls `ppoi_validate_txid_merkleroot`.
    ///
    /// # Errors
    ///
    /// Returns an error if the transport fails, the response payload is invalid, or the returned
    /// boolean does not match the expected request context.
    pub fn validate_txid_merkleroot(
        &self,
        expected_chain_params: PoiChainParams,
        params: &PoiValidateTxidMerklerootParams,
    ) -> Result<bool, PoiError> {
        let response = self.request_and_parse(
            &PoiJsonRpcRequest::ValidateTxidMerkleroot {
                id: self.allocate_request_id(),
                params: Box::new(params.clone()),
            },
            parse_poi_validation_response_payload,
        )?;
        validate_txid_merkleroot_result(expected_chain_params, params, response)
    }

    /// Calls `ppoi_validate_poi_merkleroots`.
    ///
    /// # Errors
    ///
    /// Returns an error if the transport fails, the response payload is invalid, or the returned
    /// boolean does not match the expected request context.
    pub fn validate_poi_merkleroots(
        &self,
        expected_chain_params: PoiChainParams,
        expected_list_key: &PoiListKey,
        expected_poi_merkleroots: &[MerkleRoot],
        params: &PoiValidatePoiMerklerootsParams,
    ) -> Result<bool, PoiError> {
        let response = self.request_and_parse(
            &PoiJsonRpcRequest::ValidatePoiMerkleroots {
                id: self.allocate_request_id(),
                params: Box::new(params.clone()),
            },
            parse_poi_validation_response_payload,
        )?;
        validate_poi_merkleroots_result(
            expected_chain_params,
            expected_list_key,
            expected_poi_merkleroots,
            params,
            response,
        )
    }

    /// Calls `ppoi_submit_transact_proof`.
    ///
    /// # Errors
    ///
    /// Returns an error if the transport fails or the response payload is invalid.
    pub fn submit_transact_proof(
        &self,
        params: &PoiSubmitTransactProofParams,
    ) -> Result<(), PoiError> {
        self.request_and_parse(
            &PoiJsonRpcRequest::SubmitTransactProof {
                id: self.allocate_request_id(),
                params: Box::new(params.clone()),
            },
            parse_poi_submit_transact_proof_response_payload,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use railgunners_types::{ChainId, ChainType, MerkleRoot, TxidVersion};

    use super::{PoiClient, PoiJsonRpcTransport};
    use crate::{PoiChainParams, PoiError, PoiListKey, PoiValidatePoiMerklerootsParams};

    #[derive(Clone, Default)]
    struct RecordingTransport {
        requests: Arc<Mutex<Vec<String>>>,
        response: String,
    }

    impl RecordingTransport {
        fn new(response: &str) -> Self {
            Self { requests: Arc::new(Mutex::new(Vec::new())), response: response.to_owned() }
        }

        fn requests(&self) -> Vec<String> {
            self.requests.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone()
        }
    }

    impl PoiJsonRpcTransport for RecordingTransport {
        fn execute(&self, request_body: &str) -> Result<String, PoiError> {
            self.requests
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(request_body.to_owned());
            Ok(self.response.clone())
        }
    }

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

    #[test]
    fn health_uses_transport_and_parses_response() {
        let transport = RecordingTransport::new(r#"{"jsonrpc":"2.0","result":"ok","id":1}"#);
        let client = PoiClient::new(transport.clone());

        let response = client
            .health()
            .unwrap_or_else(|error| panic!("health request should succeed: {error}"));

        assert_eq!(response.status(), "ok");
        assert_eq!(
            transport.requests(),
            vec![r#"{"jsonrpc":"2.0","method":"ppoi_health","params":[],"id":1}"#.to_owned()]
        );
    }

    #[test]
    fn validate_poi_merkleroots_surfaces_context_mismatch() {
        let expected_roots = vec![root(1), root(2)];
        let request = PoiValidatePoiMerklerootsParams::new(
            chain_params(),
            list_key(),
            expected_roots.clone(),
        )
        .unwrap_or_else(|error| panic!("request should construct: {error}"));
        let transport = RecordingTransport::new(r#"{"jsonrpc":"2.0","result":true,"id":1}"#);
        let client = PoiClient::new(transport);

        let Err(error) =
            client.validate_poi_merkleroots(chain_params(), &list_key(), &[root(9)], &request)
        else {
            panic!("validation mismatch should fail");
        };

        assert_eq!(
            error,
            PoiError::PoiValidationContextMismatch(
                "POI merkleroot set did not match the expected request context"
            )
        );
    }
}
