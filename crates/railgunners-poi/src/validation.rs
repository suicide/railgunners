//! Pure POI response validation helpers.

use railgunners_types::MerkleRoot;

use crate::{
    PoiChainParams, PoiError, PoiListKey, PoiTxidStatus, PoiValidatePoiMerklerootsParams,
    PoiValidateTxidMerklerootParams, PoiValidatedTxidStatus,
};

fn check_optional_root_pair(
    index: Option<u64>,
    root: Option<&MerkleRoot>,
    message: &'static str,
) -> Result<(), PoiError> {
    match (index, root) {
        (Some(_), Some(_)) | (None, None) => Ok(()),
        _ => Err(PoiError::InvalidPoiStatus(message)),
    }
}

fn check_expected_chain_params(
    expected_chain_params: PoiChainParams,
    actual_chain_params: PoiChainParams,
) -> Result<(), PoiError> {
    if expected_chain_params == actual_chain_params {
        Ok(())
    } else {
        Err(PoiError::PoiValidationContextMismatch(
            "POI chain params did not match the expected request context",
        ))
    }
}

/// Checks that a latest-validated-txid status is internally consistent.
///
/// # Errors
///
/// Returns an error when the validated txid index/root pair is only partially present.
pub fn check_validated_txid_status(status: &PoiValidatedTxidStatus) -> Result<(), PoiError> {
    // The POI node may legitimately know neither value yet, but callers should never
    // observe only one half of the validated pair.
    check_optional_root_pair(
        status.validated_txid_index(),
        status.validated_merkleroot(),
        "validated txid status must include both validatedTxidIndex and validatedMerkleroot or neither",
    )
}

/// Checks that a txid sync status payload is internally consistent.
///
/// # Errors
///
/// Returns an error when either optional txid index/root pair is only partially present.
pub fn check_txid_status(status: &PoiTxidStatus) -> Result<(), PoiError> {
    check_optional_root_pair(
        status.current_txid_index(),
        status.current_merkleroot(),
        "txid status must include both currentTxidIndex and currentMerkleroot or neither",
    )?;
    check_optional_root_pair(
        status.validated_txid_index(),
        status.validated_merkleroot(),
        "txid status must include both validatedTxidIndex and validatedMerkleroot or neither",
    )
}

/// Validates a parsed `ppoi_validate_txid_merkleroot` boolean result against the expected request context.
///
/// # Errors
///
/// Returns an error when the expected chain params do not match the original typed request.
pub fn validate_txid_merkleroot_result(
    expected_chain_params: PoiChainParams,
    request: &PoiValidateTxidMerklerootParams,
    result: bool,
) -> Result<bool, PoiError> {
    // This endpoint returns only a bare boolean, so the caller must bind that boolean to the
    // exact request context that produced it before trusting the result.
    check_expected_chain_params(expected_chain_params, request.chain_params())?;
    Ok(result)
}

/// Validates a parsed `ppoi_validate_poi_merkleroots` boolean result against the expected request context.
///
/// # Errors
///
/// Returns an error when the expected request context does not match the original typed request.
pub fn validate_poi_merkleroots_result(
    expected_chain_params: PoiChainParams,
    expected_list_key: &PoiListKey,
    expected_poi_merkleroots: &[MerkleRoot],
    request: &PoiValidatePoiMerklerootsParams,
    result: bool,
) -> Result<bool, PoiError> {
    check_expected_chain_params(expected_chain_params, request.chain_params())?;
    if expected_list_key != request.list_key() {
        return Err(PoiError::PoiValidationContextMismatch(
            "POI list key did not match the expected request context",
        ));
    }
    if expected_poi_merkleroots.is_empty() {
        return Err(PoiError::PoiValidationContextMismatch(
            "expected POI merkleroot set must not be empty",
        ));
    }
    if expected_poi_merkleroots != request.poi_merkleroots() {
        return Err(PoiError::PoiValidationContextMismatch(
            "POI merkleroot set did not match the expected request context",
        ));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use railgunners_types::{ChainId, ChainType, MerkleRoot, TxidVersion};

    use super::{
        check_txid_status, check_validated_txid_status, validate_poi_merkleroots_result,
        validate_txid_merkleroot_result,
    };
    use crate::{
        PoiChainParams, PoiError, PoiListKey, PoiTxidStatus, PoiValidatePoiMerklerootsParams,
        PoiValidateTxidMerklerootParams, PoiValidatedTxidStatus,
    };

    fn chain_params() -> PoiChainParams {
        PoiChainParams::new(
            ChainType::new(0),
            ChainId::new(1)
                .unwrap_or_else(|error| panic!("test chain id should validate: {error}")),
            TxidVersion::V2PoseidonMerkle,
        )
    }

    fn other_chain_params() -> PoiChainParams {
        PoiChainParams::new(
            ChainType::new(0),
            ChainId::new(10)
                .unwrap_or_else(|error| panic!("test chain id should validate: {error}")),
            TxidVersion::V2PoseidonMerkle,
        )
    }

    fn list_key() -> PoiListKey {
        PoiListKey::parse("efc6ddb59c098a13fb2b618fdae94c1c3a807abc8fb1837c93620c9143ee9e88")
            .unwrap_or_else(|error| panic!("test list key should parse: {error}"))
    }

    fn other_list_key() -> PoiListKey {
        PoiListKey::parse("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .unwrap_or_else(|error| panic!("test list key should parse: {error}"))
    }

    fn root(byte: u8) -> MerkleRoot {
        MerkleRoot::new([byte; 32])
    }

    #[test]
    fn validated_txid_status_accepts_complete_pair() {
        let status = PoiValidatedTxidStatus::new(Some(42), Some(root(9)));
        check_validated_txid_status(&status)
            .unwrap_or_else(|error| panic!("complete validated pair should pass: {error}"));
    }

    #[test]
    fn validated_txid_status_accepts_empty_pair() {
        let status = PoiValidatedTxidStatus::new(None, None);
        check_validated_txid_status(&status)
            .unwrap_or_else(|error| panic!("empty validated pair should pass: {error}"));
    }

    #[test]
    fn validated_txid_status_rejects_partial_pair() {
        let status = PoiValidatedTxidStatus::new(Some(42), None);
        let Err(error) = check_validated_txid_status(&status) else {
            panic!("partial validated pair should fail");
        };

        assert_eq!(
            error,
            PoiError::InvalidPoiStatus(
                "validated txid status must include both validatedTxidIndex and validatedMerkleroot or neither"
            )
        );
    }

    #[test]
    fn txid_status_accepts_complete_pairs() {
        let status = PoiTxidStatus::new(Some(8), Some(root(1)), Some(7), Some(root(2)));
        check_txid_status(&status)
            .unwrap_or_else(|error| panic!("complete txid status should pass: {error}"));
    }

    #[test]
    fn txid_status_rejects_partial_current_pair() {
        let status = PoiTxidStatus::new(Some(8), None, Some(7), Some(root(2)));
        let Err(error) = check_txid_status(&status) else {
            panic!("partial current pair should fail");
        };

        assert_eq!(
            error,
            PoiError::InvalidPoiStatus(
                "txid status must include both currentTxidIndex and currentMerkleroot or neither"
            )
        );
    }

    #[test]
    fn txid_status_rejects_partial_validated_pair() {
        let status = PoiTxidStatus::new(Some(8), Some(root(1)), None, Some(root(2)));
        let Err(error) = check_txid_status(&status) else {
            panic!("partial validated pair should fail");
        };

        assert_eq!(
            error,
            PoiError::InvalidPoiStatus(
                "txid status must include both validatedTxidIndex and validatedMerkleroot or neither"
            )
        );
    }

    #[test]
    fn txid_merkleroot_result_accepts_matching_context() {
        let request = PoiValidateTxidMerklerootParams::new(chain_params(), 3, 4, root(5));
        let result = validate_txid_merkleroot_result(chain_params(), &request, true)
            .unwrap_or_else(|error| panic!("matching context should pass: {error}"));

        assert!(result);
    }

    #[test]
    fn txid_merkleroot_result_rejects_chain_mismatch() {
        let request = PoiValidateTxidMerklerootParams::new(chain_params(), 3, 4, root(5));
        let Err(error) = validate_txid_merkleroot_result(other_chain_params(), &request, true)
        else {
            panic!("chain mismatch should fail");
        };

        assert_eq!(
            error,
            PoiError::PoiValidationContextMismatch(
                "POI chain params did not match the expected request context"
            )
        );
    }

    #[test]
    fn poi_merkleroots_result_accepts_matching_context() {
        let expected_roots = vec![root(1), root(2)];
        let request = PoiValidatePoiMerklerootsParams::new(
            chain_params(),
            list_key(),
            expected_roots.clone(),
        )
        .unwrap_or_else(|error| panic!("request should construct: {error}"));

        let result = validate_poi_merkleroots_result(
            chain_params(),
            request.list_key(),
            &expected_roots,
            &request,
            false,
        )
        .unwrap_or_else(|error| panic!("matching context should pass: {error}"));

        assert!(!result);
    }

    #[test]
    fn poi_merkleroots_result_rejects_list_key_mismatch() {
        let expected_roots = vec![root(1), root(2)];
        let request = PoiValidatePoiMerklerootsParams::new(
            chain_params(),
            list_key(),
            expected_roots.clone(),
        )
        .unwrap_or_else(|error| panic!("request should construct: {error}"));

        let Err(error) = validate_poi_merkleroots_result(
            chain_params(),
            &other_list_key(),
            &expected_roots,
            &request,
            true,
        ) else {
            panic!("list key mismatch should fail");
        };

        assert_eq!(
            error,
            PoiError::PoiValidationContextMismatch(
                "POI list key did not match the expected request context"
            )
        );
    }

    #[test]
    fn poi_merkleroots_result_rejects_root_set_mismatch() {
        let request = PoiValidatePoiMerklerootsParams::new(
            chain_params(),
            list_key(),
            vec![root(1), root(2)],
        )
        .unwrap_or_else(|error| panic!("request should construct: {error}"));

        let Err(error) = validate_poi_merkleroots_result(
            chain_params(),
            request.list_key(),
            &[root(1), root(3)],
            &request,
            true,
        ) else {
            panic!("root set mismatch should fail");
        };

        assert_eq!(
            error,
            PoiError::PoiValidationContextMismatch(
                "POI merkleroot set did not match the expected request context"
            )
        );
    }

    #[test]
    fn poi_merkleroots_result_rejects_empty_expected_roots() {
        let request =
            PoiValidatePoiMerklerootsParams::new(chain_params(), list_key(), vec![root(1)])
                .unwrap_or_else(|error| panic!("request should construct: {error}"));

        let Err(error) = validate_poi_merkleroots_result(
            chain_params(),
            request.list_key(),
            &[],
            &request,
            true,
        ) else {
            panic!("empty expected roots should fail");
        };

        assert_eq!(
            error,
            PoiError::PoiValidationContextMismatch("expected POI merkleroot set must not be empty")
        );
    }
}
