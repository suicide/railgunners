/// COMMON transact payload types, parsing, and cryptography.
pub mod common;
/// EIP-7702 (`TX7702`) transact payload types and parsing.
pub mod tx7702;

use serde::Deserialize;

use crate::BroadcasterError;

/// Canonical broadcaster transact request type supported by this crate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BroadcasterTransactRequestType {
    /// Canonical COMMON transact payload.
    Common,
    /// EIP-7702 (`TX7702`) transact payload.
    Tx7702,
}

impl BroadcasterTransactRequestType {
    /// Returns the canonical wire discriminator.
    #[must_use]
    pub const fn as_wire(self) -> &'static str {
        match self {
            Self::Common => "COMMON",
            Self::Tx7702 => "TX7702",
        }
    }

    /// Parses a wire discriminator.
    ///
    /// `"undefined"` is how older clients serialize a missing discriminator, so
    /// it stays `COMMON` for compatibility.
    ///
    /// # Errors
    ///
    /// Returns [`BroadcasterError::UnsupportedTransactType`] for any other value.
    pub fn parse(value: &str) -> Result<Self, BroadcasterError> {
        match value {
            "COMMON" | "undefined" => Ok(Self::Common),
            "TX7702" => Ok(Self::Tx7702),
            unsupported => Err(BroadcasterError::UnsupportedTransactType(unsupported.to_owned())),
        }
    }
}

/// Typed broadcaster transact request, dispatched by its wire discriminator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BroadcasterTransactRequest {
    /// Canonical COMMON transact payload.
    Common(common::BroadcasterRawParamsTransactCommon),
    /// EIP-7702 transact payload.
    Tx7702(tx7702::BroadcasterRawParamsTransactTx7702),
}

impl BroadcasterTransactRequest {
    /// Returns the request type.
    #[must_use]
    pub const fn transact_type(&self) -> BroadcasterTransactRequestType {
        match self {
            Self::Common(_) => BroadcasterTransactRequestType::Common,
            Self::Tx7702(_) => BroadcasterTransactRequestType::Tx7702,
        }
    }
}

#[derive(Deserialize)]
struct TransactTypeHeader {
    #[serde(rename = "transactType", default)]
    transact_type: Option<serde_json::Value>,
}

/// Parses a broadcaster transact payload by its `transactType` discriminator.
///
/// A missing discriminator and `"undefined"` are `COMMON`. An explicit
/// `"TX7702"` wins over any `COMMON`-shaped fields in the same object, so an
/// attached authorization is never dropped. Unknown discriminators are
/// rejected.
///
/// # Errors
///
/// Returns an error if the payload is not JSON, or the selected request shape is
/// malformed.
pub fn parse(payload: &str) -> Result<BroadcasterTransactRequest, BroadcasterError> {
    match peek_transact_type(payload)? {
        BroadcasterTransactRequestType::Common => {
            common::parse(payload).map(BroadcasterTransactRequest::Common)
        }
        BroadcasterTransactRequestType::Tx7702 => {
            tx7702::parse(payload).map(BroadcasterTransactRequest::Tx7702)
        }
    }
}

fn peek_transact_type(payload: &str) -> Result<BroadcasterTransactRequestType, BroadcasterError> {
    let header: TransactTypeHeader =
        serde_json::from_str(payload).map_err(|_| BroadcasterError::InvalidTransactPayloadJson)?;

    match header.transact_type {
        None | Some(serde_json::Value::Null) => Ok(BroadcasterTransactRequestType::Common),
        Some(serde_json::Value::String(value)) => BroadcasterTransactRequestType::parse(&value),
        Some(other) => Err(BroadcasterError::UnsupportedTransactType(other.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::{BroadcasterTransactRequest, BroadcasterTransactRequestType, common, parse};
    use crate::BroadcasterError;

    const VIEWING_KEY: &str = "0x0707070707070707070707070707070707070707070707070707070707070707";
    const TO: &str = "0x1111111111111111111111111111111111111111";

    fn common_payload(transact_type: Option<&str>) -> serde_json::Value {
        let mut value = serde_json::json!({
            "txidVersion": "V2_PoseidonMerkle",
            "chainID": 1,
            "chainType": 0,
            "feesID": "fees-cache-id",
            "broadcasterViewingKey": VIEWING_KEY,
            "to": TO,
            "data": "0x1234",
            "minGasPrice": "4096",
            "preTransactionPOIsPerTxidLeafPerList": {},
        });
        if let Some(transact_type) = transact_type {
            value["transactType"] = serde_json::Value::String(transact_type.to_owned());
        }
        value
    }

    fn tx7702_payload() -> serde_json::Value {
        let mut value = common_payload(Some("TX7702"));
        let object =
            value.as_object_mut().unwrap_or_else(|| panic!("payload should be a JSON object"));
        object.remove("minGasPrice");
        value["maxFeePerGas"] = serde_json::Value::String("2000000000".to_owned());
        value["maxPriorityFeePerGas"] = serde_json::Value::String("1".to_owned());
        value["authorization"] = serde_json::json!({
            "address": TO,
            "nonce": "1",
            "chainId": "1",
            "signature": {
                "r": "0x1111111111111111111111111111111111111111111111111111111111111111",
                "s": "0x2222222222222222222222222222222222222222222222222222222222222222",
                "v": 27,
            },
        });
        value
    }

    #[test]
    fn dispatches_tx7702_ahead_of_common_fields() {
        let payload = tx7702_payload().to_string();
        let request =
            parse(&payload).unwrap_or_else(|error| panic!("payload should parse: {error}"));

        assert_eq!(request.transact_type(), BroadcasterTransactRequestType::Tx7702);
        assert!(matches!(request, BroadcasterTransactRequest::Tx7702(_)));
    }

    #[test]
    fn tx7702_with_min_gas_price_stays_tx7702() {
        let mut value = tx7702_payload();
        value["minGasPrice"] = serde_json::Value::String("4096".to_owned());
        value["useRelayAdapt"] = serde_json::Value::Bool(true);

        let request = parse(&value.to_string())
            .unwrap_or_else(|error| panic!("payload should parse: {error}"));

        assert_eq!(request.transact_type(), BroadcasterTransactRequestType::Tx7702);
    }

    #[test]
    fn missing_transact_type_is_common() {
        let request = parse(&common_payload(None).to_string())
            .unwrap_or_else(|error| panic!("payload should parse: {error}"));

        assert_eq!(request.transact_type(), BroadcasterTransactRequestType::Common);
    }

    #[test]
    fn undefined_transact_type_is_common() {
        let request = parse(&common_payload(Some("undefined")).to_string())
            .unwrap_or_else(|error| panic!("payload should parse: {error}"));

        assert_eq!(request.transact_type(), BroadcasterTransactRequestType::Common);
    }

    #[test]
    fn rejects_unknown_transact_type() {
        let Err(error) = parse(&common_payload(Some("UNSUPPORTED")).to_string()) else {
            panic!("unknown transact type should fail");
        };

        assert_eq!(error, BroadcasterError::UnsupportedTransactType("UNSUPPORTED".to_owned()));
    }

    #[test]
    fn common_parse_still_rejects_tx7702() {
        // A COMMON-shaped payload that claims TX7702 must not become COMMON, or
        // the authorization would be dropped.
        let mut value = tx7702_payload();
        value["minGasPrice"] = serde_json::Value::String("4096".to_owned());

        let Err(error) = common::parse(&value.to_string()) else {
            panic!("common parse must not accept a TX7702 payload");
        };

        assert_eq!(error, BroadcasterError::UnsupportedTransactType("TX7702".to_owned()));
    }
}
