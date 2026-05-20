//! Typed errors for POI model parsing and validation.

use crate::model::MissingPreTransactionPoiBundle;

/// Errors raised while constructing or parsing typed POI models.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PoiError {
    /// A POI JSON-RPC method string was unknown.
    UnknownPoiJsonRpcMethod(String),
    /// A POI status string was unknown.
    UnknownPoiStatus(String),
    /// A POI list type string was unknown.
    UnknownPoiListType(String),
    /// A POI event type string was unknown.
    UnknownPoiEventType(String),
    /// A required POI list field was empty or malformed.
    InvalidPoiListMetadata(&'static str),
    /// A POI proof-like payload was missing required data.
    InvalidPoiPayload(&'static str),
    /// A typed POI wrapper could not be parsed from hex.
    InvalidHexEncoding(&'static str),
    /// A typed POI field did not encode a canonical BN254 scalar value.
    InvalidFieldEncoding(&'static str),
    /// A required pre-transaction POI bundle entry was missing.
    MissingRequiredPreTransactionPois(Box<MissingPreTransactionPoiBundle>),
    /// A POI JSON-RPC request payload was malformed.
    InvalidPoiJsonRpcRequest(&'static str),
    /// A POI JSON-RPC request payload JSON could not be parsed or serialized.
    InvalidPoiJsonRpcRequestJson,
    /// A POI JSON-RPC response payload was malformed.
    InvalidPoiJsonRpcResponse(&'static str),
    /// A POI JSON-RPC response payload JSON could not be parsed.
    InvalidPoiJsonRpcResponseJson,
    /// The remote POI JSON-RPC endpoint returned an error payload.
    PoiJsonRpcRemoteError {
        /// Remote JSON-RPC error code.
        code: i64,
        /// Remote JSON-RPC error message.
        message: String,
    },
    /// A parsed POI status payload was internally inconsistent.
    InvalidPoiStatus(&'static str),
    /// Parsed POI request/response context did not match the caller expectation.
    PoiValidationContextMismatch(&'static str),
    /// A configured POI transport endpoint URL was invalid.
    InvalidPoiTransportEndpoint(String),
    /// The POI transport failed before receiving a response.
    PoiTransportFailed(String),
    /// The POI transport timed out.
    PoiTransportTimeout,
    /// The POI transport returned an unexpected HTTP status code.
    PoiTransportUnexpectedHttpStatus(u16),
    /// The POI transport exhausted its retry budget.
    PoiTransportRetryExhausted {
        /// The number of attempted requests, including the first attempt.
        attempts: u32,
        /// The final retryable transport error that exhausted the budget.
        last_error: Box<PoiError>,
    },
}

impl core::fmt::Display for PoiError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownPoiJsonRpcMethod(method) => {
                write!(formatter, "unknown POI JSON-RPC method: {method}")
            }
            Self::UnknownPoiStatus(status) => write!(formatter, "unknown POI status: {status}"),
            Self::UnknownPoiListType(list_type) => {
                write!(formatter, "unknown POI list type: {list_type}")
            }
            Self::UnknownPoiEventType(event_type) => {
                write!(formatter, "unknown POI event type: {event_type}")
            }
            Self::MissingRequiredPreTransactionPois(_) => {
                formatter.write_str("required pre-transaction POI bundle entries were missing")
            }
            Self::InvalidPoiListMetadata(message)
            | Self::InvalidPoiPayload(message)
            | Self::InvalidHexEncoding(message)
            | Self::InvalidFieldEncoding(message)
            | Self::InvalidPoiStatus(message)
            | Self::InvalidPoiJsonRpcRequest(message)
            | Self::PoiValidationContextMismatch(message)
            | Self::InvalidPoiJsonRpcResponse(message) => formatter.write_str(message),
            Self::InvalidPoiJsonRpcRequestJson => {
                formatter.write_str("failed to parse or serialize POI JSON-RPC request JSON")
            }
            Self::InvalidPoiJsonRpcResponseJson => {
                formatter.write_str("failed to parse POI JSON-RPC response JSON")
            }
            Self::PoiJsonRpcRemoteError { code, message } => {
                write!(formatter, "POI JSON-RPC remote error {code}: {message}")
            }
            Self::InvalidPoiTransportEndpoint(endpoint) => {
                write!(formatter, "invalid POI transport endpoint: {endpoint}")
            }
            Self::PoiTransportFailed(message) => {
                write!(formatter, "POI transport failed: {message}")
            }
            Self::PoiTransportTimeout => formatter.write_str("POI transport timed out"),
            Self::PoiTransportUnexpectedHttpStatus(status) => {
                write!(formatter, "POI transport returned unexpected HTTP status: {status}")
            }
            Self::PoiTransportRetryExhausted { attempts, last_error } => {
                write!(formatter, "POI transport exhausted {attempts} attempts: {last_error}")
            }
        }
    }
}

impl std::error::Error for PoiError {}
