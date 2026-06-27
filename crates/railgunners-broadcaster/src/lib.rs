//! Optional broadcaster-facing models and validation helpers.

mod error;
mod fee;
/// Transact request types, parsing, and cryptography.
pub mod transact;
mod waku;

pub use error::BroadcasterError;
pub use fee::{
    BroadcasterFeeMessage, BroadcasterFeeMessageData, BroadcasterFeeMessageDataFields,
    parse_fee_message_data, parse_fee_message_payload, parse_fee_message_wire,
    serialize_fee_message_data, sign_fee_message, validate_fee_message, validate_fee_message_at,
    verify_fee_message_signature,
};
pub use waku::{
    BroadcasterEncryptedData, BroadcasterTransactEnvelope, BroadcasterTransactResponse,
    parse_transact_envelope_payload, parse_transact_response_payload,
    serialize_fee_message_payload, serialize_transact_envelope_payload,
    serialize_transact_response_payload,
};
