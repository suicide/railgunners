//! Optional broadcaster-facing models and validation helpers.
//!
//! Fee quotes treat the classic `relayAdapt` address as optional. A chain with
//! no classic relay-adapt deployment omits the key instead of sending `null`,
//! an empty string, or the zero address, and consumers fall back to
//! `relayAdapt7702`. A missing key is the canonical "no classic relay" signal;
//! an empty string is rejected, while the all-zero address is still accepted
//! because some broadcasters publish it as a legacy sentinel.

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
