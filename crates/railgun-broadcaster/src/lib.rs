//! Optional broadcaster-facing models and validation helpers.

mod error;
mod fee;

pub use error::BroadcasterError;
pub use fee::{
    BroadcasterFeeMessage, BroadcasterFeeMessageData, parse_fee_message_data,
    parse_fee_message_payload, parse_fee_message_wire, validate_fee_message,
    validate_fee_message_at, verify_fee_message_signature,
};
