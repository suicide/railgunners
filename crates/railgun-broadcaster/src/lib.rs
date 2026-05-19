//! Optional broadcaster-facing models and validation helpers.

mod error;
mod fee;
mod transact;

pub use error::BroadcasterError;
pub use fee::{
    BroadcasterFeeMessage, BroadcasterFeeMessageData, parse_fee_message_data,
    parse_fee_message_payload, parse_fee_message_wire, validate_fee_message,
    validate_fee_message_at, verify_fee_message_signature,
};
pub use transact::{
    BroadcasterRawParamsTransactCommon, BroadcasterRequestSharedParams,
    BroadcasterTransactRequestType, BroadcasterVersionRange, parse_transact_common_payload,
    serialize_transact_common_payload,
};
