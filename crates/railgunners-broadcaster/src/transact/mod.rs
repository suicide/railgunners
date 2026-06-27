/// COMMON transact payload types, parsing, and cryptography.
pub mod common;

use crate::BroadcasterError;

/// Canonical broadcaster transact request type supported by this crate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BroadcasterTransactRequestType {
    /// Canonical COMMON transact payload.
    Common,
}

impl BroadcasterTransactRequestType {
    pub(crate) fn as_wire(self) -> &'static str {
        match self {
            Self::Common => "COMMON",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, BroadcasterError> {
        match value {
            "COMMON" => Ok(Self::Common),
            unsupported => Err(BroadcasterError::UnsupportedTransactType(unsupported.to_owned())),
        }
    }
}
