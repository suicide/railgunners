//! Typed errors for broadcaster message parsing and validation.

/// Errors raised while parsing or validating broadcaster-facing payloads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BroadcasterError {
    /// The outer broadcaster fee message JSON could not be parsed.
    InvalidFeeMessagePayload,
    /// The broadcaster fee message was missing or malformed.
    InvalidFeeMessage(&'static str),
    /// The hex-encoded fee message data field could not be decoded.
    InvalidFeeMessageDataHex,
    /// The decoded fee message data bytes were not valid UTF-8.
    InvalidFeeMessageDataUtf8,
    /// The inner broadcaster fee message data JSON could not be parsed.
    InvalidFeeMessageDataJson,
    /// The parsed fee message data contained invalid field values.
    InvalidFeeMessageField(&'static str),
    /// The fee quote is stale for the supplied validation time.
    ExpiredFeeQuote {
        /// Fee-expiration timestamp carried by the message.
        fee_expiration: u64,
        /// Validation timestamp supplied by the caller.
        validation_time: u64,
    },
    /// The fee message signature was malformed.
    InvalidFeeMessageSignature,
    /// The fee message signature did not verify against the broadcaster identity.
    InvalidFeeMessageSignatureVerification,
}

impl core::fmt::Display for BroadcasterError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidFeeMessagePayload => {
                formatter.write_str("failed to parse broadcaster fee message payload JSON")
            }
            Self::InvalidFeeMessage(message) | Self::InvalidFeeMessageField(message) => {
                formatter.write_str(message)
            }
            Self::InvalidFeeMessageDataHex => {
                formatter.write_str("broadcaster fee message data must be valid hex")
            }
            Self::InvalidFeeMessageDataUtf8 => formatter
                .write_str("broadcaster fee message data hex must decode to valid UTF-8 JSON"),
            Self::InvalidFeeMessageDataJson => {
                formatter.write_str("failed to parse broadcaster fee message data JSON")
            }
            Self::ExpiredFeeQuote { fee_expiration, validation_time } => write!(
                formatter,
                "broadcaster fee quote expired at {fee_expiration}, validation time was {validation_time}"
            ),
            Self::InvalidFeeMessageSignature => {
                formatter.write_str("broadcaster fee message signature must be valid 64-byte hex")
            }
            Self::InvalidFeeMessageSignatureVerification => {
                formatter.write_str("broadcaster fee message signature verification failed")
            }
        }
    }
}

impl std::error::Error for BroadcasterError {}
