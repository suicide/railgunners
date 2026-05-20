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
    /// The transact payload JSON could not be parsed.
    InvalidTransactPayloadJson,
    /// The parsed transact payload was missing required data.
    InvalidTransactPayload(&'static str),
    /// The transact payload requested an unsupported transact type.
    UnsupportedTransactType(String),
    /// The transact payload used an unsupported txid version.
    UnsupportedTxidVersion(String),
    /// The transact payload used an unsupported chain type.
    UnsupportedChainType(u64),
    /// The transact payload used an invalid chain id.
    InvalidChainId,
    /// The transact payload used an invalid broadcaster viewing key.
    InvalidBroadcasterViewingKey,
    /// The transact payload used an invalid destination address.
    InvalidTransactToAddress,
    /// The transact payload used malformed calldata.
    InvalidTransactCalldata,
    /// The transact payload POI bundle was malformed.
    InvalidTransactPoiBundle(&'static str),
    /// The transact envelope JSON could not be parsed.
    InvalidTransactEnvelopePayloadJson,
    /// The transact envelope was malformed.
    InvalidTransactEnvelopePayload(&'static str),
    /// The transact envelope public key was malformed.
    InvalidTransactEnvelopePubkey,
    /// The transact envelope encrypted payload tuple was malformed.
    InvalidTransactEnvelopeEncryptedData(&'static str),
    /// The broadcaster viewing key used for transact encryption was invalid.
    InvalidBroadcasterEncryptionKey,
    /// Broadcaster transact encryption failed unexpectedly.
    TransactEncryptionFailed,
    /// Broadcaster transact decryption failed unexpectedly.
    TransactDecryptionFailed,
    /// Broadcaster transact plaintext was not valid UTF-8 JSON.
    InvalidTransactPayloadUtf8,
    /// The transact response JSON could not be parsed.
    InvalidTransactResponsePayloadJson,
    /// The transact response was malformed.
    InvalidTransactResponsePayload(&'static str),
}

impl core::fmt::Display for BroadcasterError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidFeeMessagePayload => {
                formatter.write_str("failed to parse broadcaster fee message payload JSON")
            }
            Self::InvalidFeeMessage(message)
            | Self::InvalidFeeMessageField(message)
            | Self::InvalidTransactPayload(message)
            | Self::InvalidTransactPoiBundle(message)
            | Self::InvalidTransactEnvelopePayload(message)
            | Self::InvalidTransactEnvelopeEncryptedData(message)
            | Self::InvalidTransactResponsePayload(message) => formatter.write_str(message),
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
            Self::InvalidTransactPayloadJson => {
                formatter.write_str("failed to parse broadcaster transact payload JSON")
            }
            Self::InvalidTransactPayloadUtf8 => {
                formatter.write_str("broadcaster transact payload must decrypt to valid UTF-8 JSON")
            }
            Self::UnsupportedTransactType(transact_type) => {
                write!(formatter, "unsupported broadcaster transact type: {transact_type}")
            }
            Self::UnsupportedTxidVersion(version) => {
                write!(formatter, "unsupported broadcaster txid version: {version}")
            }
            Self::UnsupportedChainType(chain_type) => {
                write!(formatter, "unsupported broadcaster chain type: {chain_type}")
            }
            Self::InvalidChainId => formatter.write_str("broadcaster chain id must be non-zero"),
            Self::InvalidBroadcasterViewingKey => {
                formatter.write_str("broadcaster viewing key must be valid 32-byte hex public key")
            }
            Self::InvalidTransactToAddress => {
                formatter.write_str("broadcaster transact to address must be valid 20-byte hex")
            }
            Self::InvalidTransactCalldata => {
                formatter.write_str("broadcaster transact data must be valid hex")
            }
            Self::InvalidTransactEnvelopePayloadJson => {
                formatter.write_str("failed to parse broadcaster transact envelope JSON")
            }
            Self::InvalidTransactEnvelopePubkey => formatter.write_str(
                "broadcaster transact envelope pubkey must be valid 32-byte hex viewing public key",
            ),
            Self::InvalidBroadcasterEncryptionKey => formatter
                .write_str("broadcaster viewing key must decode to a valid ed25519 public key"),
            Self::TransactEncryptionFailed => {
                formatter.write_str("failed to encrypt broadcaster transact payload")
            }
            Self::TransactDecryptionFailed => {
                formatter.write_str("failed to decrypt broadcaster transact payload")
            }
            Self::InvalidTransactResponsePayloadJson => {
                formatter.write_str("failed to parse broadcaster transact response JSON")
            }
        }
    }
}

impl std::error::Error for BroadcasterError {}
