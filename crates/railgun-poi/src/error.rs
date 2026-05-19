//! Typed errors for POI model parsing and validation.

/// Errors raised while constructing or parsing typed POI models.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PoiError {
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
}

impl core::fmt::Display for PoiError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownPoiStatus(status) => write!(formatter, "unknown POI status: {status}"),
            Self::UnknownPoiListType(list_type) => {
                write!(formatter, "unknown POI list type: {list_type}")
            }
            Self::UnknownPoiEventType(event_type) => {
                write!(formatter, "unknown POI event type: {event_type}")
            }
            Self::InvalidPoiListMetadata(message)
            | Self::InvalidPoiPayload(message)
            | Self::InvalidHexEncoding(message)
            | Self::InvalidFieldEncoding(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for PoiError {}
