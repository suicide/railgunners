//! Typed errors for artifact variant and source resolution.

/// Errors raised while resolving artifact variants, layouts, or sources.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArtifactError {
    /// The provided standard circuit shape is not supported by canonical artifacts.
    UnsupportedStandardShape {
        /// Requested input count.
        n_inputs: u8,
        /// Requested output count.
        n_outputs: u8,
    },
    /// The provided POI circuit shape is not supported by canonical artifacts.
    UnsupportedPoiShape {
        /// Requested POI input bound.
        max_inputs: u8,
        /// Requested POI output bound.
        max_outputs: u8,
    },
    /// A source was configured in a way that cannot be resolved safely.
    InvalidSourceConfiguration(&'static str),
}

impl core::fmt::Display for ArtifactError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedStandardShape { n_inputs, n_outputs } => {
                write!(formatter, "unsupported standard circuit shape: {n_inputs}x{n_outputs}")
            }
            Self::UnsupportedPoiShape { max_inputs, max_outputs } => {
                write!(formatter, "unsupported POI circuit shape: {max_inputs}x{max_outputs}")
            }
            Self::InvalidSourceConfiguration(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for ArtifactError {}
