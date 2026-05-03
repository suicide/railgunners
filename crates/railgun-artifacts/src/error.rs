//! Typed errors for artifact variant and source resolution.

use std::path::PathBuf;

use crate::ArtifactFileKind;

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
    /// Artifact verification inputs were malformed or incomplete.
    InvalidVerificationInput(&'static str),
    /// The canonical hash catalog could not be parsed.
    HashCatalogParseFailed,
    /// The provided variant string is not a supported canonical artifact variant.
    UnknownArtifactVariant(String),
    /// The canonical hash catalog does not contain an expected hash entry.
    MissingExpectedHash {
        /// The requested file kind.
        kind: ArtifactFileKind,
        /// The requested variant string.
        variant: String,
    },
    /// The requested local artifact file could not be read.
    ArtifactReadFailed {
        /// The attempted path.
        path: PathBuf,
    },
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
            Self::InvalidSourceConfiguration(message) | Self::InvalidVerificationInput(message) => {
                formatter.write_str(message)
            }
            Self::HashCatalogParseFailed => {
                formatter.write_str("failed to parse canonical artifact hash catalog")
            }
            Self::UnknownArtifactVariant(variant) => {
                write!(formatter, "unknown canonical artifact variant: {variant}")
            }
            Self::MissingExpectedHash { kind, variant } => {
                write!(formatter, "missing expected hash for {kind} artifact: {variant}")
            }
            Self::ArtifactReadFailed { path } => {
                write!(formatter, "failed to read artifact file: {}", path.display())
            }
        }
    }
}

impl std::error::Error for ArtifactError {}
