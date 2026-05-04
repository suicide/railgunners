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
    /// A download configuration was malformed or incomplete.
    InvalidDownloadConfiguration(&'static str),
    /// A remote artifact download failed.
    ArtifactDownloadFailed {
        /// The attempted URL.
        url: String,
        /// Optional HTTP status code when available.
        status_code: Option<u16>,
    },
    /// A Brotli-compressed artifact could not be decompressed.
    ArtifactDecompressionFailed {
        /// The compressed artifact kind.
        kind: ArtifactFileKind,
    },
    /// The local artifact cache could not be written safely.
    ArtifactCacheWriteFailed {
        /// The attempted final path.
        path: PathBuf,
    },
    /// A downloaded artifact failed canonical hash verification.
    ArtifactVerificationFailed {
        /// The verified artifact kind.
        kind: ArtifactFileKind,
        /// The verified file path.
        path: PathBuf,
        /// The canonical expected SHA-256 hash.
        expected_hash: String,
        /// The actual SHA-256 hash computed from disk.
        actual_hash: String,
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
            Self::InvalidDownloadConfiguration(message) => formatter.write_str(message),
            Self::ArtifactDownloadFailed { url, status_code } => match status_code {
                Some(status_code) => {
                    write!(formatter, "failed to download artifact from {url}: HTTP {status_code}")
                }
                None => write!(formatter, "failed to download artifact from {url}"),
            },
            Self::ArtifactDecompressionFailed { kind } => {
                write!(formatter, "failed to decompress Brotli artifact: {kind}")
            }
            Self::ArtifactCacheWriteFailed { path } => {
                write!(formatter, "failed to write artifact cache file: {}", path.display())
            }
            Self::ArtifactVerificationFailed { kind, path, expected_hash, actual_hash } => write!(
                formatter,
                "artifact verification failed for {kind} at {}: expected {expected_hash}, got {actual_hash}",
                path.display()
            ),
        }
    }
}

impl std::error::Error for ArtifactError {}
