//! Optional artifact selection and source abstractions for RAILGUN proving assets.
//!
//! This crate resolves canonical circuit variants and storage layout metadata without
//! coupling callers to any built-in download or decompression behavior.

mod error;
mod hash;
mod layout;
mod local;
mod source;
mod variant;
mod verify;

pub use error::ArtifactError;
pub use hash::{ArtifactFileKind, ArtifactHashes, canonical_artifact_hashes};
pub use layout::{
    ArtifactLayout, resolve_artifact_layout, resolve_poi_layout, resolve_standard_layout,
};
pub use local::LocalArtifactSource;
pub use source::{ArtifactSource, ResolvedArtifactPaths};
pub use variant::{
    ArtifactVariant, CircuitFamily, PoiCircuitShape, StandardCircuitShape, parse_artifact_variant,
    resolve_poi_variant, resolve_standard_variant,
};
pub use verify::{
    ArtifactFileVerification, ArtifactVerificationFiles, ArtifactVerificationResult,
    verify_artifact_file, verify_local_artifacts,
};
