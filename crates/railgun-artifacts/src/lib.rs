//! Optional artifact selection and source abstractions for RAILGUN proving assets.
//!
//! This crate resolves canonical circuit variants and storage layout metadata without
//! coupling callers to built-in download or decompression behavior unless the optional
//! `download` feature is enabled.

mod backend;
#[cfg(feature = "download")]
mod download;
mod error;
mod hash;
mod layout;
mod load;
mod local;
mod source;
mod variant;
mod verify;

pub use backend::ArtifactBackend;
#[cfg(feature = "download")]
pub use download::{
    ArtifactDownloadConfig, ArtifactDownloadResult, ArtifactRemoteSource, ArtifactRemoteUrls,
    DownloadedArtifactFiles, download_artifacts,
};
pub use error::ArtifactError;
pub use hash::{ArtifactFileKind, ArtifactHashes, canonical_artifact_hashes};
pub use layout::{
    ArtifactLayout, resolve_artifact_layout, resolve_poi_layout, resolve_standard_layout,
};
pub use load::{
    LoadedArtifactBundle, LoadedArtifactFiles, LoadedArtifactPaths, VerificationKeyJson,
    load_artifact_bundle, load_artifact_bundle_from_resolved_paths,
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
