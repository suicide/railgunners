//! Optional artifact selection and source abstractions for RAILGUN proving assets.
//!
//! This crate resolves canonical circuit variants and storage layout metadata without
//! coupling callers to any built-in download or decompression behavior.

mod error;
mod layout;
mod local;
mod source;
mod variant;

pub use error::ArtifactError;
pub use layout::{
    ArtifactLayout, resolve_artifact_layout, resolve_poi_layout, resolve_standard_layout,
};
pub use local::LocalArtifactSource;
pub use source::{ArtifactSource, ResolvedArtifactPaths};
pub use variant::{
    ArtifactVariant, CircuitFamily, PoiCircuitShape, StandardCircuitShape, resolve_poi_variant,
    resolve_standard_variant,
};
