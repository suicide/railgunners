//! Canonical artifact hash catalog lookup.

use serde::Deserialize;
use std::{collections::BTreeMap, sync::OnceLock};

use crate::{ArtifactError, ArtifactVariant};

const ARTIFACT_HASH_CATALOG: &str = include_str!("../data/artifact-v2-hashes.json");

/// Canonical artifact file kind used for verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactFileKind {
    /// The proving key artifact.
    Zkey,
    /// The WASM prover artifact.
    Wasm,
    /// The native prover data artifact.
    Dat,
}

impl core::fmt::Display for ArtifactFileKind {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Zkey => formatter.write_str("zkey"),
            Self::Wasm => formatter.write_str("wasm"),
            Self::Dat => formatter.write_str("dat"),
        }
    }
}

/// Canonical expected SHA-256 hashes for a single artifact variant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactHashes {
    zkey: String,
    wasm: String,
    dat: String,
}

impl ArtifactHashes {
    /// Returns the expected `zkey` SHA-256 hash.
    #[must_use]
    pub fn zkey(&self) -> &str {
        &self.zkey
    }

    /// Returns the expected `wasm` SHA-256 hash.
    #[must_use]
    pub fn wasm(&self) -> &str {
        &self.wasm
    }

    /// Returns the expected `dat` SHA-256 hash.
    #[must_use]
    pub fn dat(&self) -> &str {
        &self.dat
    }

    /// Returns the expected hash for the requested file kind.
    #[must_use]
    pub fn expected_hash(&self, kind: ArtifactFileKind) -> &str {
        match kind {
            ArtifactFileKind::Zkey => self.zkey(),
            ArtifactFileKind::Wasm => self.wasm(),
            ArtifactFileKind::Dat => self.dat(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
struct ArtifactHashesRecord {
    zkey: String,
    wasm: String,
    dat: String,
}

fn hash_catalog() -> Result<&'static BTreeMap<String, ArtifactHashesRecord>, ArtifactError> {
    static HASH_CATALOG: OnceLock<Result<BTreeMap<String, ArtifactHashesRecord>, ArtifactError>> =
        OnceLock::new();

    HASH_CATALOG
        .get_or_init(|| {
            serde_json::from_str(ARTIFACT_HASH_CATALOG)
                .map_err(|_| ArtifactError::HashCatalogParseFailed)
        })
        .as_ref()
        .map_err(Clone::clone)
}

/// Looks up the canonical expected artifact hashes for a variant.
///
/// # Errors
///
/// Returns an error when the variant is not present in the canonical hash catalog.
pub fn canonical_artifact_hashes(
    variant: &ArtifactVariant,
) -> Result<ArtifactHashes, ArtifactError> {
    let variant_string = variant.to_string();
    let Some(record) = hash_catalog()?.get(&variant_string) else {
        return Err(ArtifactError::UnknownArtifactVariant(variant_string));
    };

    Ok(ArtifactHashes {
        zkey: record.zkey.clone(),
        wasm: record.wasm.clone(),
        dat: record.dat.clone(),
    })
}

#[cfg(test)]
mod tests {
    use crate::{canonical_artifact_hashes, resolve_poi_variant, resolve_standard_variant};

    #[test]
    fn looks_up_standard_vector_hashes() {
        let Ok(variant) = resolve_standard_variant(1, 1) else {
            panic!("expected supported standard shape 1x1");
        };
        let Ok(hashes) = canonical_artifact_hashes(&variant) else {
            panic!("expected canonical standard hash entry");
        };

        assert_eq!(
            hashes.zkey(),
            "27443e834f807f0d4ce8a0c2a0e028d1d540cba9c3e4d64b864b367e797215f4"
        );
        assert_eq!(
            hashes.wasm(),
            "37a1528543305c64805e3c607940341abf61ba8516f73cfeb625cd09e5bda7a6"
        );
        assert_eq!(
            hashes.dat(),
            "e05df1379eb913024dc9f54faca213b877af7566722f0835a6afb551d53f6390"
        );
    }

    #[test]
    fn looks_up_poi_vector_hashes() {
        let Ok(variant) = resolve_poi_variant(3, 3) else {
            panic!("expected supported POI shape 3x3");
        };
        let Ok(hashes) = canonical_artifact_hashes(&variant) else {
            panic!("expected canonical POI hash entry");
        };

        assert_eq!(
            hashes.zkey(),
            "667984c51df2122956107c11c3c606e4e4688f70fb25515b9388cbd5140e48b3"
        );
        assert_eq!(
            hashes.wasm(),
            "831aad53c05d19f9854ed27429610da724fbdf9e1e7023aa7a90666f50b0da78"
        );
        assert_eq!(
            hashes.dat(),
            "8f6dff99544025e4af4631be91599194ad680cb54f5242bf09779781d7fc4ee1"
        );
    }
}
