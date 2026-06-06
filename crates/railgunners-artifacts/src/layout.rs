//! Canonical artifact storage layout resolution.

use std::path::PathBuf;

use crate::{
    ArtifactError, ArtifactVariant, CircuitFamily, resolve_poi_variant, resolve_standard_variant,
};

const STANDARD_ARTIFACT_ROOT: &str = "artifacts-v2.1";
const POI_ARTIFACT_ROOT: &str = "artifacts-v2.1/poi-nov-2-23";

/// Canonical relative storage layout metadata for a resolved artifact variant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactLayout {
    family: CircuitFamily,
    variant: ArtifactVariant,
    directory: PathBuf,
    zkey_path: PathBuf,
    vkey_path: PathBuf,
    wasm_path: PathBuf,
    dat_path: PathBuf,
}

impl ArtifactLayout {
    /// Returns the circuit family.
    #[must_use]
    pub const fn family(&self) -> CircuitFamily {
        self.family
    }

    /// Returns the resolved canonical variant.
    #[must_use]
    pub const fn variant(&self) -> ArtifactVariant {
        self.variant
    }

    /// Returns the resolved canonical variant string.
    #[must_use]
    pub fn variant_string(&self) -> String {
        self.variant.to_string()
    }

    /// Returns the canonical relative directory for the variant.
    #[must_use]
    pub fn directory(&self) -> &std::path::Path {
        &self.directory
    }

    /// Returns the canonical relative path for the `zkey` artifact.
    #[must_use]
    pub fn zkey_path(&self) -> &std::path::Path {
        &self.zkey_path
    }

    /// Returns the canonical relative path for the `vkey.json` artifact.
    #[must_use]
    pub fn vkey_path(&self) -> &std::path::Path {
        &self.vkey_path
    }

    /// Returns the canonical relative path for the `wasm` artifact.
    #[must_use]
    pub fn wasm_path(&self) -> &std::path::Path {
        &self.wasm_path
    }

    /// Returns the canonical relative path for the `dat` artifact.
    #[must_use]
    pub fn dat_path(&self) -> &std::path::Path {
        &self.dat_path
    }
}

/// Resolves the canonical relative storage layout for an artifact variant.
#[must_use]
pub fn resolve_artifact_layout(variant: &ArtifactVariant) -> ArtifactLayout {
    let variant_string = variant.to_string();
    let directory = match variant.family() {
        CircuitFamily::Standard => PathBuf::from(STANDARD_ARTIFACT_ROOT).join(&variant_string),
        CircuitFamily::Poi => PathBuf::from(POI_ARTIFACT_ROOT).join(&variant_string),
    };

    ArtifactLayout {
        family: variant.family(),
        variant: *variant,
        zkey_path: directory.join("zkey"),
        vkey_path: directory.join("vkey.json"),
        wasm_path: directory.join("wasm"),
        dat_path: directory.join("dat"),
        directory,
    }
}

/// Resolves standard artifact layout metadata.
///
/// # Errors
///
/// Returns an error when the requested standard shape is unsupported.
pub fn resolve_standard_layout(
    n_inputs: u8,
    n_outputs: u8,
) -> Result<ArtifactLayout, ArtifactError> {
    resolve_standard_variant(n_inputs, n_outputs).map(|variant| resolve_artifact_layout(&variant))
}

/// Resolves POI artifact layout metadata.
///
/// # Errors
///
/// Returns an error when the requested POI shape is unsupported.
pub fn resolve_poi_layout(
    max_inputs: u8,
    max_outputs: u8,
) -> Result<ArtifactLayout, ArtifactError> {
    resolve_poi_variant(max_inputs, max_outputs).map(|variant| resolve_artifact_layout(&variant))
}

#[cfg(test)]
mod tests {
    use super::{resolve_poi_layout, resolve_standard_layout};

    #[test]
    fn resolves_standard_layout_under_standard_root() {
        let Ok(layout) = resolve_standard_layout(10, 4) else {
            panic!("expected supported standard shape 10x4");
        };
        assert_eq!(layout.variant_string(), "10x04");
        assert_eq!(layout.directory().to_string_lossy(), "artifacts-v2.1/10x04");
        assert_eq!(layout.zkey_path().to_string_lossy(), "artifacts-v2.1/10x04/zkey");
        assert_eq!(layout.vkey_path().to_string_lossy(), "artifacts-v2.1/10x04/vkey.json");
        assert_eq!(layout.wasm_path().to_string_lossy(), "artifacts-v2.1/10x04/wasm");
        assert_eq!(layout.dat_path().to_string_lossy(), "artifacts-v2.1/10x04/dat");
    }

    #[test]
    fn resolves_poi_layout_under_poi_root() {
        let Ok(layout) = resolve_poi_layout(3, 3) else {
            panic!("expected supported POI shape 3x3");
        };
        assert_eq!(layout.variant_string(), "POI_3x3");
        assert_eq!(layout.directory().to_string_lossy(), "artifacts-v2.1/poi-nov-2-23/POI_3x3");
        assert_eq!(
            layout.zkey_path().to_string_lossy(),
            "artifacts-v2.1/poi-nov-2-23/POI_3x3/zkey"
        );
        assert_eq!(
            layout.vkey_path().to_string_lossy(),
            "artifacts-v2.1/poi-nov-2-23/POI_3x3/vkey.json"
        );
        assert_eq!(
            layout.wasm_path().to_string_lossy(),
            "artifacts-v2.1/poi-nov-2-23/POI_3x3/wasm"
        );
        assert_eq!(layout.dat_path().to_string_lossy(), "artifacts-v2.1/poi-nov-2-23/POI_3x3/dat");
    }
}
