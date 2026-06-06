//! Artifact source capability traits.

use std::path::{Path, PathBuf};

use crate::ArtifactLayout;

/// Concrete source-local artifact paths resolved from canonical layout metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedArtifactPaths {
    source_root: PathBuf,
    directory: PathBuf,
    zkey_path: PathBuf,
    vkey_path: PathBuf,
    wasm_path: PathBuf,
    dat_path: PathBuf,
}

impl ResolvedArtifactPaths {
    /// Returns the configured source root used for resolution.
    #[must_use]
    pub fn source_root(&self) -> &Path {
        &self.source_root
    }

    /// Returns the fully resolved variant directory.
    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// Returns the fully resolved `zkey` path.
    #[must_use]
    pub fn zkey_path(&self) -> &Path {
        &self.zkey_path
    }

    /// Returns the fully resolved `vkey.json` path.
    #[must_use]
    pub fn vkey_path(&self) -> &Path {
        &self.vkey_path
    }

    /// Returns the fully resolved `wasm` path.
    #[must_use]
    pub fn wasm_path(&self) -> &Path {
        &self.wasm_path
    }

    /// Returns the fully resolved `dat` path.
    #[must_use]
    pub fn dat_path(&self) -> &Path {
        &self.dat_path
    }

    pub(crate) fn new(source_root: PathBuf, layout: &ArtifactLayout) -> Self {
        Self {
            directory: source_root.join(layout.directory()),
            zkey_path: source_root.join(layout.zkey_path()),
            vkey_path: source_root.join(layout.vkey_path()),
            wasm_path: source_root.join(layout.wasm_path()),
            dat_path: source_root.join(layout.dat_path()),
            source_root,
        }
    }
}

/// Capability for resolving canonical artifact layouts through a concrete source.
pub trait ArtifactSource {
    /// Source-specific error type.
    type Error;

    /// Resolves concrete source-local artifact paths for a canonical layout.
    ///
    /// # Errors
    ///
    /// Returns an error when the source cannot represent the requested layout.
    fn resolve(&self, layout: &ArtifactLayout) -> Result<ResolvedArtifactPaths, Self::Error>;
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::{ArtifactSource, LocalArtifactSource, resolve_standard_layout};

    #[test]
    fn local_source_resolves_concrete_paths_from_layout() {
        let Ok(source) = LocalArtifactSource::new(PathBuf::from("cache")) else {
            panic!("expected valid local source root");
        };
        let Ok(layout) = resolve_standard_layout(1, 1) else {
            panic!("expected supported standard shape 1x1");
        };
        let Ok(resolved) = source.resolve(&layout) else {
            panic!("expected local source to resolve canonical layout");
        };

        assert_eq!(resolved.source_root(), PathBuf::from("cache").as_path());
        assert_eq!(resolved.directory(), PathBuf::from("cache/artifacts-v2.1/01x01").as_path());
        assert_eq!(
            resolved.zkey_path(),
            PathBuf::from("cache/artifacts-v2.1/01x01/zkey").as_path()
        );
        assert_eq!(
            resolved.vkey_path(),
            PathBuf::from("cache/artifacts-v2.1/01x01/vkey.json").as_path()
        );
        assert_eq!(
            resolved.wasm_path(),
            PathBuf::from("cache/artifacts-v2.1/01x01/wasm").as_path()
        );
        assert_eq!(resolved.dat_path(), PathBuf::from("cache/artifacts-v2.1/01x01/dat").as_path());
    }
}
