//! Local filesystem artifact source.

use std::path::PathBuf;

use crate::{ArtifactError, ArtifactLayout, ArtifactSource, ResolvedArtifactPaths};

/// Local filesystem-backed artifact source rooted at a caller-provided directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalArtifactSource {
    root: PathBuf,
}

impl LocalArtifactSource {
    /// Creates a local artifact source rooted at the provided directory.
    ///
    /// # Errors
    ///
    /// Returns an error when the provided root path is empty.
    pub fn new(root: PathBuf) -> Result<Self, ArtifactError> {
        if root.as_os_str().is_empty() {
            Err(ArtifactError::InvalidSourceConfiguration(
                "local artifact source root must not be empty",
            ))
        } else {
            Ok(Self { root })
        }
    }

    /// Returns the configured source root.
    #[must_use]
    pub fn root(&self) -> &std::path::Path {
        &self.root
    }
}

impl ArtifactSource for LocalArtifactSource {
    type Error = ArtifactError;

    fn resolve(&self, layout: &ArtifactLayout) -> Result<ResolvedArtifactPaths, Self::Error> {
        Ok(ResolvedArtifactPaths::new(self.root.clone(), layout))
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::{ArtifactError, LocalArtifactSource};

    #[test]
    fn rejects_empty_root_configuration() {
        let Err(error) = LocalArtifactSource::new(PathBuf::new()) else {
            panic!("expected empty local root to be rejected");
        };
        assert_eq!(
            error,
            ArtifactError::InvalidSourceConfiguration(
                "local artifact source root must not be empty"
            )
        );
    }

    #[test]
    fn accepts_non_empty_root_configuration() {
        let Ok(source) = LocalArtifactSource::new(PathBuf::from("artifacts")) else {
            panic!("expected non-empty local root to be accepted");
        };
        assert_eq!(source.root(), PathBuf::from("artifacts").as_path());
    }
}
