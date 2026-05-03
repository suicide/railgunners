//! Offline local artifact verification helpers.

use std::{
    fs,
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};

use crate::{ArtifactError, ArtifactFileKind, ArtifactVariant, canonical_artifact_hashes};

/// Per-file local verification result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactFileVerification {
    kind: ArtifactFileKind,
    path: PathBuf,
    expected_hash: String,
    actual_hash: String,
    ok: bool,
}

impl ArtifactFileVerification {
    /// Returns the verified file kind.
    #[must_use]
    pub const fn kind(&self) -> ArtifactFileKind {
        self.kind
    }

    /// Returns the verified local file path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the expected SHA-256 hash.
    #[must_use]
    pub fn expected_hash(&self) -> &str {
        &self.expected_hash
    }

    /// Returns the actual SHA-256 hash computed from disk.
    #[must_use]
    pub fn actual_hash(&self) -> &str {
        &self.actual_hash
    }

    /// Returns whether the local file matched the canonical expected hash.
    #[must_use]
    pub const fn ok(&self) -> bool {
        self.ok
    }
}

/// The set of per-file verification results returned for a variant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactVerificationFiles {
    zkey: ArtifactFileVerification,
    wasm: Option<ArtifactFileVerification>,
    dat: Option<ArtifactFileVerification>,
}

impl ArtifactVerificationFiles {
    /// Returns the `zkey` verification result.
    #[must_use]
    pub fn zkey(&self) -> &ArtifactFileVerification {
        &self.zkey
    }

    /// Returns the `wasm` verification result when provided.
    #[must_use]
    pub fn wasm(&self) -> Option<&ArtifactFileVerification> {
        self.wasm.as_ref()
    }

    /// Returns the `dat` verification result when provided.
    #[must_use]
    pub fn dat(&self) -> Option<&ArtifactFileVerification> {
        self.dat.as_ref()
    }
}

/// Aggregate offline verification result for a local artifact set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactVerificationResult {
    variant: ArtifactVariant,
    files: ArtifactVerificationFiles,
    ok: bool,
}

impl ArtifactVerificationResult {
    /// Returns the verified artifact variant.
    #[must_use]
    pub const fn variant(&self) -> ArtifactVariant {
        self.variant
    }

    /// Returns the per-file verification results.
    #[must_use]
    pub fn files(&self) -> &ArtifactVerificationFiles {
        &self.files
    }

    /// Returns whether every provided file matched the canonical expected hash.
    #[must_use]
    pub const fn ok(&self) -> bool {
        self.ok
    }
}

/// Verifies a single local artifact file against the canonical hash catalog.
///
/// # Errors
///
/// Returns an error when the local file cannot be read or the variant is not in the
/// canonical hash catalog.
pub fn verify_artifact_file(
    kind: ArtifactFileKind,
    variant: &ArtifactVariant,
    path: &Path,
) -> Result<ArtifactFileVerification, ArtifactError> {
    let hashes = canonical_artifact_hashes(variant)?;
    let bytes = fs::read(path)
        .map_err(|_| ArtifactError::ArtifactReadFailed { path: path.to_path_buf() })?;

    let expected_hash = hashes.expected_hash(kind).to_owned();
    let actual_hash = sha256_hex(&bytes);

    Ok(ArtifactFileVerification {
        kind,
        path: path.to_path_buf(),
        expected_hash: expected_hash.clone(),
        ok: actual_hash == expected_hash,
        actual_hash,
    })
}

/// Verifies a local artifact set against the canonical hash catalog.
///
/// # Errors
///
/// Returns an error when the input is incomplete, a local file cannot be read, or the
/// variant is not present in the canonical hash catalog.
pub fn verify_local_artifacts(
    variant: &ArtifactVariant,
    zkey: &Path,
    wasm: Option<&Path>,
    dat: Option<&Path>,
) -> Result<ArtifactVerificationResult, ArtifactError> {
    if wasm.is_none() && dat.is_none() {
        return Err(ArtifactError::InvalidVerificationInput(
            "artifact verification requires at least one of --wasm or --dat",
        ));
    }

    let zkey = verify_artifact_file(ArtifactFileKind::Zkey, variant, zkey)?;
    let wasm =
        wasm.map(|path| verify_artifact_file(ArtifactFileKind::Wasm, variant, path)).transpose()?;
    let dat =
        dat.map(|path| verify_artifact_file(ArtifactFileKind::Dat, variant, path)).transpose()?;

    let ok = zkey.ok()
        && wasm.as_ref().is_none_or(ArtifactFileVerification::ok)
        && dat.as_ref().is_none_or(ArtifactFileVerification::ok);

    Ok(ArtifactVerificationResult {
        variant: *variant,
        files: ArtifactVerificationFiles { zkey, wasm, dat },
        ok,
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use core::fmt::Write as _;
        let _ = write!(&mut encoded, "{byte:02x}");
    }
    encoded
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::{ArtifactFileVerification, sha256_hex, verify_local_artifacts};
    use crate::{ArtifactError, resolve_standard_variant};

    fn temp_dir_path(test_name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| panic!("system time should be after unix epoch"))
            .as_nanos();
        std::env::temp_dir().join(format!("railgun-artifacts-{test_name}-{nanos}"))
    }

    fn write_file(directory: &Path, name: &str, contents: &[u8]) -> PathBuf {
        fs::create_dir_all(directory)
            .unwrap_or_else(|_| panic!("test temp directory should be creatable"));
        let path = directory.join(name);
        fs::write(&path, contents).unwrap_or_else(|_| panic!("test file should be writable"));
        path
    }

    #[test]
    fn rejects_missing_backend_paths() {
        let Ok(variant) = resolve_standard_variant(1, 1) else {
            panic!("expected supported standard shape 1x1");
        };

        let Err(error) = verify_local_artifacts(&variant, Path::new("/tmp/zkey"), None, None)
        else {
            panic!("expected missing backend inputs to fail");
        };

        assert_eq!(
            error,
            ArtifactError::InvalidVerificationInput(
                "artifact verification requires at least one of --wasm or --dat"
            )
        );
    }

    #[test]
    fn reports_missing_local_file() {
        let Ok(variant) = resolve_standard_variant(1, 1) else {
            panic!("expected supported standard shape 1x1");
        };

        let Err(error) = verify_local_artifacts(
            &variant,
            Path::new("/tmp/missing-zkey"),
            Some(Path::new("/tmp/missing-wasm")),
            None,
        ) else {
            panic!("expected missing local file to fail");
        };

        match error {
            ArtifactError::ArtifactReadFailed { path } => {
                assert_eq!(path, PathBuf::from("/tmp/missing-zkey"));
            }
            _ => panic!("expected artifact read failure"),
        }
    }

    #[test]
    fn returns_structured_mismatch_results_for_canonical_catalog() {
        let directory = temp_dir_path("mismatch");
        let zkey_path = write_file(&directory, "zkey", b"wrong zkey");
        let wasm_path = write_file(&directory, "wasm", b"wrong wasm");

        let Ok(variant) = resolve_standard_variant(1, 1) else {
            panic!("expected supported standard shape 1x1");
        };
        let Ok(result) = verify_local_artifacts(&variant, &zkey_path, Some(&wasm_path), None)
        else {
            panic!("expected mismatch verification to return structured result");
        };

        assert!(!result.ok());
        assert!(!result.files().zkey().ok());
        assert_eq!(result.files().wasm().map(ArtifactFileVerification::ok), Some(false));
        assert!(result.files().dat().is_none());

        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn sha256_hex_matches_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
