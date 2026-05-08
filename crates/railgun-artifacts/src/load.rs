//! Typed local artifact loading helpers for prover consumers.

use std::{
    fs,
    path::{Path, PathBuf},
};

use serde_json::{Map, Value};

use crate::{ArtifactBackend, ArtifactError, ArtifactVariant, ResolvedArtifactPaths};

/// Parsed verification key JSON object loaded from `vkey.json`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationKeyJson {
    object: Map<String, Value>,
}

impl VerificationKeyJson {
    /// Parses a verification key from UTF-8 JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when the bytes are not valid JSON or the root is not a JSON object.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ArtifactError> {
        let value: Value =
            serde_json::from_slice(bytes).map_err(|_| ArtifactError::ArtifactVkeyParseFailed)?;
        Self::from_value(value)
    }

    /// Creates a verification key wrapper from a JSON value.
    ///
    /// # Errors
    ///
    /// Returns an error when the value is not a JSON object.
    pub fn from_value(value: Value) -> Result<Self, ArtifactError> {
        match value {
            Value::Object(object) => Ok(Self { object }),
            _ => Err(ArtifactError::ArtifactVkeyInvalidShape),
        }
    }

    /// Returns the verification key as a JSON object map.
    #[must_use]
    pub fn as_object(&self) -> &Map<String, Value> {
        &self.object
    }

    /// Returns the verification key as a JSON value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        Value::Object(self.object.clone())
    }
}

/// Local file paths for a loadable artifact bundle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadedArtifactPaths {
    zkey: PathBuf,
    vkey: PathBuf,
    wasm: Option<PathBuf>,
    dat: Option<PathBuf>,
}

impl LoadedArtifactPaths {
    /// Creates a new artifact path set.
    #[must_use]
    pub fn new(
        zkey_path: PathBuf,
        vkey_path: PathBuf,
        wasm_path: Option<PathBuf>,
        dat_path: Option<PathBuf>,
    ) -> Self {
        Self { zkey: zkey_path, vkey: vkey_path, wasm: wasm_path, dat: dat_path }
    }

    /// Creates artifact paths from resolved canonical layout paths and backend selection.
    #[must_use]
    pub fn from_resolved_paths(paths: &ResolvedArtifactPaths, backend: ArtifactBackend) -> Self {
        Self {
            zkey: paths.zkey_path().to_path_buf(),
            vkey: paths.vkey_path().to_path_buf(),
            wasm: backend.includes_wasm().then(|| paths.wasm_path().to_path_buf()),
            dat: backend.includes_dat().then(|| paths.dat_path().to_path_buf()),
        }
    }

    /// Returns the `zkey` path.
    #[must_use]
    pub fn zkey_path(&self) -> &Path {
        &self.zkey
    }

    /// Returns the `vkey.json` path.
    #[must_use]
    pub fn vkey_path(&self) -> &Path {
        &self.vkey
    }

    /// Returns the `wasm` path when selected.
    #[must_use]
    pub fn wasm_path(&self) -> Option<&Path> {
        self.wasm.as_deref()
    }

    /// Returns the `dat` path when selected.
    #[must_use]
    pub fn dat_path(&self) -> Option<&Path> {
        self.dat.as_deref()
    }
}

/// Loaded in-memory artifact bytes and parsed verification key data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadedArtifactFiles {
    zkey: Vec<u8>,
    vkey: VerificationKeyJson,
    wasm: Option<Vec<u8>>,
    dat: Option<Vec<u8>>,
}

impl LoadedArtifactFiles {
    /// Creates a loaded artifact file bundle.
    ///
    /// # Errors
    ///
    /// Returns an error when the selected backend artifact combination is unsupported.
    pub fn new(
        backend: ArtifactBackend,
        zkey: Vec<u8>,
        vkey: VerificationKeyJson,
        wasm: Option<Vec<u8>>,
        dat: Option<Vec<u8>>,
    ) -> Result<Self, ArtifactError> {
        validate_backend_combination(backend, wasm.as_ref(), dat.as_ref())?;
        Ok(Self { zkey, vkey, wasm, dat })
    }

    /// Returns the loaded `zkey` bytes.
    #[must_use]
    pub fn zkey(&self) -> &[u8] {
        &self.zkey
    }

    /// Returns the parsed verification key JSON object.
    #[must_use]
    pub fn vkey(&self) -> &VerificationKeyJson {
        &self.vkey
    }

    /// Returns the loaded `wasm` bytes when selected.
    #[must_use]
    pub fn wasm(&self) -> Option<&[u8]> {
        self.wasm.as_deref()
    }

    /// Returns the loaded `dat` bytes when selected.
    #[must_use]
    pub fn dat(&self) -> Option<&[u8]> {
        self.dat.as_deref()
    }
}

/// Prover-facing loaded artifact bundle with variant and backend metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadedArtifactBundle {
    variant: ArtifactVariant,
    backend: ArtifactBackend,
    paths: LoadedArtifactPaths,
    files: LoadedArtifactFiles,
}

impl LoadedArtifactBundle {
    /// Creates a loaded artifact bundle from typed parts.
    #[must_use]
    pub fn new(
        variant: ArtifactVariant,
        backend: ArtifactBackend,
        paths: LoadedArtifactPaths,
        files: LoadedArtifactFiles,
    ) -> Self {
        Self { variant, backend, paths, files }
    }

    /// Returns the loaded artifact variant.
    #[must_use]
    pub const fn variant(&self) -> ArtifactVariant {
        self.variant
    }

    /// Returns the selected backend metadata.
    #[must_use]
    pub const fn backend(&self) -> ArtifactBackend {
        self.backend
    }

    /// Returns the local source paths used for loading.
    #[must_use]
    pub fn paths(&self) -> &LoadedArtifactPaths {
        &self.paths
    }

    /// Returns the loaded in-memory files.
    #[must_use]
    pub fn files(&self) -> &LoadedArtifactFiles {
        &self.files
    }
}

/// Loads a typed artifact bundle from explicit local paths.
///
/// # Errors
///
/// Returns an error when a required file is missing or unreadable, the selected backend
/// artifact combination is unsupported, or `vkey.json` is malformed.
pub fn load_artifact_bundle(
    variant: ArtifactVariant,
    backend: ArtifactBackend,
    paths: LoadedArtifactPaths,
) -> Result<LoadedArtifactBundle, ArtifactError> {
    let zkey = read_required_file(paths.zkey_path())?;
    let vkey_bytes = read_required_file(paths.vkey_path())?;
    let vkey = VerificationKeyJson::from_bytes(&vkey_bytes)?;
    let wasm = read_optional_file(paths.wasm_path())?;
    let dat = read_optional_file(paths.dat_path())?;
    let files = LoadedArtifactFiles::new(backend, zkey, vkey, wasm, dat)?;

    Ok(LoadedArtifactBundle::new(variant, backend, paths, files))
}

/// Loads a typed artifact bundle from canonical resolved paths and backend selection.
///
/// # Errors
///
/// Returns an error when a required file is missing or unreadable, the selected backend
/// artifact combination is unsupported, or `vkey.json` is malformed.
pub fn load_artifact_bundle_from_resolved_paths(
    variant: ArtifactVariant,
    backend: ArtifactBackend,
    paths: &ResolvedArtifactPaths,
) -> Result<LoadedArtifactBundle, ArtifactError> {
    load_artifact_bundle(variant, backend, LoadedArtifactPaths::from_resolved_paths(paths, backend))
}

fn validate_backend_combination(
    backend: ArtifactBackend,
    wasm: Option<&Vec<u8>>,
    dat: Option<&Vec<u8>>,
) -> Result<(), ArtifactError> {
    match backend {
        ArtifactBackend::Wasm if wasm.is_none() => Err(ArtifactError::InvalidLoadedArtifactBundle(
            "wasm artifact bundle requires a wasm file",
        )),
        ArtifactBackend::Wasm if dat.is_some() => Err(ArtifactError::InvalidLoadedArtifactBundle(
            "wasm artifact bundle must not include dat; use ArtifactBackend::Both to load both",
        )),
        ArtifactBackend::Native if dat.is_none() => {
            Err(ArtifactError::InvalidLoadedArtifactBundle(
                "native artifact bundle requires a dat file",
            ))
        }
        ArtifactBackend::Native if wasm.is_some() => {
            Err(ArtifactError::InvalidLoadedArtifactBundle(
                "native artifact bundle must not include wasm; use ArtifactBackend::Both to load both",
            ))
        }
        ArtifactBackend::Both if wasm.is_none() || dat.is_none() => {
            Err(ArtifactError::InvalidLoadedArtifactBundle(
                "dual artifact bundle requires both wasm and dat files",
            ))
        }
        _ => Ok(()),
    }
}

fn read_required_file(path: &Path) -> Result<Vec<u8>, ArtifactError> {
    fs::read(path).map_err(|_| ArtifactError::ArtifactReadFailed { path: path.to_path_buf() })
}

fn read_optional_file(path: Option<&Path>) -> Result<Option<Vec<u8>>, ArtifactError> {
    path.map(read_required_file).transpose()
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use serde_json::json;

    use super::{
        LoadedArtifactFiles, LoadedArtifactPaths, VerificationKeyJson, load_artifact_bundle,
        load_artifact_bundle_from_resolved_paths,
    };
    use crate::{
        ArtifactBackend, ArtifactError, ArtifactSource, LocalArtifactSource, resolve_poi_variant,
        resolve_standard_layout, resolve_standard_variant,
    };

    fn temp_dir_path(test_name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| panic!("system time should be after unix epoch"))
            .as_nanos();
        std::env::temp_dir().join(format!("railgun-artifacts-load-{test_name}-{nanos}"))
    }

    fn write_file(directory: &PathBuf, name: &str, contents: &[u8]) -> PathBuf {
        fs::create_dir_all(directory)
            .unwrap_or_else(|_| panic!("test temp directory should be creatable"));
        let path = directory.join(name);
        fs::write(&path, contents).unwrap_or_else(|_| panic!("test file should be writable"));
        path
    }

    #[test]
    fn loads_standard_artifact_bundle_from_paths() {
        let directory = temp_dir_path("standard-paths");
        let paths = LoadedArtifactPaths::new(
            write_file(&directory, "zkey", b"zkey"),
            write_file(&directory, "vkey.json", br#"{"protocol":"groth16"}"#),
            Some(write_file(&directory, "wasm", b"wasm")),
            None,
        );
        let Ok(variant) = resolve_standard_variant(1, 1) else {
            panic!("expected supported standard shape 1x1");
        };

        let Ok(bundle) = load_artifact_bundle(variant, ArtifactBackend::Wasm, paths.clone()) else {
            panic!("expected standard wasm bundle to load");
        };

        assert_eq!(bundle.variant(), variant);
        assert_eq!(bundle.backend(), ArtifactBackend::Wasm);
        assert_eq!(bundle.paths(), &paths);
        assert_eq!(bundle.files().zkey(), b"zkey");
        assert_eq!(bundle.files().wasm(), Some(&b"wasm"[..]));
        assert!(bundle.files().dat().is_none());
        assert_eq!(bundle.files().vkey().as_object().get("protocol"), Some(&json!("groth16")));

        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn loads_poi_artifact_bundle_from_resolved_paths() {
        let root = temp_dir_path("poi-resolved");
        let Ok(source) = LocalArtifactSource::new(root.clone()) else {
            panic!("expected local source root to be valid");
        };
        let Ok(layout) = crate::resolve_poi_layout(3, 3) else {
            panic!("expected supported POI layout 3x3");
        };
        let Ok(resolved_paths) = source.resolve(&layout) else {
            panic!("expected resolved local artifact paths");
        };

        fs::create_dir_all(resolved_paths.directory())
            .unwrap_or_else(|_| panic!("expected resolved directory to be creatable"));
        fs::write(resolved_paths.zkey_path(), b"zkey")
            .unwrap_or_else(|_| panic!("expected zkey write"));
        fs::write(resolved_paths.vkey_path(), br#"{"curve":"bn254"}"#)
            .unwrap_or_else(|_| panic!("expected vkey write"));
        fs::write(resolved_paths.wasm_path(), b"wasm")
            .unwrap_or_else(|_| panic!("expected wasm write"));
        fs::write(resolved_paths.dat_path(), b"dat")
            .unwrap_or_else(|_| panic!("expected dat write"));

        let Ok(variant) = resolve_poi_variant(3, 3) else {
            panic!("expected supported poi shape 3x3");
        };
        let Ok(bundle) = load_artifact_bundle_from_resolved_paths(
            variant,
            ArtifactBackend::Both,
            &resolved_paths,
        ) else {
            panic!("expected POI dual backend bundle to load");
        };

        assert_eq!(bundle.variant(), variant);
        assert_eq!(bundle.backend(), ArtifactBackend::Both);
        assert_eq!(bundle.files().wasm(), Some(&b"wasm"[..]));
        assert_eq!(bundle.files().dat(), Some(&b"dat"[..]));
        assert_eq!(bundle.files().vkey().as_object().get("curve"), Some(&json!("bn254")));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn rejects_missing_required_local_file() {
        let directory = temp_dir_path("missing-file");
        let paths = LoadedArtifactPaths::new(
            directory.join("missing-zkey"),
            directory.join("vkey.json"),
            Some(directory.join("wasm")),
            None,
        );
        let Ok(variant) = resolve_standard_variant(1, 1) else {
            panic!("expected supported standard shape 1x1");
        };

        let Err(error) = load_artifact_bundle(variant, ArtifactBackend::Wasm, paths) else {
            panic!("expected missing zkey to fail");
        };

        match error {
            ArtifactError::ArtifactReadFailed { path } => {
                assert_eq!(path, directory.join("missing-zkey"));
            }
            _ => panic!("expected artifact read failure"),
        }
    }

    #[test]
    fn rejects_invalid_vkey_json_parse() {
        let directory = temp_dir_path("invalid-vkey-parse");
        let paths = LoadedArtifactPaths::new(
            write_file(&directory, "zkey", b"zkey"),
            write_file(&directory, "vkey.json", b"not-json"),
            Some(write_file(&directory, "wasm", b"wasm")),
            None,
        );
        let Ok(variant) = resolve_standard_variant(1, 1) else {
            panic!("expected supported standard shape 1x1");
        };

        let Err(error) = load_artifact_bundle(variant, ArtifactBackend::Wasm, paths) else {
            panic!("expected invalid vkey json to fail");
        };

        assert_eq!(error, ArtifactError::ArtifactVkeyParseFailed);

        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn rejects_non_object_vkey_json() {
        let directory = temp_dir_path("invalid-vkey-shape");
        let paths = LoadedArtifactPaths::new(
            write_file(&directory, "zkey", b"zkey"),
            write_file(&directory, "vkey.json", b"[1,2,3]"),
            Some(write_file(&directory, "wasm", b"wasm")),
            None,
        );
        let Ok(variant) = resolve_standard_variant(1, 1) else {
            panic!("expected supported standard shape 1x1");
        };

        let Err(error) = load_artifact_bundle(variant, ArtifactBackend::Wasm, paths) else {
            panic!("expected non-object vkey to fail");
        };

        assert_eq!(error, ArtifactError::ArtifactVkeyInvalidShape);

        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn rejects_unsupported_backend_combination() {
        let Ok(vkey) = VerificationKeyJson::from_value(json!({"protocol":"groth16"})) else {
            panic!("expected object vkey to parse");
        };

        let Err(error) = LoadedArtifactFiles::new(
            ArtifactBackend::Wasm,
            b"zkey".to_vec(),
            vkey,
            Some(b"wasm".to_vec()),
            Some(b"dat".to_vec()),
        ) else {
            panic!("expected extra dat file to be rejected for wasm backend");
        };

        assert_eq!(
            error,
            ArtifactError::InvalidLoadedArtifactBundle(
                "wasm artifact bundle must not include dat; use ArtifactBackend::Both to load both"
            )
        );
    }

    #[test]
    fn loads_standard_layout_paths_for_native_backend() {
        let root = temp_dir_path("standard-native-resolved");
        let Ok(source) = LocalArtifactSource::new(root.clone()) else {
            panic!("expected local source root to be valid");
        };
        let Ok(layout) = resolve_standard_layout(1, 1) else {
            panic!("expected supported standard layout");
        };
        let Ok(resolved_paths) = source.resolve(&layout) else {
            panic!("expected resolved local artifact paths");
        };

        fs::create_dir_all(resolved_paths.directory())
            .unwrap_or_else(|_| panic!("expected resolved directory to be creatable"));
        fs::write(resolved_paths.zkey_path(), b"zkey")
            .unwrap_or_else(|_| panic!("expected zkey write"));
        fs::write(resolved_paths.vkey_path(), br#"{"curve":"bn254"}"#)
            .unwrap_or_else(|_| panic!("expected vkey write"));
        fs::write(resolved_paths.dat_path(), b"dat")
            .unwrap_or_else(|_| panic!("expected dat write"));

        let Ok(variant) = resolve_standard_variant(1, 1) else {
            panic!("expected supported standard shape 1x1");
        };
        let Ok(bundle) = load_artifact_bundle_from_resolved_paths(
            variant,
            ArtifactBackend::Native,
            &resolved_paths,
        ) else {
            panic!("expected native bundle to load");
        };

        assert_eq!(bundle.files().dat(), Some(&b"dat"[..]));
        assert!(bundle.files().wasm().is_none());

        let _ = fs::remove_dir_all(root);
    }
}
