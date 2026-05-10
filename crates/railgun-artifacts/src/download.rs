//! Optional canonical artifact download and cache helpers.

use std::{
    fs,
    io::{Cursor, Read, Write},
    path::{Path, PathBuf},
};

use tempfile::NamedTempFile;

use crate::{
    ArtifactBackend, ArtifactError, ArtifactFileKind, ArtifactSource, ArtifactVariant,
    ArtifactVerificationResult, LocalArtifactSource, ResolvedArtifactPaths,
    resolve_artifact_layout, verify_local_artifacts,
};

const DEFAULT_GATEWAY_BASE_URL: &str = "https://ipfs-lb.com";
const DEFAULT_STANDARD_CID: &str = "QmUsmnK4PFc7zDp2cmC4wBZxYLjNyRgWfs5GNcJJ2uLcpU";
const DEFAULT_POI_CID: &str = "QmZrP9zaZw2LwErT2yA6VpMWm65UdToQiKj4DtStVsUJHr";

/// Remote artifact source configuration for canonical downloads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactRemoteSource {
    gateway_base_url: String,
    standard_cid: String,
    poi_cid: String,
}

impl ArtifactRemoteSource {
    /// Creates a remote source configuration.
    ///
    /// # Errors
    ///
    /// Returns an error when any required field is empty.
    pub fn new(
        gateway_base_url: &str,
        standard_cid: &str,
        poi_cid: &str,
    ) -> Result<Self, ArtifactError> {
        if gateway_base_url.trim().is_empty() {
            return Err(ArtifactError::InvalidDownloadConfiguration(
                "artifact gateway base URL must not be empty",
            ));
        }
        if standard_cid.trim().is_empty() {
            return Err(ArtifactError::InvalidDownloadConfiguration(
                "standard artifact CID must not be empty",
            ));
        }
        if poi_cid.trim().is_empty() {
            return Err(ArtifactError::InvalidDownloadConfiguration(
                "POI artifact CID must not be empty",
            ));
        }

        Ok(Self {
            gateway_base_url: gateway_base_url.trim_end_matches('/').to_owned(),
            standard_cid: standard_cid.to_owned(),
            poi_cid: poi_cid.to_owned(),
        })
    }

    /// Returns the canonical default IPFS source configuration.
    #[must_use]
    pub fn canonical() -> Self {
        Self {
            gateway_base_url: DEFAULT_GATEWAY_BASE_URL.to_owned(),
            standard_cid: DEFAULT_STANDARD_CID.to_owned(),
            poi_cid: DEFAULT_POI_CID.to_owned(),
        }
    }

    /// Returns the configured gateway base URL.
    #[must_use]
    pub fn gateway_base_url(&self) -> &str {
        &self.gateway_base_url
    }

    /// Returns the configured standard artifact CID.
    #[must_use]
    pub fn standard_cid(&self) -> &str {
        &self.standard_cid
    }

    /// Returns the configured POI artifact CID.
    #[must_use]
    pub fn poi_cid(&self) -> &str {
        &self.poi_cid
    }

    /// Resolves canonical remote URLs for a variant and backend selection.
    #[must_use]
    pub fn resolve_urls(
        &self,
        variant: &ArtifactVariant,
        backend: ArtifactBackend,
    ) -> ArtifactRemoteUrls {
        let variant_string = variant.to_string();
        let cid = if matches!(variant.family(), crate::CircuitFamily::Poi) {
            self.poi_cid()
        } else {
            self.standard_cid()
        };
        let base = format!("{}/ipfs/{cid}/", self.gateway_base_url());

        match variant.family() {
            crate::CircuitFamily::Standard => ArtifactRemoteUrls {
                zkey: format!("{base}circuits/{variant_string}/zkey.br"),
                vkey: format!("{base}circuits/{variant_string}/vkey.json"),
                wasm: backend
                    .includes_wasm()
                    .then(|| format!("{base}prover/snarkjs/{variant_string}.wasm.br")),
                dat: backend
                    .includes_dat()
                    .then(|| format!("{base}prover/native/{variant_string}.dat.br")),
            },
            crate::CircuitFamily::Poi => ArtifactRemoteUrls {
                zkey: format!("{base}{variant_string}/zkey.br"),
                vkey: format!("{base}{variant_string}/vkey.json"),
                wasm: backend.includes_wasm().then(|| format!("{base}{variant_string}/wasm.br")),
                dat: backend.includes_dat().then(|| format!("{base}{variant_string}/dat.br")),
            },
        }
    }
}

/// Canonical remote URLs for all files involved in one download request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactRemoteUrls {
    zkey: String,
    vkey: String,
    wasm: Option<String>,
    dat: Option<String>,
}

impl ArtifactRemoteUrls {
    /// Returns the canonical `zkey.br` URL.
    #[must_use]
    pub fn zkey_url(&self) -> &str {
        &self.zkey
    }

    /// Returns the canonical `vkey.json` URL.
    #[must_use]
    pub fn vkey_url(&self) -> &str {
        &self.vkey
    }

    /// Returns the canonical `wasm.br` URL when requested.
    #[must_use]
    pub fn wasm_url(&self) -> Option<&str> {
        self.wasm.as_deref()
    }

    /// Returns the canonical `dat.br` URL when requested.
    #[must_use]
    pub fn dat_url(&self) -> Option<&str> {
        self.dat.as_deref()
    }
}

/// Download configuration for populating the local canonical artifact cache.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactDownloadConfig {
    remote_source: ArtifactRemoteSource,
    cache_root: PathBuf,
}

impl ArtifactDownloadConfig {
    /// Creates a download configuration with an explicit remote source and cache root.
    ///
    /// # Errors
    ///
    /// Returns an error when the cache root is empty.
    pub fn new(
        remote_source: ArtifactRemoteSource,
        cache_root: PathBuf,
    ) -> Result<Self, ArtifactError> {
        if cache_root.as_os_str().is_empty() {
            return Err(ArtifactError::InvalidDownloadConfiguration(
                "artifact cache root must not be empty",
            ));
        }

        Ok(Self { remote_source, cache_root })
    }

    /// Creates a download configuration using the canonical IPFS defaults.
    ///
    /// # Errors
    ///
    /// Returns an error when the cache root is empty.
    pub fn canonical(cache_root: PathBuf) -> Result<Self, ArtifactError> {
        Self::new(ArtifactRemoteSource::canonical(), cache_root)
    }

    /// Returns the configured remote source.
    #[must_use]
    pub fn remote_source(&self) -> &ArtifactRemoteSource {
        &self.remote_source
    }

    /// Returns the configured local cache root.
    #[must_use]
    pub fn cache_root(&self) -> &Path {
        &self.cache_root
    }
}

/// Concrete local cache files produced by one download request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DownloadedArtifactFiles {
    directory: PathBuf,
    zkey_path: PathBuf,
    vkey_path: PathBuf,
    wasm_path: Option<PathBuf>,
    dat_path: Option<PathBuf>,
}

impl DownloadedArtifactFiles {
    /// Returns the canonical cache directory for the downloaded variant.
    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// Returns the cached `zkey` path.
    #[must_use]
    pub fn zkey_path(&self) -> &Path {
        &self.zkey_path
    }

    /// Returns the cached `vkey.json` path.
    #[must_use]
    pub fn vkey_path(&self) -> &Path {
        &self.vkey_path
    }

    /// Returns the cached `wasm` path when requested.
    #[must_use]
    pub fn wasm_path(&self) -> Option<&Path> {
        self.wasm_path.as_deref()
    }

    /// Returns the cached `dat` path when requested.
    #[must_use]
    pub fn dat_path(&self) -> Option<&Path> {
        self.dat_path.as_deref()
    }

    fn from_resolved_paths(paths: &ResolvedArtifactPaths, backend: ArtifactBackend) -> Self {
        Self {
            directory: paths.directory().to_path_buf(),
            zkey_path: paths.zkey_path().to_path_buf(),
            vkey_path: paths.vkey_path().to_path_buf(),
            wasm_path: backend.includes_wasm().then(|| paths.wasm_path().to_path_buf()),
            dat_path: backend.includes_dat().then(|| paths.dat_path().to_path_buf()),
        }
    }
}

/// Final result for a verified artifact download.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactDownloadResult {
    variant: ArtifactVariant,
    files: DownloadedArtifactFiles,
    verification: ArtifactVerificationResult,
}

impl ArtifactDownloadResult {
    /// Returns the downloaded artifact variant.
    #[must_use]
    pub const fn variant(&self) -> ArtifactVariant {
        self.variant
    }

    /// Returns the cached local files.
    #[must_use]
    pub fn files(&self) -> &DownloadedArtifactFiles {
        &self.files
    }

    /// Returns the verification result for the cached files.
    #[must_use]
    pub fn verification(&self) -> &ArtifactVerificationResult {
        &self.verification
    }
}

/// Downloads, decompresses, verifies, and caches canonical artifacts locally.
///
/// # Errors
///
/// Returns an error when download configuration is invalid, a remote fetch fails,
/// Brotli decompression fails, canonical verification fails, or the cache cannot be
/// written safely.
pub fn download_artifacts(
    variant: &ArtifactVariant,
    backend: ArtifactBackend,
    config: &ArtifactDownloadConfig,
) -> Result<ArtifactDownloadResult, ArtifactError> {
    download_artifacts_with(*variant, backend, config, |variant, zkey, wasm, dat| {
        verify_local_artifacts(&variant, zkey, wasm, dat)
    })
}

fn download_artifacts_with<F>(
    variant: ArtifactVariant,
    backend: ArtifactBackend,
    config: &ArtifactDownloadConfig,
    verifier: F,
) -> Result<ArtifactDownloadResult, ArtifactError>
where
    F: Fn(
        ArtifactVariant,
        &Path,
        Option<&Path>,
        Option<&Path>,
    ) -> Result<ArtifactVerificationResult, ArtifactError>,
{
    let layout = resolve_artifact_layout(&variant);
    let source = LocalArtifactSource::new(config.cache_root.clone())?;
    let paths = source.resolve(&layout)?;
    fs::create_dir_all(paths.directory()).map_err(|_| ArtifactError::ArtifactCacheWriteFailed {
        path: paths.directory().to_path_buf(),
    })?;

    let urls = config.remote_source.resolve_urls(&variant, backend);
    let temp_files = download_into_temp_files(&paths, &urls, backend)?;

    let verification = verifier(
        variant,
        temp_files.zkey.path(),
        temp_files.wasm.as_ref().map(NamedTempFile::path),
        temp_files.dat.as_ref().map(NamedTempFile::path),
    )?;
    ensure_verification_passed(&verification)?;

    persist_downloaded_files(temp_files, &paths, backend)?;
    let files = DownloadedArtifactFiles::from_resolved_paths(&paths, backend);

    Ok(ArtifactDownloadResult { variant, files, verification })
}

struct TempDownloadedFiles {
    zkey: NamedTempFile,
    vkey: NamedTempFile,
    wasm: Option<NamedTempFile>,
    dat: Option<NamedTempFile>,
}

fn download_into_temp_files(
    paths: &ResolvedArtifactPaths,
    urls: &ArtifactRemoteUrls,
    backend: ArtifactBackend,
) -> Result<TempDownloadedFiles, ArtifactError> {
    let zkey = download_compressed_file(
        ArtifactFileKind::Zkey,
        urls.zkey_url(),
        paths.zkey_path(),
        paths.directory(),
    )?;
    let vkey = download_uncompressed_file(urls.vkey_url(), paths.vkey_path(), paths.directory())?;
    let wasm = if backend.includes_wasm() {
        let wasm_url = urls.wasm_url().ok_or(ArtifactError::InvalidDownloadConfiguration(
            "artifact backend requires a wasm download URL",
        ))?;
        Some(download_compressed_file(
            ArtifactFileKind::Wasm,
            wasm_url,
            paths.wasm_path(),
            paths.directory(),
        )?)
    } else {
        None
    };
    let dat = if backend.includes_dat() {
        let dat_url = urls.dat_url().ok_or(ArtifactError::InvalidDownloadConfiguration(
            "artifact backend requires a dat download URL",
        ))?;
        Some(download_compressed_file(
            ArtifactFileKind::Dat,
            dat_url,
            paths.dat_path(),
            paths.directory(),
        )?)
    } else {
        None
    };

    Ok(TempDownloadedFiles { zkey, vkey, wasm, dat })
}

fn download_uncompressed_file(
    url: &str,
    target_path: &Path,
    directory: &Path,
) -> Result<NamedTempFile, ArtifactError> {
    let bytes = fetch_url_bytes(url)?;
    write_temp_file(directory, target_path, &bytes)
}

fn download_compressed_file(
    kind: ArtifactFileKind,
    url: &str,
    target_path: &Path,
    directory: &Path,
) -> Result<NamedTempFile, ArtifactError> {
    let bytes = fetch_url_bytes(url)?;
    let decompressed = decompress_brotli(kind, &bytes)?;
    write_temp_file(directory, target_path, &decompressed)
}

fn fetch_url_bytes(url: &str) -> Result<Vec<u8>, ArtifactError> {
    let mut response = ureq::get(url).call().map_err(|error| map_download_error(url, &error))?;
    let mut bytes = Vec::new();
    response.body_mut().as_reader().read_to_end(&mut bytes).map_err(|_| {
        ArtifactError::ArtifactDownloadFailed { url: url.to_owned(), status_code: None }
    })?;
    Ok(bytes)
}

fn map_download_error(url: &str, error: &ureq::Error) -> ArtifactError {
    match error {
        ureq::Error::StatusCode(status_code) => ArtifactError::ArtifactDownloadFailed {
            url: url.to_owned(),
            status_code: Some(*status_code),
        },
        _ => ArtifactError::ArtifactDownloadFailed { url: url.to_owned(), status_code: None },
    }
}

fn decompress_brotli(kind: ArtifactFileKind, compressed: &[u8]) -> Result<Vec<u8>, ArtifactError> {
    let mut decompressed = Vec::new();
    let mut reader = brotli::Decompressor::new(Cursor::new(compressed), 4096);
    reader
        .read_to_end(&mut decompressed)
        .map_err(|_| ArtifactError::ArtifactDecompressionFailed { kind })?;
    Ok(decompressed)
}

fn write_temp_file(
    directory: &Path,
    target_path: &Path,
    bytes: &[u8],
) -> Result<NamedTempFile, ArtifactError> {
    let mut temp_file = NamedTempFile::new_in(directory)
        .map_err(|_| ArtifactError::ArtifactCacheWriteFailed { path: target_path.to_path_buf() })?;
    temp_file
        .write_all(bytes)
        .map_err(|_| ArtifactError::ArtifactCacheWriteFailed { path: target_path.to_path_buf() })?;
    temp_file
        .flush()
        .map_err(|_| ArtifactError::ArtifactCacheWriteFailed { path: target_path.to_path_buf() })?;
    Ok(temp_file)
}

fn ensure_verification_passed(
    verification: &ArtifactVerificationResult,
) -> Result<(), ArtifactError> {
    if verification.ok() {
        return Ok(());
    }

    for file in
        [Some(verification.files().zkey()), verification.files().wasm(), verification.files().dat()]
            .into_iter()
            .flatten()
    {
        if !file.ok() {
            return Err(ArtifactError::ArtifactVerificationFailed {
                kind: file.kind(),
                path: file.path().to_path_buf(),
                expected_hash: file.expected_hash().to_owned(),
                actual_hash: file.actual_hash().to_owned(),
            });
        }
    }

    Err(ArtifactError::InvalidVerificationInput(
        "artifact verification failed without a mismatched file result",
    ))
}

fn persist_downloaded_files(
    temp_files: TempDownloadedFiles,
    paths: &ResolvedArtifactPaths,
    backend: ArtifactBackend,
) -> Result<(), ArtifactError> {
    persist_one(temp_files.zkey, paths.zkey_path())?;
    persist_one(temp_files.vkey, paths.vkey_path())?;

    if backend.includes_wasm() {
        let wasm = temp_files.wasm.ok_or(ArtifactError::InvalidDownloadConfiguration(
            "artifact backend requires a downloaded wasm file",
        ))?;
        persist_one(wasm, paths.wasm_path())?;
    }
    if backend.includes_dat() {
        let dat = temp_files.dat.ok_or(ArtifactError::InvalidDownloadConfiguration(
            "artifact backend requires a downloaded dat file",
        ))?;
        persist_one(dat, paths.dat_path())?;
    }

    Ok(())
}

fn persist_one(temp_file: NamedTempFile, destination: &Path) -> Result<(), ArtifactError> {
    if destination.exists() {
        fs::remove_file(destination).map_err(|_| ArtifactError::ArtifactCacheWriteFailed {
            path: destination.to_path_buf(),
        })?;
    }

    temp_file
        .persist(destination)
        .map_err(|_| ArtifactError::ArtifactCacheWriteFailed { path: destination.to_path_buf() })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        fs,
        io::{Read, Write},
        net::TcpListener,
        path::{Path, PathBuf},
        sync::Arc,
        thread,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::{
        ArtifactBackend, ArtifactDownloadConfig, ArtifactRemoteSource, download_artifacts,
        download_artifacts_with,
    };
    use crate::{
        ArtifactError, ArtifactFileKind, ArtifactFileVerification, ArtifactVerificationFiles,
        ArtifactVerificationResult, resolve_poi_variant, resolve_standard_variant,
    };

    struct MockResponse {
        status_line: &'static str,
        body: Vec<u8>,
        content_type: &'static str,
    }

    fn temp_dir_path(test_name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| panic!("system time should be after unix epoch"))
            .as_nanos();
        std::env::temp_dir().join(format!("railgun-artifacts-download-{test_name}-{nanos}"))
    }

    fn compress(bytes: &[u8]) -> Vec<u8> {
        let mut writer = brotli::CompressorWriter::new(Vec::new(), 4096, 5, 22);
        writer
            .write_all(bytes)
            .unwrap_or_else(|_| panic!("brotli test compression should succeed"));
        writer.into_inner()
    }

    fn start_server(
        responses: BTreeMap<String, MockResponse>,
        expected_requests: usize,
    ) -> (String, thread::JoinHandle<()>) {
        let listener =
            TcpListener::bind("127.0.0.1:0").unwrap_or_else(|_| panic!("test server should bind"));
        let address = format!(
            "http://{}",
            listener
                .local_addr()
                .unwrap_or_else(|_| panic!("test server should expose local address"))
        );
        let responses = Arc::new(responses);

        let handle = thread::spawn(move || {
            for _ in 0..expected_requests {
                let Ok((mut stream, _)) = listener.accept() else {
                    panic!("test server should accept connection");
                };

                let mut request = [0_u8; 4096];
                let read = stream
                    .read(&mut request)
                    .unwrap_or_else(|_| panic!("test server should read request"));
                let request_line = String::from_utf8_lossy(&request[..read]);
                let path = request_line
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("/");

                let fallback = MockResponse {
                    status_line: "404 Not Found",
                    body: b"missing".to_vec(),
                    content_type: "text/plain",
                };
                let response = responses.get(path).unwrap_or(&fallback);

                write!(
                    stream,
                    "HTTP/1.1 {}\r\nContent-Length: {}\r\nContent-Type: {}\r\nConnection: close\r\n\r\n",
                    response.status_line,
                    response.body.len(),
                    response.content_type
                )
                .unwrap_or_else(|_| panic!("test server should write headers"));
                stream
                    .write_all(&response.body)
                    .unwrap_or_else(|_| panic!("test server should write body"));
            }
        });

        (address, handle)
    }

    fn ok_verification_result(
        variant: crate::ArtifactVariant,
        zkey_path: &Path,
        wasm_path: Option<&Path>,
        dat_path: Option<&Path>,
    ) -> ArtifactVerificationResult {
        let zkey = ArtifactFileVerification::new(
            ArtifactFileKind::Zkey,
            zkey_path.to_path_buf(),
            "expected-zkey".to_owned(),
            "expected-zkey".to_owned(),
            true,
        );
        let wasm = wasm_path.map(|path| {
            ArtifactFileVerification::new(
                ArtifactFileKind::Wasm,
                path.to_path_buf(),
                "expected-wasm".to_owned(),
                "expected-wasm".to_owned(),
                true,
            )
        });
        let dat = dat_path.map(|path| {
            ArtifactFileVerification::new(
                ArtifactFileKind::Dat,
                path.to_path_buf(),
                "expected-dat".to_owned(),
                "expected-dat".to_owned(),
                true,
            )
        });

        ArtifactVerificationResult::new(
            variant,
            ArtifactVerificationFiles::new(zkey, wasm, dat),
            true,
        )
    }

    #[test]
    fn resolves_standard_remote_urls() {
        let source = ArtifactRemoteSource::canonical();
        let Ok(variant) = resolve_standard_variant(1, 1) else {
            panic!("expected supported standard shape 1x1");
        };

        let urls = source.resolve_urls(&variant, ArtifactBackend::Both);

        assert_eq!(
            urls.zkey_url(),
            "https://ipfs-lb.com/ipfs/QmUsmnK4PFc7zDp2cmC4wBZxYLjNyRgWfs5GNcJJ2uLcpU/circuits/01x01/zkey.br"
        );
        assert_eq!(
            urls.vkey_url(),
            "https://ipfs-lb.com/ipfs/QmUsmnK4PFc7zDp2cmC4wBZxYLjNyRgWfs5GNcJJ2uLcpU/circuits/01x01/vkey.json"
        );
        assert_eq!(
            urls.wasm_url(),
            Some(
                "https://ipfs-lb.com/ipfs/QmUsmnK4PFc7zDp2cmC4wBZxYLjNyRgWfs5GNcJJ2uLcpU/prover/snarkjs/01x01.wasm.br"
            )
        );
        assert_eq!(
            urls.dat_url(),
            Some(
                "https://ipfs-lb.com/ipfs/QmUsmnK4PFc7zDp2cmC4wBZxYLjNyRgWfs5GNcJJ2uLcpU/prover/native/01x01.dat.br"
            )
        );
    }

    #[test]
    fn resolves_poi_remote_urls() {
        let source = ArtifactRemoteSource::canonical();
        let Ok(variant) = resolve_poi_variant(3, 3) else {
            panic!("expected supported POI shape 3x3");
        };

        let urls = source.resolve_urls(&variant, ArtifactBackend::Both);

        assert_eq!(
            urls.zkey_url(),
            "https://ipfs-lb.com/ipfs/QmZrP9zaZw2LwErT2yA6VpMWm65UdToQiKj4DtStVsUJHr/POI_3x3/zkey.br"
        );
        assert_eq!(
            urls.vkey_url(),
            "https://ipfs-lb.com/ipfs/QmZrP9zaZw2LwErT2yA6VpMWm65UdToQiKj4DtStVsUJHr/POI_3x3/vkey.json"
        );
        assert_eq!(
            urls.wasm_url(),
            Some(
                "https://ipfs-lb.com/ipfs/QmZrP9zaZw2LwErT2yA6VpMWm65UdToQiKj4DtStVsUJHr/POI_3x3/wasm.br"
            )
        );
        assert_eq!(
            urls.dat_url(),
            Some(
                "https://ipfs-lb.com/ipfs/QmZrP9zaZw2LwErT2yA6VpMWm65UdToQiKj4DtStVsUJHr/POI_3x3/dat.br"
            )
        );
    }

    #[test]
    fn downloads_decompresses_and_caches_files() {
        let zkey_bytes = b"zkey-bytes";
        let wasm_bytes = b"wasm-bytes";
        let vkey_bytes = br#"{"vkey":true}"#;

        let mut responses = BTreeMap::new();
        responses.insert(
            "/ipfs/test-standard/circuits/01x01/zkey.br".to_owned(),
            MockResponse {
                status_line: "200 OK",
                body: compress(zkey_bytes),
                content_type: "application/octet-stream",
            },
        );
        responses.insert(
            "/ipfs/test-standard/circuits/01x01/vkey.json".to_owned(),
            MockResponse {
                status_line: "200 OK",
                body: vkey_bytes.to_vec(),
                content_type: "application/json",
            },
        );
        responses.insert(
            "/ipfs/test-standard/prover/snarkjs/01x01.wasm.br".to_owned(),
            MockResponse {
                status_line: "200 OK",
                body: compress(wasm_bytes),
                content_type: "application/octet-stream",
            },
        );

        let (address, handle) = start_server(responses, 3);
        let cache_root = temp_dir_path("cache-success");
        let Ok(config) = ArtifactDownloadConfig::new(
            ArtifactRemoteSource::new(&address, "test-standard", "test-poi")
                .unwrap_or_else(|_| panic!("expected valid remote source")),
            cache_root.clone(),
        ) else {
            panic!("expected valid download config");
        };
        let Ok(variant) = resolve_standard_variant(1, 1) else {
            panic!("expected supported standard shape 1x1");
        };

        let Ok(result) = download_artifacts_with(
            variant,
            ArtifactBackend::Wasm,
            &config,
            |variant, zkey, wasm, dat| Ok(ok_verification_result(variant, zkey, wasm, dat)),
        ) else {
            panic!("expected download and cache flow to succeed");
        };

        assert_eq!(
            fs::read(result.files().zkey_path())
                .unwrap_or_else(|_| panic!("expected cached zkey to be readable")),
            zkey_bytes
        );
        assert_eq!(
            fs::read(result.files().vkey_path())
                .unwrap_or_else(|_| panic!("expected cached vkey to be readable")),
            vkey_bytes
        );
        assert_eq!(
            fs::read(
                result.files().wasm_path().unwrap_or_else(|| panic!("expected cached wasm path"))
            )
            .unwrap_or_else(|_| panic!("expected cached wasm to be readable")),
            wasm_bytes
        );
        assert!(result.files().dat_path().is_none());
        assert!(result.verification().ok());

        handle.join().unwrap_or_else(|_| panic!("test server should shut down cleanly"));
        let _ = fs::remove_dir_all(cache_root);
    }

    #[test]
    fn fails_download_when_hash_verification_mismatches() {
        let mut responses = BTreeMap::new();
        responses.insert(
            "/ipfs/test-standard/circuits/01x01/zkey.br".to_owned(),
            MockResponse {
                status_line: "200 OK",
                body: compress(b"wrong-zkey"),
                content_type: "application/octet-stream",
            },
        );
        responses.insert(
            "/ipfs/test-standard/circuits/01x01/vkey.json".to_owned(),
            MockResponse {
                status_line: "200 OK",
                body: br#"{"vkey":true}"#.to_vec(),
                content_type: "application/json",
            },
        );
        responses.insert(
            "/ipfs/test-standard/prover/snarkjs/01x01.wasm.br".to_owned(),
            MockResponse {
                status_line: "200 OK",
                body: compress(b"wrong-wasm"),
                content_type: "application/octet-stream",
            },
        );

        let (address, handle) = start_server(responses, 3);
        let cache_root = temp_dir_path("cache-mismatch");
        let Ok(config) = ArtifactDownloadConfig::new(
            ArtifactRemoteSource::new(&address, "test-standard", "test-poi")
                .unwrap_or_else(|_| panic!("expected valid remote source")),
            cache_root.clone(),
        ) else {
            panic!("expected valid download config");
        };
        let Ok(variant) = resolve_standard_variant(1, 1) else {
            panic!("expected supported standard shape 1x1");
        };

        let Err(error) = download_artifacts(&variant, ArtifactBackend::Wasm, &config) else {
            panic!("expected canonical hash mismatch to fail download");
        };

        match error {
            ArtifactError::ArtifactVerificationFailed { kind, .. } => {
                assert_eq!(kind, ArtifactFileKind::Zkey);
            }
            _ => panic!("expected artifact verification failure"),
        }
        assert!(!cache_root.join("artifacts-v2.1/01x01/zkey").exists());

        handle.join().unwrap_or_else(|_| panic!("test server should shut down cleanly"));
        let _ = fs::remove_dir_all(cache_root);
    }

    #[test]
    fn fails_download_when_remote_object_is_missing() {
        let responses = BTreeMap::new();
        let (address, handle) = start_server(responses, 1);
        let cache_root = temp_dir_path("cache-404");
        let Ok(config) = ArtifactDownloadConfig::new(
            ArtifactRemoteSource::new(&address, "test-standard", "test-poi")
                .unwrap_or_else(|_| panic!("expected valid remote source")),
            cache_root.clone(),
        ) else {
            panic!("expected valid download config");
        };
        let Ok(variant) = resolve_standard_variant(1, 1) else {
            panic!("expected supported standard shape 1x1");
        };

        let Err(error) = download_artifacts_with(
            variant,
            ArtifactBackend::Wasm,
            &config,
            |variant, zkey, wasm, dat| Ok(ok_verification_result(variant, zkey, wasm, dat)),
        ) else {
            panic!("expected missing remote object to fail download");
        };

        assert_eq!(
            error,
            ArtifactError::ArtifactDownloadFailed {
                url: format!(
                    "{}/ipfs/test-standard/circuits/01x01/zkey.br",
                    config.remote_source().gateway_base_url()
                ),
                status_code: Some(404),
            }
        );

        handle.join().unwrap_or_else(|_| panic!("test server should shut down cleanly"));
        let _ = fs::remove_dir_all(cache_root);
    }

    #[test]
    fn fails_download_when_brotli_data_is_invalid() {
        let mut responses = BTreeMap::new();
        responses.insert(
            "/ipfs/test-standard/circuits/01x01/zkey.br".to_owned(),
            MockResponse {
                status_line: "200 OK",
                body: b"not-brotli".to_vec(),
                content_type: "application/octet-stream",
            },
        );

        let (address, handle) = start_server(responses, 1);
        let cache_root = temp_dir_path("cache-invalid-brotli");
        let Ok(config) = ArtifactDownloadConfig::new(
            ArtifactRemoteSource::new(&address, "test-standard", "test-poi")
                .unwrap_or_else(|_| panic!("expected valid remote source")),
            cache_root.clone(),
        ) else {
            panic!("expected valid download config");
        };
        let Ok(variant) = resolve_standard_variant(1, 1) else {
            panic!("expected supported standard shape 1x1");
        };

        let Err(error) = download_artifacts_with(
            variant,
            ArtifactBackend::Wasm,
            &config,
            |variant, zkey, wasm, dat| Ok(ok_verification_result(variant, zkey, wasm, dat)),
        ) else {
            panic!("expected invalid Brotli payload to fail download");
        };

        assert_eq!(
            error,
            ArtifactError::ArtifactDecompressionFailed { kind: ArtifactFileKind::Zkey }
        );

        handle.join().unwrap_or_else(|_| panic!("test server should shut down cleanly"));
        let _ = fs::remove_dir_all(cache_root);
    }
}
