//! Backend selection helpers driven by loaded artifact bundle capabilities.

use railgun_artifacts::{ArtifactBackend, LoadedArtifactBundle};

use crate::{
    NativeProverBackend, NativeProverExecutor, ProverError, SelectedProverBackend,
    WasmProverBackend, WasmProverExecutor,
};

/// Explicit backend preference for bundles that carry both wasm and native artifacts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendPreference {
    /// Use wasm when available, otherwise fall back to native.
    PreferWasm,
    /// Use native when available, otherwise fall back to wasm.
    PreferNative,
    /// Require wasm selection.
    RequireWasm,
    /// Require native selection.
    RequireNative,
}

/// Configured injected proving runtimes available for backend selection.
#[derive(Clone, Copy, Default)]
pub struct AvailableProverExecutors<'a> {
    /// Configured wasm proving runtime.
    pub wasm: Option<&'a dyn WasmProverExecutor>,
    /// Configured native proving runtime.
    pub native: Option<&'a dyn NativeProverExecutor>,
}

/// Selects a concrete proving backend instance from a loaded artifact bundle.
///
/// # Errors
///
/// Returns an error when the selected backend is unsupported by the artifact bundle or no
/// matching runtime executor is configured.
pub fn select_prover_backend(
    bundle: LoadedArtifactBundle,
    preference: BackendPreference,
    executors: AvailableProverExecutors<'_>,
) -> Result<SelectedProverBackend<'_>, ProverError> {
    match bundle.backend() {
        ArtifactBackend::Wasm => match preference {
            BackendPreference::RequireNative => Err(ProverError::UnsupportedBackendSelection {
                bundle_backend: ArtifactBackend::Wasm,
                required_backend: ArtifactBackend::Native,
            }),
            _ => build_wasm(bundle, executors.wasm),
        },
        ArtifactBackend::Native => match preference {
            BackendPreference::RequireWasm => Err(ProverError::UnsupportedBackendSelection {
                bundle_backend: ArtifactBackend::Native,
                required_backend: ArtifactBackend::Wasm,
            }),
            _ => build_native(bundle, executors.native),
        },
        ArtifactBackend::Both => match preference {
            BackendPreference::PreferWasm => {
                if let Some(executor) = executors.wasm {
                    Ok(SelectedProverBackend::Wasm(WasmProverBackend::new(bundle, executor)))
                } else if let Some(executor) = executors.native {
                    Ok(SelectedProverBackend::Native(NativeProverBackend::new(bundle, executor)))
                } else {
                    Err(ProverError::MissingRuntimeCapability(ArtifactBackend::Both))
                }
            }
            BackendPreference::PreferNative => {
                if let Some(executor) = executors.native {
                    Ok(SelectedProverBackend::Native(NativeProverBackend::new(bundle, executor)))
                } else if let Some(executor) = executors.wasm {
                    Ok(SelectedProverBackend::Wasm(WasmProverBackend::new(bundle, executor)))
                } else {
                    Err(ProverError::MissingRuntimeCapability(ArtifactBackend::Both))
                }
            }
            BackendPreference::RequireWasm => build_wasm(bundle, executors.wasm),
            BackendPreference::RequireNative => build_native(bundle, executors.native),
        },
    }
}

fn build_wasm(
    bundle: LoadedArtifactBundle,
    executor: Option<&dyn WasmProverExecutor>,
) -> Result<SelectedProverBackend<'_>, ProverError> {
    match bundle.backend() {
        ArtifactBackend::Wasm | ArtifactBackend::Both => executor
            .map(|executor| SelectedProverBackend::Wasm(WasmProverBackend::new(bundle, executor)))
            .ok_or(ProverError::MissingRuntimeCapability(ArtifactBackend::Wasm)),
        ArtifactBackend::Native => Err(ProverError::UnsupportedBackendSelection {
            bundle_backend: ArtifactBackend::Native,
            required_backend: ArtifactBackend::Wasm,
        }),
    }
}

fn build_native(
    bundle: LoadedArtifactBundle,
    executor: Option<&dyn NativeProverExecutor>,
) -> Result<SelectedProverBackend<'_>, ProverError> {
    match bundle.backend() {
        ArtifactBackend::Native | ArtifactBackend::Both => executor
            .map(|executor| {
                SelectedProverBackend::Native(NativeProverBackend::new(bundle, executor))
            })
            .ok_or(ProverError::MissingRuntimeCapability(ArtifactBackend::Native)),
        ArtifactBackend::Wasm => Err(ProverError::UnsupportedBackendSelection {
            bundle_backend: ArtifactBackend::Wasm,
            required_backend: ArtifactBackend::Native,
        }),
    }
}
