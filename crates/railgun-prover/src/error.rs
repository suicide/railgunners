//! Typed errors for prover backend selection and execution.

use railgun_artifacts::{ArtifactBackend, CircuitFamily};

use crate::ProofFamily;

/// Errors raised while selecting or executing a prover backend.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProverError {
    /// The selected artifact bundle cannot satisfy the requested backend.
    UnsupportedBackendSelection {
        /// Backend capability present in the artifact bundle.
        bundle_backend: ArtifactBackend,
        /// Backend required by the caller.
        required_backend: ArtifactBackend,
    },
    /// No configured runtime executor can satisfy the selected backend.
    MissingRuntimeCapability(ArtifactBackend),
    /// The loaded artifact bundle circuit family does not support the requested proof family.
    UnsupportedProofFamily {
        /// Proof family requested by the caller.
        requested: ProofFamily,
        /// Circuit family carried by the loaded artifact bundle.
        bundle_family: CircuitFamily,
    },
    /// Prepared circuit inputs were malformed.
    InvalidPreparedInputs(&'static str),
    /// Verification public inputs were malformed.
    InvalidPublicInputs(&'static str),
    /// The selected backend does not support local verification in the current runtime.
    VerificationUnsupported(ArtifactBackend),
    /// The underlying executor failed while proving or verifying.
    ExecutionFailed(&'static str),
}

impl core::fmt::Display for ProverError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedBackendSelection { bundle_backend, required_backend } => {
                write!(
                    formatter,
                    "artifact bundle backend {bundle_backend:?} does not satisfy requested backend {required_backend:?}"
                )
            }
            Self::MissingRuntimeCapability(backend) => {
                write!(formatter, "missing runtime capability for backend {backend:?}")
            }
            Self::UnsupportedProofFamily { requested, bundle_family } => {
                write!(
                    formatter,
                    "proof family {requested:?} is unsupported for circuit family {bundle_family:?}"
                )
            }
            Self::InvalidPreparedInputs(message)
            | Self::InvalidPublicInputs(message)
            | Self::ExecutionFailed(message) => formatter.write_str(message),
            Self::VerificationUnsupported(backend) => {
                write!(formatter, "verification is unsupported for backend {backend:?}")
            }
        }
    }
}

impl std::error::Error for ProverError {}
