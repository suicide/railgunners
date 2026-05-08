//! Backend-neutral proving traits and concrete selected backend wrappers.

use railgun_artifacts::{
    ArtifactBackend, CircuitFamily, LoadedArtifactBundle, VerificationKeyJson,
};

use crate::{
    GeneratedProof, Groth16Proof, NativeProverExecutor, PoiProofRequest, PoiPublicInputs,
    ProofFamily, ProverError, PublicSignals, TransactionProofRequest, TransactionPublicInputs,
    WasmProverExecutor,
};

/// Capability trait for turning typed public inputs into backend-ready public signals.
pub trait PublicInputAdapter {
    /// Derives ordered public signals for transaction proof verification.
    ///
    /// # Errors
    ///
    /// Returns an error when the public inputs are malformed for the backend.
    fn transaction_public_signals(
        &self,
        public_inputs: &TransactionPublicInputs,
    ) -> Result<PublicSignals, ProverError>;

    /// Derives ordered public signals for POI proof verification.
    ///
    /// # Errors
    ///
    /// Returns an error when the public inputs are malformed for the backend.
    fn poi_public_signals(
        &self,
        public_inputs: &PoiPublicInputs,
    ) -> Result<PublicSignals, ProverError>;
}

/// Capability trait for proof generation.
pub trait ProofGenerator {
    /// Proves a Railgun transaction circuit.
    ///
    /// # Errors
    ///
    /// Returns an error when the backend does not support the loaded artifact bundle or the
    /// underlying executor fails.
    fn prove_transaction(
        &self,
        request: &TransactionProofRequest,
    ) -> Result<GeneratedProof, ProverError>;

    /// Proves a Proof of Innocence circuit.
    ///
    /// # Errors
    ///
    /// Returns an error when the backend does not support the loaded artifact bundle or the
    /// underlying executor fails.
    fn prove_poi(&self, request: &PoiProofRequest) -> Result<GeneratedProof, ProverError>;
}

/// Capability trait for local proof verification.
pub trait ProofVerifier {
    /// Verifies a Railgun transaction proof.
    ///
    /// # Errors
    ///
    /// Returns an error when verification is unsupported or the underlying executor fails.
    fn verify_transaction(
        &self,
        public_inputs: &TransactionPublicInputs,
        proof: &Groth16Proof,
    ) -> Result<bool, ProverError>;

    /// Verifies a Proof of Innocence proof.
    ///
    /// # Errors
    ///
    /// Returns an error when verification is unsupported or the underlying executor fails.
    fn verify_poi(
        &self,
        public_inputs: &PoiPublicInputs,
        proof: &Groth16Proof,
    ) -> Result<bool, ProverError>;
}

/// Canonical SDK-facing proving backend interface.
pub trait ProverBackend: PublicInputAdapter + ProofGenerator + ProofVerifier {
    /// Returns the selected proving backend kind.
    fn backend_kind(&self) -> ArtifactBackend;

    /// Returns the loaded artifact bundle bound to this backend instance.
    fn bundle(&self) -> &LoadedArtifactBundle;

    /// Returns whether the backend can represent the requested proof family for the bound bundle.
    fn supports(&self, family: ProofFamily) -> bool;
}

/// Wasm proving backend bound to a loaded artifact bundle and injected executor.
pub struct WasmProverBackend<'a> {
    bundle: LoadedArtifactBundle,
    executor: &'a dyn WasmProverExecutor,
}

impl<'a> WasmProverBackend<'a> {
    /// Creates a wasm proving backend for the provided loaded artifact bundle.
    #[must_use]
    pub fn new(bundle: LoadedArtifactBundle, executor: &'a dyn WasmProverExecutor) -> Self {
        Self { bundle, executor }
    }

    fn ensure_family(&self, requested: ProofFamily) -> Result<(), ProverError> {
        ensure_bundle_family(self.bundle(), requested)
    }
}

impl PublicInputAdapter for WasmProverBackend<'_> {
    fn transaction_public_signals(
        &self,
        public_inputs: &TransactionPublicInputs,
    ) -> Result<PublicSignals, ProverError> {
        Ok(public_inputs.signals().clone())
    }

    fn poi_public_signals(
        &self,
        public_inputs: &PoiPublicInputs,
    ) -> Result<PublicSignals, ProverError> {
        Ok(public_inputs.signals().clone())
    }
}

impl ProofGenerator for WasmProverBackend<'_> {
    fn prove_transaction(
        &self,
        request: &TransactionProofRequest,
    ) -> Result<GeneratedProof, ProverError> {
        self.ensure_family(ProofFamily::RailgunTransaction)?;
        self.executor.prove_transaction(self.bundle(), request)
    }

    fn prove_poi(&self, request: &PoiProofRequest) -> Result<GeneratedProof, ProverError> {
        self.ensure_family(ProofFamily::Poi)?;
        self.executor.prove_poi(self.bundle(), request)
    }
}

impl ProofVerifier for WasmProverBackend<'_> {
    fn verify_transaction(
        &self,
        public_inputs: &TransactionPublicInputs,
        proof: &Groth16Proof,
    ) -> Result<bool, ProverError> {
        self.ensure_family(ProofFamily::RailgunTransaction)?;
        let signals = self.transaction_public_signals(public_inputs)?;
        self.executor.verify(vkey(self.bundle()), &signals, proof)
    }

    fn verify_poi(
        &self,
        public_inputs: &PoiPublicInputs,
        proof: &Groth16Proof,
    ) -> Result<bool, ProverError> {
        self.ensure_family(ProofFamily::Poi)?;
        let signals = self.poi_public_signals(public_inputs)?;
        self.executor.verify(vkey(self.bundle()), &signals, proof)
    }
}

impl ProverBackend for WasmProverBackend<'_> {
    fn backend_kind(&self) -> ArtifactBackend {
        ArtifactBackend::Wasm
    }

    fn bundle(&self) -> &LoadedArtifactBundle {
        &self.bundle
    }

    fn supports(&self, family: ProofFamily) -> bool {
        supports_family(self.bundle().variant().family(), family)
    }
}

/// Native proving backend bound to a loaded artifact bundle and injected executor.
pub struct NativeProverBackend<'a> {
    bundle: LoadedArtifactBundle,
    executor: &'a dyn NativeProverExecutor,
}

impl<'a> NativeProverBackend<'a> {
    /// Creates a native proving backend for the provided loaded artifact bundle.
    #[must_use]
    pub fn new(bundle: LoadedArtifactBundle, executor: &'a dyn NativeProverExecutor) -> Self {
        Self { bundle, executor }
    }

    fn ensure_family(&self, requested: ProofFamily) -> Result<(), ProverError> {
        ensure_bundle_family(self.bundle(), requested)
    }
}

impl PublicInputAdapter for NativeProverBackend<'_> {
    fn transaction_public_signals(
        &self,
        public_inputs: &TransactionPublicInputs,
    ) -> Result<PublicSignals, ProverError> {
        Ok(public_inputs.signals().clone())
    }

    fn poi_public_signals(
        &self,
        public_inputs: &PoiPublicInputs,
    ) -> Result<PublicSignals, ProverError> {
        Ok(public_inputs.signals().clone())
    }
}

impl ProofGenerator for NativeProverBackend<'_> {
    fn prove_transaction(
        &self,
        request: &TransactionProofRequest,
    ) -> Result<GeneratedProof, ProverError> {
        self.ensure_family(ProofFamily::RailgunTransaction)?;
        self.executor.prove_transaction(self.bundle(), request)
    }

    fn prove_poi(&self, request: &PoiProofRequest) -> Result<GeneratedProof, ProverError> {
        self.ensure_family(ProofFamily::Poi)?;
        self.executor.prove_poi(self.bundle(), request)
    }
}

impl ProofVerifier for NativeProverBackend<'_> {
    fn verify_transaction(
        &self,
        public_inputs: &TransactionPublicInputs,
        proof: &Groth16Proof,
    ) -> Result<bool, ProverError> {
        self.ensure_family(ProofFamily::RailgunTransaction)?;
        let signals = self.transaction_public_signals(public_inputs)?;
        self.executor.verify(vkey(self.bundle()), &signals, proof)
    }

    fn verify_poi(
        &self,
        public_inputs: &PoiPublicInputs,
        proof: &Groth16Proof,
    ) -> Result<bool, ProverError> {
        self.ensure_family(ProofFamily::Poi)?;
        let signals = self.poi_public_signals(public_inputs)?;
        self.executor.verify(vkey(self.bundle()), &signals, proof)
    }
}

impl ProverBackend for NativeProverBackend<'_> {
    fn backend_kind(&self) -> ArtifactBackend {
        ArtifactBackend::Native
    }

    fn bundle(&self) -> &LoadedArtifactBundle {
        &self.bundle
    }

    fn supports(&self, family: ProofFamily) -> bool {
        supports_family(self.bundle().variant().family(), family)
    }
}

/// Selected proving backend instance bound to one loaded artifact bundle.
pub enum SelectedProverBackend<'a> {
    /// Wasm-backed proving runtime.
    Wasm(WasmProverBackend<'a>),
    /// Native-backed proving runtime.
    Native(NativeProverBackend<'a>),
}

impl PublicInputAdapter for SelectedProverBackend<'_> {
    fn transaction_public_signals(
        &self,
        public_inputs: &TransactionPublicInputs,
    ) -> Result<PublicSignals, ProverError> {
        match self {
            Self::Wasm(backend) => backend.transaction_public_signals(public_inputs),
            Self::Native(backend) => backend.transaction_public_signals(public_inputs),
        }
    }

    fn poi_public_signals(
        &self,
        public_inputs: &PoiPublicInputs,
    ) -> Result<PublicSignals, ProverError> {
        match self {
            Self::Wasm(backend) => backend.poi_public_signals(public_inputs),
            Self::Native(backend) => backend.poi_public_signals(public_inputs),
        }
    }
}

impl ProofGenerator for SelectedProverBackend<'_> {
    fn prove_transaction(
        &self,
        request: &TransactionProofRequest,
    ) -> Result<GeneratedProof, ProverError> {
        match self {
            Self::Wasm(backend) => backend.prove_transaction(request),
            Self::Native(backend) => backend.prove_transaction(request),
        }
    }

    fn prove_poi(&self, request: &PoiProofRequest) -> Result<GeneratedProof, ProverError> {
        match self {
            Self::Wasm(backend) => backend.prove_poi(request),
            Self::Native(backend) => backend.prove_poi(request),
        }
    }
}

impl ProofVerifier for SelectedProverBackend<'_> {
    fn verify_transaction(
        &self,
        public_inputs: &TransactionPublicInputs,
        proof: &Groth16Proof,
    ) -> Result<bool, ProverError> {
        match self {
            Self::Wasm(backend) => backend.verify_transaction(public_inputs, proof),
            Self::Native(backend) => backend.verify_transaction(public_inputs, proof),
        }
    }

    fn verify_poi(
        &self,
        public_inputs: &PoiPublicInputs,
        proof: &Groth16Proof,
    ) -> Result<bool, ProverError> {
        match self {
            Self::Wasm(backend) => backend.verify_poi(public_inputs, proof),
            Self::Native(backend) => backend.verify_poi(public_inputs, proof),
        }
    }
}

impl ProverBackend for SelectedProverBackend<'_> {
    fn backend_kind(&self) -> ArtifactBackend {
        match self {
            Self::Wasm(backend) => backend.backend_kind(),
            Self::Native(backend) => backend.backend_kind(),
        }
    }

    fn bundle(&self) -> &LoadedArtifactBundle {
        match self {
            Self::Wasm(backend) => backend.bundle(),
            Self::Native(backend) => backend.bundle(),
        }
    }

    fn supports(&self, family: ProofFamily) -> bool {
        match self {
            Self::Wasm(backend) => backend.supports(family),
            Self::Native(backend) => backend.supports(family),
        }
    }
}

fn supports_family(bundle_family: CircuitFamily, requested: ProofFamily) -> bool {
    matches!(
        (bundle_family, requested),
        (CircuitFamily::Standard, ProofFamily::RailgunTransaction)
            | (CircuitFamily::Poi, ProofFamily::Poi)
    )
}

fn ensure_bundle_family(
    bundle: &LoadedArtifactBundle,
    requested: ProofFamily,
) -> Result<(), ProverError> {
    let bundle_family = bundle.variant().family();
    if supports_family(bundle_family, requested) {
        Ok(())
    } else {
        Err(ProverError::UnsupportedProofFamily { requested, bundle_family })
    }
}

fn vkey(bundle: &LoadedArtifactBundle) -> &VerificationKeyJson {
    bundle.files().vkey()
}
