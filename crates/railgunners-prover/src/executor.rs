//! Injected executor traits for concrete proving runtimes.

use railgunners_artifacts::{LoadedArtifactBundle, VerificationKeyJson};

use crate::{
    GeneratedProof, Groth16Proof, PoiProofRequest, ProverError, PublicSignals,
    TransactionProofRequest,
};

/// Injected wasm proving runtime.
pub trait WasmProverExecutor {
    /// Proves a Railgun transaction circuit using wasm artifacts.
    ///
    /// # Errors
    ///
    /// Returns any runtime-specific proving error.
    fn prove_transaction(
        &self,
        bundle: &LoadedArtifactBundle,
        request: &TransactionProofRequest,
    ) -> Result<GeneratedProof, ProverError>;

    /// Proves a Proof of Innocence circuit using wasm artifacts.
    ///
    /// # Errors
    ///
    /// Returns any runtime-specific proving error.
    fn prove_poi(
        &self,
        bundle: &LoadedArtifactBundle,
        request: &PoiProofRequest,
    ) -> Result<GeneratedProof, ProverError>;

    /// Verifies a proof against a local verification key using the wasm-capable runtime.
    ///
    /// # Errors
    ///
    /// Returns any runtime-specific verification error.
    fn verify(
        &self,
        vkey: &VerificationKeyJson,
        public_signals: &PublicSignals,
        proof: &Groth16Proof,
    ) -> Result<bool, ProverError>;
}

/// Injected native proving runtime.
pub trait NativeProverExecutor {
    /// Proves a Railgun transaction circuit using native artifacts.
    ///
    /// # Errors
    ///
    /// Returns any runtime-specific proving error.
    fn prove_transaction(
        &self,
        bundle: &LoadedArtifactBundle,
        request: &TransactionProofRequest,
    ) -> Result<GeneratedProof, ProverError>;

    /// Proves a Proof of Innocence circuit using native artifacts.
    ///
    /// # Errors
    ///
    /// Returns any runtime-specific proving error.
    fn prove_poi(
        &self,
        bundle: &LoadedArtifactBundle,
        request: &PoiProofRequest,
    ) -> Result<GeneratedProof, ProverError>;

    /// Verifies a proof against a local verification key when the native runtime supports it.
    ///
    /// # Errors
    ///
    /// Returns any runtime-specific verification error.
    fn verify(
        &self,
        vkey: &VerificationKeyJson,
        public_signals: &PublicSignals,
        proof: &Groth16Proof,
    ) -> Result<bool, ProverError>;
}
