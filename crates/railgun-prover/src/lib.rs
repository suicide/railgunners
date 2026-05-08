//! Optional prover backend abstraction for RAILGUN proving runtimes.

mod backend;
mod error;
mod executor;
mod model;
mod request;
mod select;

pub use backend::{
    NativeProverBackend, ProofGenerator, ProofVerifier, ProverBackend, PublicInputAdapter,
    SelectedProverBackend, WasmProverBackend,
};
pub use error::ProverError;
pub use executor::{NativeProverExecutor, WasmProverExecutor};
pub use model::{
    GeneratedProof, Groth16Proof, PoiPublicInputs, PreparedCircuitInputs, ProofFamily,
    PublicSignals, TransactionPublicInputs,
};
pub use request::{PoiProofRequest, TransactionProofRequest};
pub use select::{AvailableProverExecutors, BackendPreference, select_prover_backend};

#[cfg(test)]
mod tests {
    use railgun_artifacts::{
        ArtifactBackend, LoadedArtifactBundle, LoadedArtifactFiles, LoadedArtifactPaths,
        VerificationKeyJson, resolve_poi_variant, resolve_standard_variant,
    };
    use serde_json::json;

    use super::{
        AvailableProverExecutors, BackendPreference, GeneratedProof, Groth16Proof,
        NativeProverExecutor, PoiProofRequest, PoiPublicInputs, PreparedCircuitInputs, ProofFamily,
        ProofGenerator, ProofVerifier, ProverBackend, ProverError, PublicInputAdapter,
        PublicSignals, TransactionProofRequest, TransactionPublicInputs, WasmProverExecutor,
        select_prover_backend,
    };

    struct StubWasmExecutor;

    impl WasmProverExecutor for StubWasmExecutor {
        fn prove_transaction(
            &self,
            _bundle: &LoadedArtifactBundle,
            _request: &TransactionProofRequest,
        ) -> Result<GeneratedProof, ProverError> {
            Ok(canned_proof("wasm-tx"))
        }

        fn prove_poi(
            &self,
            _bundle: &LoadedArtifactBundle,
            _request: &PoiProofRequest,
        ) -> Result<GeneratedProof, ProverError> {
            Ok(canned_proof("wasm-poi"))
        }

        fn verify(
            &self,
            _vkey: &VerificationKeyJson,
            _public_signals: &PublicSignals,
            _proof: &Groth16Proof,
        ) -> Result<bool, ProverError> {
            Ok(true)
        }
    }

    struct StubNativeExecutor {
        supports_verify: bool,
    }

    impl NativeProverExecutor for StubNativeExecutor {
        fn prove_transaction(
            &self,
            _bundle: &LoadedArtifactBundle,
            _request: &TransactionProofRequest,
        ) -> Result<GeneratedProof, ProverError> {
            Ok(canned_proof("native-tx"))
        }

        fn prove_poi(
            &self,
            _bundle: &LoadedArtifactBundle,
            _request: &PoiProofRequest,
        ) -> Result<GeneratedProof, ProverError> {
            Ok(canned_proof("native-poi"))
        }

        fn verify(
            &self,
            _vkey: &VerificationKeyJson,
            _public_signals: &PublicSignals,
            _proof: &Groth16Proof,
        ) -> Result<bool, ProverError> {
            if self.supports_verify {
                Ok(true)
            } else {
                Err(ProverError::VerificationUnsupported(ArtifactBackend::Native))
            }
        }
    }

    fn canned_proof(label: &str) -> GeneratedProof {
        GeneratedProof::new(
            Groth16Proof::new(
                [format!("{label}-a0"), format!("{label}-a1")],
                [
                    [format!("{label}-b00"), format!("{label}-b01")],
                    [format!("{label}-b10"), format!("{label}-b11")],
                ],
                [format!("{label}-c0"), format!("{label}-c1")],
            ),
            Some(PublicSignals::new(vec![format!("{label}-signal")])),
        )
    }

    fn bundle(backend: ArtifactBackend, poi: bool) -> LoadedArtifactBundle {
        let variant = if poi {
            resolve_poi_variant(3, 3).unwrap_or_else(|_| panic!("expected supported poi variant"))
        } else {
            resolve_standard_variant(1, 1)
                .unwrap_or_else(|_| panic!("expected supported standard variant"))
        };
        let vkey = VerificationKeyJson::from_value(json!({"protocol": "groth16"}))
            .unwrap_or_else(|_| panic!("expected object vkey"));
        let files = match backend {
            ArtifactBackend::Wasm => LoadedArtifactFiles::new(
                backend,
                b"zkey".to_vec(),
                vkey,
                Some(b"wasm".to_vec()),
                None,
            ),
            ArtifactBackend::Native => LoadedArtifactFiles::new(
                backend,
                b"zkey".to_vec(),
                vkey,
                None,
                Some(b"dat".to_vec()),
            ),
            ArtifactBackend::Both => LoadedArtifactFiles::new(
                backend,
                b"zkey".to_vec(),
                vkey,
                Some(b"wasm".to_vec()),
                Some(b"dat".to_vec()),
            ),
        }
        .unwrap_or_else(|_| panic!("expected valid loaded artifact files"));

        LoadedArtifactBundle::new(
            variant,
            backend,
            LoadedArtifactPaths::new(
                "zkey".into(),
                "vkey.json".into(),
                backend.includes_wasm().then(|| "wasm".into()),
                backend.includes_dat().then(|| "dat".into()),
            ),
            files,
        )
    }

    #[test]
    fn selects_wasm_backend_from_wasm_bundle() {
        let wasm = StubWasmExecutor;
        let selected = select_prover_backend(
            bundle(ArtifactBackend::Wasm, false),
            BackendPreference::PreferWasm,
            AvailableProverExecutors { wasm: Some(&wasm), native: None },
        )
        .unwrap_or_else(|_| panic!("expected wasm backend selection"));

        assert_eq!(selected.backend_kind(), ArtifactBackend::Wasm);
        assert!(selected.supports(ProofFamily::RailgunTransaction));
        assert!(!selected.supports(ProofFamily::Poi));
    }

    #[test]
    fn selects_native_backend_from_native_bundle() {
        let native = StubNativeExecutor { supports_verify: true };
        let selected = select_prover_backend(
            bundle(ArtifactBackend::Native, false),
            BackendPreference::PreferNative,
            AvailableProverExecutors { wasm: None, native: Some(&native) },
        )
        .unwrap_or_else(|_| panic!("expected native backend selection"));

        assert_eq!(selected.backend_kind(), ArtifactBackend::Native);
    }

    #[test]
    fn prefers_native_for_dual_backend_bundle() {
        let wasm = StubWasmExecutor;
        let native = StubNativeExecutor { supports_verify: true };
        let selected = select_prover_backend(
            bundle(ArtifactBackend::Both, false),
            BackendPreference::PreferNative,
            AvailableProverExecutors { wasm: Some(&wasm), native: Some(&native) },
        )
        .unwrap_or_else(|_| panic!("expected native backend selection"));

        assert_eq!(selected.backend_kind(), ArtifactBackend::Native);
    }

    #[test]
    fn falls_back_to_native_when_wasm_preferred_but_missing() {
        let native = StubNativeExecutor { supports_verify: true };
        let selected = select_prover_backend(
            bundle(ArtifactBackend::Both, false),
            BackendPreference::PreferWasm,
            AvailableProverExecutors { wasm: None, native: Some(&native) },
        )
        .unwrap_or_else(|_| panic!("expected native fallback selection"));

        assert_eq!(selected.backend_kind(), ArtifactBackend::Native);
    }

    #[test]
    fn rejects_unsupported_required_backend_for_bundle() {
        let native = StubNativeExecutor { supports_verify: true };
        let error = select_prover_backend(
            bundle(ArtifactBackend::Wasm, false),
            BackendPreference::RequireNative,
            AvailableProverExecutors { wasm: None, native: Some(&native) },
        );
        let Err(error) = error else {
            panic!("expected unsupported backend selection to fail");
        };

        assert_eq!(
            error,
            ProverError::UnsupportedBackendSelection {
                bundle_backend: ArtifactBackend::Wasm,
                required_backend: ArtifactBackend::Native,
            }
        );
    }

    #[test]
    fn rejects_missing_runtime_capability() {
        let error = select_prover_backend(
            bundle(ArtifactBackend::Wasm, false),
            BackendPreference::RequireWasm,
            AvailableProverExecutors::default(),
        );
        let Err(error) = error else {
            panic!("expected missing runtime capability selection to fail");
        };

        assert_eq!(error, ProverError::MissingRuntimeCapability(ArtifactBackend::Wasm));
    }

    #[test]
    fn proves_transaction_with_selected_wasm_backend() {
        let wasm = StubWasmExecutor;
        let selected = select_prover_backend(
            bundle(ArtifactBackend::Wasm, false),
            BackendPreference::RequireWasm,
            AvailableProverExecutors { wasm: Some(&wasm), native: None },
        )
        .unwrap_or_else(|_| panic!("expected wasm backend selection"));
        let request = TransactionProofRequest::new(
            PreparedCircuitInputs::from_value(json!({"foo": ["bar"]}))
                .unwrap_or_else(|_| panic!("expected object prepared inputs")),
        );

        let result = selected
            .prove_transaction(&request)
            .unwrap_or_else(|_| panic!("expected transaction proof generation"));

        assert_eq!(result.proof().pi_a(), &["wasm-tx-a0".to_owned(), "wasm-tx-a1".to_owned()]);
    }

    #[test]
    fn rejects_unsupported_proof_family_for_selected_backend() {
        let wasm = StubWasmExecutor;
        let selected = select_prover_backend(
            bundle(ArtifactBackend::Wasm, false),
            BackendPreference::RequireWasm,
            AvailableProverExecutors { wasm: Some(&wasm), native: None },
        )
        .unwrap_or_else(|_| panic!("expected wasm backend selection"));
        let request = PoiProofRequest::new(
            PreparedCircuitInputs::from_value(json!({"foo": ["bar"]}))
                .unwrap_or_else(|_| panic!("expected object prepared inputs")),
        );

        let error = selected.prove_poi(&request);
        let Err(error) = error else {
            panic!("expected unsupported proof family prove call to fail");
        };

        assert_eq!(
            error,
            ProverError::UnsupportedProofFamily {
                requested: ProofFamily::Poi,
                bundle_family: railgun_artifacts::CircuitFamily::Standard,
            }
        );
    }

    #[test]
    fn native_verification_can_fail_deterministically() {
        let native = StubNativeExecutor { supports_verify: false };
        let selected = select_prover_backend(
            bundle(ArtifactBackend::Native, true),
            BackendPreference::RequireNative,
            AvailableProverExecutors { wasm: None, native: Some(&native) },
        )
        .unwrap_or_else(|_| panic!("expected native backend selection"));

        let proof = canned_proof("native-poi");
        let error =
            selected.verify_poi(&PoiPublicInputs::new(vec!["signal".to_owned()]), proof.proof());
        let Err(error) = error else {
            panic!("expected verification unsupported call to fail");
        };

        assert_eq!(error, ProverError::VerificationUnsupported(ArtifactBackend::Native));
    }

    #[test]
    fn exposes_public_input_adapter_helpers() {
        let wasm = StubWasmExecutor;
        let selected = select_prover_backend(
            bundle(ArtifactBackend::Wasm, false),
            BackendPreference::RequireWasm,
            AvailableProverExecutors { wasm: Some(&wasm), native: None },
        )
        .unwrap_or_else(|_| panic!("expected wasm backend selection"));

        let signals = selected
            .transaction_public_signals(&TransactionPublicInputs::new(vec![
                "a".to_owned(),
                "b".to_owned(),
            ]))
            .unwrap_or_else(|_| panic!("expected public input adaptation"));

        assert_eq!(signals.as_slice(), &["a".to_owned(), "b".to_owned()]);
    }
}
