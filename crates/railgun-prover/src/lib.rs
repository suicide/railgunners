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
    use num_bigint::BigUint;
    use railgun_artifacts::{
        ArtifactBackend, LoadedArtifactBundle, LoadedArtifactFiles, LoadedArtifactPaths,
        StandardCircuitShape, VerificationKeyJson, resolve_poi_variant, resolve_standard_variant,
    };
    use railgun_types::{
        BN254_SCALAR_FIELD_MODULUS_BYTES, BoundParamsHash, MerkleRoot, NoteCommitment, Nullifier,
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

    fn decode_hex<const N: usize>(value: &str) -> [u8; N] {
        let trimmed = value.strip_prefix("0x").unwrap_or(value);
        assert_eq!(trimmed.len(), N * 2, "hex input has unexpected length");

        let mut bytes = [0_u8; N];
        for (index, chunk) in trimmed.as_bytes().chunks_exact(2).enumerate() {
            let high = (chunk[0] as char)
                .to_digit(16)
                .unwrap_or_else(|| panic!("invalid hex nibble at index {}", index * 2));
            let low = (chunk[1] as char)
                .to_digit(16)
                .unwrap_or_else(|| panic!("invalid hex nibble at index {}", index * 2 + 1));
            bytes[index] = u8::try_from((high << 4) | low)
                .unwrap_or_else(|_| panic!("hex byte should fit into u8"));
        }

        bytes
    }

    fn decimal_from_hex(value: &str) -> String {
        BigUint::from_bytes_be(&decode_hex::<32>(value)).to_str_radix(10)
    }

    fn nullifier(value: &str) -> Nullifier {
        Nullifier::new(BigUint::from_bytes_be(&decode_hex::<32>(value)))
            .unwrap_or_else(|error| panic!("nullifier vector should construct: {error}"))
    }

    fn commitment(value: &str) -> NoteCommitment {
        NoteCommitment::new(BigUint::from_bytes_be(&decode_hex::<32>(value)))
            .unwrap_or_else(|error| panic!("commitment vector should construct: {error}"))
    }

    fn tx_public_inputs(shape: StandardCircuitShape) -> TransactionPublicInputs {
        let nullifiers = (0..shape.n_inputs())
            .map(|index| {
                Nullifier::new(BigUint::from(u32::from(index) + 3))
                    .unwrap_or_else(|error| panic!("test nullifier should validate: {error}"))
            })
            .collect();
        let commitments_out = (0..shape.n_outputs())
            .map(|index| {
                NoteCommitment::new(BigUint::from(u32::from(index) + 17))
                    .unwrap_or_else(|error| panic!("test commitment should validate: {error}"))
            })
            .collect();

        TransactionPublicInputs::new(
            shape,
            MerkleRoot::new([0_u8; 32]),
            BoundParamsHash::new([1_u8; 32]),
            nullifiers,
            commitments_out,
        )
        .unwrap_or_else(|error| panic!("typed transaction public inputs should construct: {error}"))
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
    fn rejects_transaction_public_inputs_with_wrong_nullifier_count() {
        let shape = StandardCircuitShape::new(2, 1)
            .unwrap_or_else(|_| panic!("expected supported standard shape"));
        let error = TransactionPublicInputs::new(
            shape,
            MerkleRoot::new([0_u8; 32]),
            BoundParamsHash::new([1_u8; 32]),
            vec![
                Nullifier::new(3_u8.into())
                    .unwrap_or_else(|error| panic!("test nullifier should validate: {error}")),
            ],
            vec![
                NoteCommitment::new(9_u8.into())
                    .unwrap_or_else(|error| panic!("test commitment should validate: {error}")),
            ],
        );
        let Err(error) = error else {
            panic!("expected nullifier-count mismatch to fail");
        };

        assert_eq!(
            error,
            ProverError::InvalidPublicInputs(
                "nullifier count must exactly match the selected circuit inputs"
            )
        );
    }

    #[test]
    fn rejects_transaction_public_inputs_with_wrong_commitment_count() {
        let shape = StandardCircuitShape::new(1, 2)
            .unwrap_or_else(|_| panic!("expected supported standard shape"));
        let error = TransactionPublicInputs::new(
            shape,
            MerkleRoot::new([0_u8; 32]),
            BoundParamsHash::new([1_u8; 32]),
            vec![
                Nullifier::new(3_u8.into())
                    .unwrap_or_else(|error| panic!("test nullifier should validate: {error}")),
            ],
            vec![
                NoteCommitment::new(9_u8.into())
                    .unwrap_or_else(|error| panic!("test commitment should validate: {error}")),
            ],
        );
        let Err(error) = error else {
            panic!("expected commitment-count mismatch to fail");
        };

        assert_eq!(
            error,
            ProverError::InvalidPublicInputs(
                "commitment count must exactly match the selected circuit outputs"
            )
        );
    }

    #[test]
    fn assembles_canonical_transaction_public_signals_in_exact_order() {
        let shape = StandardCircuitShape::new(1, 1)
            .unwrap_or_else(|_| panic!("expected supported standard shape"));
        let public_inputs = TransactionPublicInputs::new(
            shape,
            MerkleRoot::new(decode_hex(
                "185cc7d2c8e1c3954ee5421a6589cd05036708ff059b97b9c10e0261ad7d6875",
            )),
            BoundParamsHash::new(decode_hex(
                "0a4e7bed8287c629fd064665543dc71fdc09b0ab9df7d556f24a1f2f9f018dc7",
            )),
            vec![nullifier("0x05802951a46d9e999151eb0eb9e4c7c1260b7ee88539011c207dc169c4dd17ee")],
            vec![commitment("0x007aaf0cbee05066820873170e293e44df6766c29da69ac46fd05d4ff2c0a225")],
        )
        .unwrap_or_else(|error| panic!("fixture public inputs should construct: {error}"));

        let signals = public_inputs
            .to_public_signals()
            .unwrap_or_else(|error| panic!("fixture public inputs should serialize: {error}"));

        assert_eq!(
            signals.as_slice(),
            &[
                decimal_from_hex(
                    "185cc7d2c8e1c3954ee5421a6589cd05036708ff059b97b9c10e0261ad7d6875"
                ),
                decimal_from_hex(
                    "0a4e7bed8287c629fd064665543dc71fdc09b0ab9df7d556f24a1f2f9f018dc7"
                ),
                decimal_from_hex(
                    "05802951a46d9e999151eb0eb9e4c7c1260b7ee88539011c207dc169c4dd17ee"
                ),
                decimal_from_hex(
                    "007aaf0cbee05066820873170e293e44df6766c29da69ac46fd05d4ff2c0a225"
                ),
            ]
        );
    }

    #[test]
    fn preserves_nullifier_then_commitment_order_for_multi_element_shapes() {
        let shape = StandardCircuitShape::new(2, 3)
            .unwrap_or_else(|_| panic!("expected supported standard shape"));
        let public_inputs = TransactionPublicInputs::new(
            shape,
            MerkleRoot::new([0_u8; 32]),
            BoundParamsHash::new([1_u8; 32]),
            vec![
                Nullifier::new(3_u8.into())
                    .unwrap_or_else(|error| panic!("test nullifier should validate: {error}")),
                Nullifier::new(4_u8.into())
                    .unwrap_or_else(|error| panic!("test nullifier should validate: {error}")),
            ],
            vec![
                NoteCommitment::new(5_u8.into())
                    .unwrap_or_else(|error| panic!("test commitment should validate: {error}")),
                NoteCommitment::new(6_u8.into())
                    .unwrap_or_else(|error| panic!("test commitment should validate: {error}")),
                NoteCommitment::new(7_u8.into())
                    .unwrap_or_else(|error| panic!("test commitment should validate: {error}")),
            ],
        )
        .unwrap_or_else(|error| panic!("multi-element public inputs should construct: {error}"));

        let signals = public_inputs.to_public_signals().unwrap_or_else(|error| {
            panic!("multi-element public inputs should serialize: {error}")
        });

        assert_eq!(
            signals.as_slice(),
            &[
                "0",
                "454086624460063511464984254936031011189294057512315937409637584344757371137",
                "3",
                "4",
                "5",
                "6",
                "7"
            ]
        );
    }

    #[test]
    fn rejects_non_canonical_merkle_root_bytes_during_serialization() {
        let shape = StandardCircuitShape::new(1, 1)
            .unwrap_or_else(|_| panic!("expected supported standard shape"));
        let public_inputs = TransactionPublicInputs::new(
            shape,
            MerkleRoot::new(BN254_SCALAR_FIELD_MODULUS_BYTES),
            BoundParamsHash::new([1_u8; 32]),
            vec![
                Nullifier::new(3_u8.into())
                    .unwrap_or_else(|error| panic!("test nullifier should validate: {error}")),
            ],
            vec![
                NoteCommitment::new(9_u8.into())
                    .unwrap_or_else(|error| panic!("test commitment should validate: {error}")),
            ],
        )
        .unwrap_or_else(|error| {
            panic!("public inputs should construct before serialization: {error}")
        });
        let error = public_inputs.to_public_signals();
        let Err(error) = error else {
            panic!("expected non-canonical merkle root bytes to fail");
        };

        assert_eq!(
            error,
            ProverError::InvalidPublicInputs("merkle root must be canonical BN254 field bytes")
        );
    }

    #[test]
    fn rejects_non_canonical_bound_params_hash_bytes_during_serialization() {
        let shape = StandardCircuitShape::new(1, 1)
            .unwrap_or_else(|_| panic!("expected supported standard shape"));
        let public_inputs = TransactionPublicInputs::new(
            shape,
            MerkleRoot::new([0_u8; 32]),
            BoundParamsHash::new(BN254_SCALAR_FIELD_MODULUS_BYTES),
            vec![
                Nullifier::new(3_u8.into())
                    .unwrap_or_else(|error| panic!("test nullifier should validate: {error}")),
            ],
            vec![
                NoteCommitment::new(9_u8.into())
                    .unwrap_or_else(|error| panic!("test commitment should validate: {error}")),
            ],
        )
        .unwrap_or_else(|error| {
            panic!("public inputs should construct before serialization: {error}")
        });
        let error = public_inputs.to_public_signals();
        let Err(error) = error else {
            panic!("expected non-canonical bound params hash bytes to fail");
        };

        assert_eq!(
            error,
            ProverError::InvalidPublicInputs(
                "bound params hash must be canonical BN254 field bytes"
            )
        );
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
            .transaction_public_signals(&tx_public_inputs(
                StandardCircuitShape::new(1, 1)
                    .unwrap_or_else(|_| panic!("expected supported standard shape")),
            ))
            .unwrap_or_else(|_| panic!("expected public input adaptation"));

        assert_eq!(
            signals.as_slice(),
            &[
                "0".to_owned(),
                "454086624460063511464984254936031011189294057512315937409637584344757371137"
                    .to_owned(),
                "3".to_owned(),
                "17".to_owned()
            ]
        );
    }
}
