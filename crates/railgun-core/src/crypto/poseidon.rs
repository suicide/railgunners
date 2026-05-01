mod constants;

use std::sync::OnceLock;

use ark_bn254::Fr;
use ark_ff::{BigInteger, Field, PrimeField, Zero};
use num_bigint::BigUint;
use num_traits::Num;

use super::CryptoError;

// This module intentionally keeps the Poseidon backend in-tree because the prior
// `light-poseidon` dependency does not support the exact 13-input Circom path
// required by RAILGUN txid derivation. Public source:
// https://github.com/Lightprotocol/light-poseidon/blob/main/light-poseidon/src/lib.rs
// The corresponding upstream test suite also asserts that inputs above 12 fail:
// https://github.com/Lightprotocol/light-poseidon/blob/main/light-poseidon/tests/bn254_fq_x5.rs
// The local implementation is a compatibility-oriented transcription of the
// Circom-compatible backend shape used by upstream RAILGUN-compatible projects,
// with parity tests against public reference implementations.
const FULL_ROUNDS: usize = 8;
const PARTIAL_ROUNDS: [usize; 16] =
    [56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68];
#[allow(dead_code)]
const TXID_INPUT_ARITY: usize = 13;
// Canonical RAILGUN Merkle zero used when padding txid nullifier and commitment
// lists to the required 13 Poseidon inputs.
//
// Public RAILGUN engine derivation:
// `keccak256(fromUTF8String("Railgun")) % SNARK_PRIME`
// https://github.com/Railgun-Community/engine/blob/main/src/models/merkletree-types.ts
// https://github.com/Railgun-Community/engine/blob/main/src/utils/constants.ts
//
// Public RAILGUN engine txid usage:
// https://github.com/Railgun-Community/engine/blob/main/src/transaction/railgun-txid.ts
//
// Cross-checking Rust implementation with the same derivation and expected value:
// https://github.com/ethereum/kohaku/blob/master/crates/railgun-rs/src/railgun/merkle_tree/merkle_tree.rs
#[allow(dead_code)]
const RAILGUN_MERKLE_ZERO_DECIMAL: &str =
    "2051258411002736885948763699317990061539314419500486054347250703186609807356";

#[allow(dead_code)]
static RAILGUN_MERKLE_ZERO_VALUE: OnceLock<BigUint> = OnceLock::new();

pub(crate) fn field_from_biguint(value: &BigUint) -> Result<Fr, CryptoError> {
    let bytes = value.to_bytes_be();
    let field = Fr::from_be_bytes_mod_order(&bytes);
    let roundtrip = BigUint::from_bytes_be(&field.into_bigint().to_bytes_be());

    if roundtrip == *value { Ok(field) } else { Err(CryptoError::InvalidFieldElement) }
}

pub(crate) fn field_from_canonical_bytes(bytes: &[u8; 32]) -> Result<Fr, CryptoError> {
    let value = BigUint::from_bytes_be(bytes);
    let field = Fr::from_be_bytes_mod_order(bytes);
    let roundtrip = BigUint::from_bytes_be(&field.into_bigint().to_bytes_be());

    if roundtrip == value { Ok(field) } else { Err(CryptoError::InvalidFieldElement) }
}

pub(crate) fn field_from_bytes_mod_order(bytes: &[u8]) -> Fr {
    Fr::from_be_bytes_mod_order(bytes)
}

pub(crate) fn field_to_biguint(field: Fr) -> BigUint {
    BigUint::from_bytes_be(&field.into_bigint().to_bytes_be())
}

pub(crate) fn field_to_canonical_bytes(field: Fr) -> [u8; 32] {
    let bytes = field.into_bigint().to_bytes_be();
    let mut padded = [0_u8; 32];
    let start = 32 - bytes.len();
    padded[start..].copy_from_slice(&bytes);
    padded
}

pub(crate) fn hash_fields(inputs: &[Fr]) -> Result<Fr, CryptoError> {
    if inputs.is_empty() || inputs.len() > PARTIAL_ROUNDS.len() {
        return Err(CryptoError::DerivationFailure);
    }

    let constants = constants::poseidon_constants();
    let width = inputs.len() + 1;
    let partial_rounds = PARTIAL_ROUNDS[width - 2];
    let round_constants = &constants.c[width - 2];
    let sparse_constants = &constants.s[width - 2];
    let mds = &constants.m[width - 2];
    let pre_sparse = &constants.p[width - 2];

    let mut state = Vec::with_capacity(width);
    state.push(Fr::zero());
    state.extend_from_slice(inputs);

    add_round_constants(&mut state, &round_constants[..width]);
    for round in 0..(FULL_ROUNDS / 2) {
        if round == (FULL_ROUNDS / 2) - 1 {
            full_round(
                &mut state,
                &round_constants[(round + 1) * width..(round + 2) * width],
                pre_sparse,
            );
        } else {
            full_round(&mut state, &round_constants[(round + 1) * width..(round + 2) * width], mds);
        }
    }

    for round in 0..partial_rounds {
        state[0] = quintic_s_box(state[0]);
        state[0] += round_constants[(FULL_ROUNDS / 2 + 1) * width + round];
        let state_head = state[0];

        let mut new_first = Fr::zero();
        for (index, value) in state.iter().enumerate() {
            new_first += sparse_constants[(width * 2 - 1) * round + index] * value;
        }

        for index in 1..width {
            state[index] +=
                state_head * sparse_constants[(width * 2 - 1) * round + width + index - 1];
        }
        state[0] = new_first;
    }

    for round in 0..(FULL_ROUNDS / 2) - 1 {
        let round_start = (FULL_ROUNDS / 2 + 1) * width + partial_rounds + round * width;
        full_round(&mut state, &round_constants[round_start..round_start + width], mds);
    }

    apply_s_box(&mut state);
    mix_state(&mut state, mds);

    Ok(state[0])
}

#[allow(dead_code)]
pub(crate) fn railgun_merkle_zero_value() -> &'static BigUint {
    RAILGUN_MERKLE_ZERO_VALUE.get_or_init(|| {
        BigUint::from_str_radix(RAILGUN_MERKLE_ZERO_DECIMAL, 10)
            .unwrap_or_else(|error| panic!("RAILGUN Merkle zero constant should parse: {error}"))
    })
}

#[allow(dead_code)]
pub(crate) fn hash_padded_txid_fields(values: &[BigUint]) -> Result<BigUint, CryptoError> {
    if values.len() > TXID_INPUT_ARITY {
        return Err(CryptoError::DerivationFailure);
    }

    let mut padded = values.iter().map(field_from_biguint_mod_order).collect::<Vec<_>>();
    let merkle_zero = field_from_biguint_mod_order(railgun_merkle_zero_value());
    while padded.len() < TXID_INPUT_ARITY {
        padded.push(merkle_zero);
    }

    hash_fields(&padded).map(field_to_biguint)
}

#[allow(dead_code)]
pub(crate) fn hash_railgun_txid(
    nullifiers: &[BigUint],
    commitments: &[BigUint],
    bound_params_hash: &BigUint,
) -> Result<BigUint, CryptoError> {
    let nullifiers_hash = hash_padded_txid_fields(nullifiers)?;
    let commitments_hash = hash_padded_txid_fields(commitments)?;

    hash_fields(&[
        field_from_biguint_mod_order(&nullifiers_hash),
        field_from_biguint_mod_order(&commitments_hash),
        field_from_biguint_mod_order(bound_params_hash),
    ])
    .map(field_to_biguint)
}

#[allow(dead_code)]
pub(crate) fn hash_railgun_txid_leaf(
    railgun_txid: &BigUint,
    utxo_tree_in: u64,
    global_tree_position: u64,
) -> Result<BigUint, CryptoError> {
    hash_fields(&[
        field_from_biguint_mod_order(railgun_txid),
        Fr::from(utxo_tree_in),
        Fr::from(global_tree_position),
    ])
    .map(field_to_biguint)
}

#[allow(dead_code)]
fn field_from_biguint_mod_order(value: &BigUint) -> Fr {
    Fr::from_be_bytes_mod_order(&value.to_bytes_be())
}

fn add_round_constants(state: &mut [Fr], round_constants: &[Fr]) {
    for (index, value) in state.iter_mut().enumerate() {
        *value += round_constants[index];
    }
}

fn quintic_s_box(value: Fr) -> Fr {
    value.pow([5])
}

fn apply_s_box(state: &mut [Fr]) {
    for value in state {
        *value = quintic_s_box(*value);
    }
}

fn mix_state(state: &mut Vec<Fr>, matrix: &[Vec<Fr>]) {
    let mut mixed = vec![Fr::zero(); state.len()];
    for (row, output) in mixed.iter_mut().enumerate() {
        for (column, value) in state.iter().enumerate() {
            *output += matrix[column][row] * value;
        }
    }
    *state = mixed;
}

fn full_round(state: &mut Vec<Fr>, round_constants: &[Fr], matrix: &[Vec<Fr>]) {
    apply_s_box(state);
    add_round_constants(state, round_constants);
    mix_state(state, matrix);
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use serde::Deserialize;

    use super::{
        field_from_biguint, field_to_biguint, hash_fields, hash_padded_txid_fields,
        hash_railgun_txid, hash_railgun_txid_leaf, railgun_merkle_zero_value,
    };
    use num_bigint::BigUint;
    use num_traits::Num;
    use railgun_types::bn254_scalar_field_modulus;

    #[derive(Deserialize)]
    struct CircomlibjsFixture {
        cases: Vec<CircomlibjsCase>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct CircomlibjsCase {
        name: String,
        arity: usize,
        inputs_decimal: Vec<String>,
        output_decimal: String,
        output_hex: String,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct EngineTxidFixture {
        canonical_merkle_zero_decimal: String,
        canonical_merkle_zero_hex: String,
        cases: Vec<EngineTxidCase>,
        txid_leaf_reference_case: EngineTxidLeafReferenceCase,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct EngineTxidCase {
        name: String,
        nullifiers_hex: Vec<String>,
        commitments_hex: Vec<String>,
        bound_params_hash_hex: String,
        nullifiers_hash_hex: String,
        commitments_hash_hex: String,
        railgun_txid_hex: String,
        utxo_tree_in: u64,
        global_tree_position_decimal: String,
        txid_leaf_hash_hex: String,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct EngineTxidLeafReferenceCase {
        railgun_txid_hex: String,
        utxo_tree_in: u64,
        global_tree_position_decimal: String,
        txid_leaf_hash_hex: String,
    }

    // These committed fixtures are generated by `scripts/poseidon/generate-vectors.mjs`
    // from the public Circom oracle package:
    // https://github.com/Railgun-Community/circomlibjs/blob/main/src/poseidon_opt.js
    #[test]
    fn poseidon_hash_matches_committed_circomlibjs_vectors() {
        let fixture = circomlibjs_fixture();

        for test_case in &fixture.cases {
            let inputs = test_case
                .inputs_decimal
                .iter()
                .map(|value| parse_decimal(value))
                .map(|value| field_from_biguint(&value))
                .collect::<Result<Vec<_>, _>>()
                .unwrap_or_else(|_| panic!("fixture inputs should be canonical field elements"));

            assert_eq!(inputs.len(), test_case.arity, "fixture arity should match input count");

            let actual = hash_fields(&inputs).map(field_to_biguint);
            let expected_decimal = parse_decimal(&test_case.output_decimal);
            let expected_hex = parse_hex(&test_case.output_hex);

            assert_eq!(
                actual,
                Ok(expected_decimal.clone()),
                "decimal parity mismatch for fixture {}",
                test_case.name,
            );
            assert_eq!(expected_decimal, expected_hex, "fixture decimal/hex outputs should agree");
        }
    }

    // These committed fixtures are generated by `scripts/poseidon/generate-vectors.mjs`
    // from the public engine txid path:
    // https://github.com/Railgun-Community/engine/blob/main/src/transaction/railgun-txid.ts
    #[test]
    fn txid_helpers_match_committed_engine_vectors() {
        let fixture = engine_txid_fixture();

        assert_eq!(
            railgun_merkle_zero_value(),
            &parse_decimal(&fixture.canonical_merkle_zero_decimal),
            "canonical RAILGUN Merkle zero decimal should match engine fixture",
        );
        assert_eq!(
            railgun_merkle_zero_value(),
            &parse_hex(&fixture.canonical_merkle_zero_hex),
            "canonical RAILGUN Merkle zero hex should match engine fixture",
        );

        for test_case in &fixture.cases {
            let nullifiers =
                test_case.nullifiers_hex.iter().map(|value| parse_hex(value)).collect::<Vec<_>>();
            let commitments =
                test_case.commitments_hex.iter().map(|value| parse_hex(value)).collect::<Vec<_>>();
            let bound_params_hash = parse_hex(&test_case.bound_params_hash_hex);

            assert_eq!(
                hash_padded_txid_fields(&nullifiers),
                Ok(parse_hex(&test_case.nullifiers_hash_hex)),
                "nullifier padded hash mismatch for fixture {}",
                test_case.name,
            );
            assert_eq!(
                hash_padded_txid_fields(&commitments),
                Ok(parse_hex(&test_case.commitments_hash_hex)),
                "commitment padded hash mismatch for fixture {}",
                test_case.name,
            );
            assert_eq!(
                hash_railgun_txid(&nullifiers, &commitments, &bound_params_hash),
                Ok(parse_hex(&test_case.railgun_txid_hex)),
                "txid hash mismatch for fixture {}",
                test_case.name,
            );
            assert_eq!(
                hash_railgun_txid_leaf(
                    &parse_hex(&test_case.railgun_txid_hex),
                    test_case.utxo_tree_in,
                    parse_decimal(&test_case.global_tree_position_decimal)
                        .try_into()
                        .unwrap_or_else(|_| panic!("global tree position should fit into u64")),
                ),
                Ok(parse_hex(&test_case.txid_leaf_hash_hex)),
                "txid leaf hash mismatch for fixture {}",
                test_case.name,
            );
        }
    }

    #[test]
    fn committed_poseidon_fixtures_include_expected_edge_cases() {
        let circom_case_names = circomlibjs_fixture()
            .cases
            .iter()
            .map(|test_case| test_case.name.as_str())
            .collect::<BTreeSet<_>>();
        let engine_case_names = engine_txid_fixture()
            .cases
            .iter()
            .map(|test_case| test_case.name.as_str())
            .collect::<BTreeSet<_>>();

        assert!(
            circom_case_names.contains("near_modulus_descending_arity_13"),
            "circom fixture should include near-modulus arity-13 coverage"
        );
        assert!(
            circom_case_names.contains("alternating_zero_one_arity_8"),
            "circom fixture should include alternating-pattern coverage"
        );
        assert!(
            engine_case_names.contains("empty_inputs"),
            "engine fixture should include empty txid-side coverage"
        );
        assert!(
            engine_case_names.contains("near_modulus_values"),
            "engine fixture should include modulo-normalization coverage"
        );
    }

    #[test]
    fn padded_txid_hash_rejects_more_than_thirteen_values() {
        let values = (0_u8..=13).map(BigUint::from).collect::<Vec<_>>();

        assert!(
            hash_padded_txid_fields(&values).is_err(),
            "txid padding helper should reject oversized inputs"
        );
    }

    #[test]
    fn txid_helpers_reduce_inputs_mod_field_order() {
        let modulus = bn254_scalar_field_modulus();

        let unreduced = vec![
            &modulus + BigUint::from(5_u8),
            (&modulus * BigUint::from(2_u8)) + BigUint::from(9_u8),
        ];
        let reduced = vec![BigUint::from(5_u8), BigUint::from(9_u8)];

        assert_eq!(
            hash_padded_txid_fields(&unreduced),
            hash_padded_txid_fields(&reduced),
            "txid helper should hash values after modulo field reduction"
        );
    }

    #[test]
    fn txid_leaf_reference_case_matches_committed_engine_fixture() {
        let fixture = engine_txid_fixture();
        let reference = &fixture.txid_leaf_reference_case;

        assert_eq!(
            hash_railgun_txid_leaf(
                &parse_hex(&reference.railgun_txid_hex),
                reference.utxo_tree_in,
                parse_decimal(&reference.global_tree_position_decimal).try_into().unwrap_or_else(
                    |_| panic!("reference global tree position should fit into u64")
                ),
            ),
            Ok(parse_hex(&reference.txid_leaf_hash_hex)),
        );
    }

    fn circomlibjs_fixture() -> &'static CircomlibjsFixture {
        static FIXTURE: std::sync::OnceLock<CircomlibjsFixture> = std::sync::OnceLock::new();
        FIXTURE.get_or_init(|| {
            serde_json::from_str(include_str!("../../testdata/poseidon/circomlibjs.json"))
                .unwrap_or_else(|error| {
                    panic!("circomlibjs poseidon fixture should parse: {error}")
                })
        })
    }

    fn engine_txid_fixture() -> &'static EngineTxidFixture {
        static FIXTURE: std::sync::OnceLock<EngineTxidFixture> = std::sync::OnceLock::new();
        FIXTURE.get_or_init(|| {
            serde_json::from_str(include_str!("../../testdata/poseidon/engine-txid.json"))
                .unwrap_or_else(|error| {
                    panic!("engine txid poseidon fixture should parse: {error}")
                })
        })
    }

    fn parse_decimal(value: &str) -> BigUint {
        BigUint::from_str_radix(value, 10)
            .unwrap_or_else(|error| panic!("fixture decimal value should parse: {error}"))
    }

    fn parse_hex(value: &str) -> BigUint {
        let trimmed = value.strip_prefix("0x").unwrap_or(value);
        BigUint::from_str_radix(trimmed, 16)
            .unwrap_or_else(|error| panic!("fixture hex value should parse: {error}"))
    }
}
