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
    use ark_bn254::Fr;

    use super::{
        field_from_biguint, field_to_biguint, hash_fields, hash_padded_txid_fields,
        hash_railgun_txid, railgun_merkle_zero_value,
    };
    use num_bigint::BigUint;
    use num_traits::Num;

    // Expected outputs copied from Kohaku's public Poseidon regression test for
    // sequential `[0, 1, ..., n]` inputs across arities 1..=13:
    // https://github.com/ethereum/kohaku/blob/master/crates/poseidon-rust/src/lib.rs
    #[test]
    fn poseidon_hash_matches_kohaku_sequential_vectors_for_arity_one_through_thirteen() {
        let expected = [
            "19014214495641488759237505126948346942972912379615652741039992445865937985820",
            "12583541437132735734108669866114103169564651237895298778035846191048104863326",
            "8599452571108419911675042369134657596129797276905188988960674134744449929238",
            "4050345352754260300667252706570081029004026400044882557845061748628670512780",
            "1475992993236322576209363326357087103599755887159177217587002895783839174540",
            "2579592068985894564663884204285667087640059297900666937160965942401359072100",
            "20329113756446417239599955060882819799955615300225172556927540370625639639591",
            "21656500796439224421257401895129482535503528269793362483330745763391692399728",
            "14408976789489036679302672303794802454823291363240129034501311453268715567967",
            "830312311503515836401584074612726804626276011883476452565502338584358217994",
            "16482319307391173079257078223199649745782806293396026512574082249553342763664",
            "9229882540043959809176016464298330440879059374171305180729988720176368448252",
            "14044108921269203222904300236541952095368226907391252621253021080476169222351",
        ];

        for (arity, expected_hash) in expected.iter().enumerate() {
            let inputs = (0..=arity)
                .map(|value| field_from_biguint(&BigUint::from(value)))
                .collect::<Result<Vec<_>, _>>()
                .unwrap_or_else(|_| panic!("small test field elements should validate"));

            assert_eq!(
                hash_fields(&inputs).map(field_to_biguint),
                Ok(BigUint::from_str_radix(expected_hash, 10)
                    .unwrap_or_else(|error| panic!("expected decimal hash should parse: {error}")))
            );
        }
    }

    // Expected outputs copied from Lightprotocol's public Circom-compatible
    // repeated-one vectors for arities 1..=12:
    // https://github.com/Lightprotocol/light-poseidon/blob/main/light-poseidon/tests/bn254_fq_x5.rs
    #[test]
    fn poseidon_hash_matches_light_poseidon_repeated_one_vectors_for_arity_one_through_twelve() {
        let expected = [
            "29176100eaa962bdc1fe6c654d6a3c130e96a4d1168b33848b897dc502820133",
            "007af346e2d304279e79e0a9f3023f771294a78acb70e73f90afe27cad401e81",
            "02c0066e10a72abd2b33c3b214cb3e81bcb1b6e30961cd23c202b18673bf2543",
            "082c9c370a0d24f4416fbc414a37681f78442d27d86385991c17d6fc0c4b7d71",
            "10389605ae688d4f14db853122c47d66a803c72b41589cb1bf868741b206b9bb",
            "2a73f679328c3eab724aa3e5bdbf50b39035d7729f135b9709890f85c5dc5e76",
            "2276310aa7f3343a284214139d9da959be2a31b2c708a5f81954b265e53a30b8",
            "177e1453c446e1b07d2b4233425147095c4fcabb233d230b6d46a214d95b2884",
            "0e8fee2fe49da30fdeeb48c42ebb44cc6ee7055f61fbca5e313b8a5fca834c47",
            "2ec4c65e6378ab8c7330854f4a7077c1ff9260e44885c4b81dd131ad3a86cd96",
            "00713d41eca635f117d4ecbceb5f3a66dc4142eb70b56765bc358f1bec40bb9b",
            "14390be0baef249bd47c65ddac65c2e52e8513c081c1cd72c98006098e9a8fbe",
        ];

        for (arity, expected_hash) in expected.iter().enumerate() {
            let inputs = vec![Fr::from(1_u8); arity + 1];
            assert_eq!(
                hash_fields(&inputs).map(field_to_biguint),
                Ok(BigUint::from_str_radix(expected_hash, 16)
                    .unwrap_or_else(|error| panic!("expected hex hash should parse: {error}")))
            );
        }
    }

    // This checks the canonical RAILGUN txid padding behavior used by the public
    // engine and broadcaster implementations:
    // https://github.com/Railgun-Community/engine/blob/main/src/transaction/railgun-txid.ts
    // https://github.com/suicide/railgun-broadcaster/blob/main/crates/core/src/transact.rs
    #[test]
    fn padded_txid_hash_uses_canonical_railgun_merkle_zero_value() {
        let values = [BigUint::from(1_u8), BigUint::from(2_u8)];
        let expected = hash_fields(&[
            Fr::from(1_u8),
            Fr::from(2_u8),
            field_from_biguint(railgun_merkle_zero_value())
                .unwrap_or_else(|_| panic!("canonical RAILGUN Merkle zero should fit the field")),
            field_from_biguint(railgun_merkle_zero_value())
                .unwrap_or_else(|_| panic!("canonical RAILGUN Merkle zero should fit the field")),
            field_from_biguint(railgun_merkle_zero_value())
                .unwrap_or_else(|_| panic!("canonical RAILGUN Merkle zero should fit the field")),
            field_from_biguint(railgun_merkle_zero_value())
                .unwrap_or_else(|_| panic!("canonical RAILGUN Merkle zero should fit the field")),
            field_from_biguint(railgun_merkle_zero_value())
                .unwrap_or_else(|_| panic!("canonical RAILGUN Merkle zero should fit the field")),
            field_from_biguint(railgun_merkle_zero_value())
                .unwrap_or_else(|_| panic!("canonical RAILGUN Merkle zero should fit the field")),
            field_from_biguint(railgun_merkle_zero_value())
                .unwrap_or_else(|_| panic!("canonical RAILGUN Merkle zero should fit the field")),
            field_from_biguint(railgun_merkle_zero_value())
                .unwrap_or_else(|_| panic!("canonical RAILGUN Merkle zero should fit the field")),
            field_from_biguint(railgun_merkle_zero_value())
                .unwrap_or_else(|_| panic!("canonical RAILGUN Merkle zero should fit the field")),
            field_from_biguint(railgun_merkle_zero_value())
                .unwrap_or_else(|_| panic!("canonical RAILGUN Merkle zero should fit the field")),
            field_from_biguint(railgun_merkle_zero_value())
                .unwrap_or_else(|_| panic!("canonical RAILGUN Merkle zero should fit the field")),
        ])
        .map(field_to_biguint);

        assert_eq!(hash_padded_txid_fields(&values), expected);
    }

    #[test]
    fn padded_txid_hash_rejects_more_than_thirteen_values() {
        let values = (0_u8..=13).map(BigUint::from).collect::<Vec<_>>();

        assert!(
            hash_padded_txid_fields(&values).is_err(),
            "txid padding helper should reject oversized inputs"
        );
    }

    // Txid helper composition matches the public engine's
    // `poseidon([nullifiersHash, commitmentsHash, boundParamsHash])` flow:
    // https://github.com/Railgun-Community/engine/blob/main/src/transaction/railgun-txid.ts
    #[test]
    fn txid_hash_matches_expected_composition() {
        let nullifiers = [BigUint::from(1_u8), BigUint::from(2_u8)];
        let commitments = [BigUint::from(3_u8), BigUint::from(4_u8), BigUint::from(5_u8)];
        let bound_params_hash = BigUint::from(6_u8);

        let nullifiers_hash = hash_padded_txid_fields(&nullifiers)
            .unwrap_or_else(|_| panic!("nullifier hash should derive"));
        let commitments_hash = hash_padded_txid_fields(&commitments)
            .unwrap_or_else(|_| panic!("commitment hash should derive"));

        assert_eq!(
            hash_railgun_txid(&nullifiers, &commitments, &bound_params_hash),
            hash_fields(&[
                field_from_biguint(&nullifiers_hash)
                    .unwrap_or_else(|_| panic!("nullifier hash should be canonical field element")),
                field_from_biguint(&commitments_hash).unwrap_or_else(|_| panic!(
                    "commitment hash should be canonical field element"
                )),
                Fr::from(6_u8),
            ])
            .map(field_to_biguint),
        );
    }
}
