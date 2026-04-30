//! Canonical Merkle proof creation and local verification.

use num_bigint::BigUint;
use railgun_types::{
    MerkleNodeHash, MerkleProof, MerkleProofElement, MerkleProofIndices, MerkleRoot, TREE_DEPTH,
};

use crate::crypto::poseidon;

/// Error returned when local Merkle proof verification inputs are malformed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MerkleProofError {
    /// The leaf hash is not a valid BN254 field element.
    InvalidLeafHash,
    /// One Merkle proof element is not a valid BN254 field element.
    InvalidPathElement(usize),
    /// Poseidon hashing failed unexpectedly.
    HashingFailure,
}

impl core::fmt::Display for MerkleProofError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidLeafHash => formatter.write_str("invalid merkle leaf hash"),
            Self::InvalidPathElement(index) => {
                write!(formatter, "invalid merkle proof path element at index {index}")
            }
            Self::HashingFailure => formatter.write_str("failed to hash merkle proof path"),
        }
    }
}

impl std::error::Error for MerkleProofError {}

fn field_from_hash_bytes(bytes: &[u8; 32]) -> Result<ark_bn254::Fr, MerkleProofError> {
    poseidon::field_from_canonical_bytes(bytes).map_err(|_| MerkleProofError::HashingFailure)
}

fn merkle_node_hash_from_field(field: ark_bn254::Fr) -> MerkleNodeHash {
    MerkleNodeHash::new(poseidon::field_to_canonical_bytes(field))
}

fn hash_left_right(
    left: &MerkleNodeHash,
    right: &MerkleProofElement,
) -> Result<MerkleNodeHash, MerkleProofError> {
    let left =
        field_from_hash_bytes(left.as_bytes()).map_err(|_| MerkleProofError::InvalidLeafHash)?;
    let right =
        field_from_hash_bytes(right.as_bytes()).map_err(|_| MerkleProofError::HashingFailure)?;
    let hash =
        poseidon::hash_fields(&[left, right]).map_err(|_| MerkleProofError::HashingFailure)?;

    Ok(merkle_node_hash_from_field(hash))
}

fn hash_pair(
    left: &MerkleNodeHash,
    right: &MerkleNodeHash,
) -> Result<MerkleNodeHash, MerkleProofError> {
    let left =
        field_from_hash_bytes(left.as_bytes()).map_err(|_| MerkleProofError::InvalidLeafHash)?;
    let right =
        field_from_hash_bytes(right.as_bytes()).map_err(|_| MerkleProofError::HashingFailure)?;
    let hash =
        poseidon::hash_fields(&[left, right]).map_err(|_| MerkleProofError::HashingFailure)?;

    Ok(merkle_node_hash_from_field(hash))
}

/// Creates the canonical dummy Merkle proof used by validation flows.
///
/// The dummy proof uses `TREE_DEPTH = 16`, an all-zero index bitfield, and
/// zero-filled sibling elements, matching upstream test behavior exactly.
///
/// # Errors
///
/// Returns an error if `leaf` is not a valid BN254 field element or if
/// Poseidon hashing fails unexpectedly.
pub fn create_dummy_merkle_proof(leaf: &MerkleNodeHash) -> Result<MerkleProof, MerkleProofError> {
    let _ =
        field_from_hash_bytes(leaf.as_bytes()).map_err(|_| MerkleProofError::InvalidLeafHash)?;

    let zero_element = MerkleProofElement::new([0_u8; MerkleProofElement::LENGTH]);
    let mut current = *leaf;
    let mut elements = Vec::with_capacity(TREE_DEPTH);

    for _ in 0..TREE_DEPTH {
        current = hash_left_right(&current, &zero_element)?;
        elements.push(zero_element);
    }

    MerkleProof::new(
        MerkleRoot::new(*current.as_bytes()),
        MerkleProofIndices::new([0_u8; MerkleProofIndices::LENGTH]),
        elements,
    )
    .map_err(|_| MerkleProofError::HashingFailure)
}

/// Verifies a Merkle proof against an explicit leaf hash.
///
/// # Errors
///
/// Returns an error if the leaf or any proof path element is not a valid BN254
/// field element or if Poseidon hashing fails unexpectedly.
pub fn verify_merkle_proof(
    leaf: &MerkleNodeHash,
    proof: &MerkleProof,
) -> Result<bool, MerkleProofError> {
    let _ =
        field_from_hash_bytes(leaf.as_bytes()).map_err(|_| MerkleProofError::InvalidLeafHash)?;
    let indices = BigUint::from_bytes_be(proof.indices().as_bytes());
    let mut current = *leaf;

    for (index, element) in proof.elements().iter().enumerate() {
        let bit_mask = BigUint::from(1_u8) << index;
        let sibling = MerkleNodeHash::new(*element.as_bytes());

        if field_from_hash_bytes(element.as_bytes()).is_err() {
            return Err(MerkleProofError::InvalidPathElement(index));
        }

        current = if (&indices & &bit_mask) == BigUint::default() {
            hash_pair(&current, &sibling)
                .map_err(|_| MerkleProofError::InvalidPathElement(index))?
        } else {
            hash_pair(&sibling, &current)
                .map_err(|_| MerkleProofError::InvalidPathElement(index))?
        };
    }

    Ok(current.as_bytes() == proof.root().as_bytes())
}

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;
    use num_traits::Num;
    use railgun_types::{MerkleProofElement, MerkleProofIndices, MerkleRoot};
    use serde::Deserialize;

    use crate::crypto::poseidon;

    use super::{
        MerkleNodeHash, MerkleProof, MerkleProofError, create_dummy_merkle_proof,
        verify_merkle_proof,
    };

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct EngineMerkleProofFixture {
        case: EngineMerkleProofCase,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct EngineMerkleProofCase {
        railgun_txid_hex: String,
        utxo_tree_in: u64,
        global_tree_position: u64,
        merkle_root_hex: String,
        indices_hex: String,
        path_elements_hex: Vec<String>,
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

    fn merkle_hash(value: &str) -> MerkleNodeHash {
        MerkleNodeHash::from_slice(&decode_hex::<32>(value))
            .unwrap_or_else(|error| panic!("expected valid merkle hash bytes: {error}"))
    }

    fn txid_leaf_hash(
        railgun_txid: &str,
        utxo_tree_in: u64,
        global_tree_position: u64,
    ) -> MerkleNodeHash {
        let txid = BigUint::from_str_radix(railgun_txid, 16)
            .unwrap_or_else(|error| panic!("txid hex should parse: {error}"));
        let hash = poseidon::hash_railgun_txid_leaf(&txid, utxo_tree_in, global_tree_position)
            .unwrap_or_else(|_| panic!("txid leaf hash should derive"));
        MerkleNodeHash::new(poseidon::field_to_canonical_bytes(
            poseidon::field_from_biguint(&hash)
                .unwrap_or_else(|_| panic!("txid leaf hash should be canonical field element")),
        ))
    }

    #[test]
    fn dummy_merkle_proof_has_canonical_shape_and_verifies() {
        let leaf = merkle_hash("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
        let proof = create_dummy_merkle_proof(&leaf)
            .unwrap_or_else(|error| panic!("dummy proof should construct: {error}"));

        assert_eq!(proof.elements().len(), 16);
        assert!(proof.elements().iter().all(|element| element.as_bytes() == &[0_u8; 32]));
        assert!(
            verify_merkle_proof(&leaf, &proof)
                .unwrap_or_else(|error| panic!("dummy proof should verify: {error}"))
        );
    }

    #[test]
    fn verifies_upstream_txid_merkle_proof_vector() {
        let fixture = engine_merkle_proof_fixture();
        let leaf = txid_leaf_hash(
            &fixture.case.railgun_txid_hex,
            fixture.case.utxo_tree_in,
            fixture.case.global_tree_position,
        );
        let elements = fixture
            .case
            .path_elements_hex
            .iter()
            .map(|element| MerkleProofElement::new(decode_hex::<32>(element)))
            .collect();
        let proof = MerkleProof::new(
            MerkleRoot::new(decode_hex::<32>(&fixture.case.merkle_root_hex)),
            MerkleProofIndices::new(decode_hex::<32>(&fixture.case.indices_hex)),
            elements,
        )
        .unwrap_or_else(|error| panic!("upstream proof vector should construct: {error}"));

        assert!(
            verify_merkle_proof(&leaf, &proof)
                .unwrap_or_else(|error| panic!("upstream proof vector should verify: {error}"))
        );
    }

    #[test]
    fn verification_fails_for_mutated_root() {
        let leaf = merkle_hash("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
        let proof = create_dummy_merkle_proof(&leaf)
            .unwrap_or_else(|error| panic!("dummy proof should construct: {error}"));
        let mutated = MerkleProof::new(
            MerkleRoot::new([7_u8; 32]),
            *proof.indices(),
            proof.elements().to_vec(),
        )
        .unwrap_or_else(|error| panic!("mutated proof should construct: {error}"));

        assert!(
            !verify_merkle_proof(&leaf, &mutated)
                .unwrap_or_else(|error| panic!("mutated proof should still evaluate: {error}"))
        );
    }

    #[test]
    fn verification_fails_for_mutated_indices() {
        let leaf = merkle_hash("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
        let proof = create_dummy_merkle_proof(&leaf)
            .unwrap_or_else(|error| panic!("dummy proof should construct: {error}"));
        let mutated = MerkleProof::new(
            *proof.root(),
            MerkleProofIndices::new([1_u8; 32]),
            proof.elements().to_vec(),
        )
        .unwrap_or_else(|error| panic!("mutated proof should construct: {error}"));

        assert!(
            !verify_merkle_proof(&leaf, &mutated)
                .unwrap_or_else(|error| panic!("mutated proof should still evaluate: {error}"))
        );
    }

    #[test]
    fn verification_fails_for_mutated_path_element() {
        let leaf = merkle_hash("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
        let proof = create_dummy_merkle_proof(&leaf)
            .unwrap_or_else(|error| panic!("dummy proof should construct: {error}"));
        let mut elements = proof.elements().to_vec();
        elements[0] = MerkleProofElement::new([9_u8; 32]);
        let mutated = MerkleProof::new(*proof.root(), *proof.indices(), elements)
            .unwrap_or_else(|error| panic!("mutated proof should construct: {error}"));

        assert!(
            !verify_merkle_proof(&leaf, &mutated)
                .unwrap_or_else(|error| panic!("mutated proof should still evaluate: {error}"))
        );
    }

    #[test]
    fn rejects_invalid_leaf_field_element() {
        let leaf = MerkleNodeHash::new([0xff_u8; 32]);
        let Err(error) = create_dummy_merkle_proof(&leaf) else {
            panic!("invalid leaf field element should be rejected deterministically");
        };

        assert_eq!(error, MerkleProofError::InvalidLeafHash);
    }

    fn engine_merkle_proof_fixture() -> &'static EngineMerkleProofFixture {
        static FIXTURE: std::sync::OnceLock<EngineMerkleProofFixture> = std::sync::OnceLock::new();
        FIXTURE.get_or_init(|| {
            serde_json::from_str(include_str!("../testdata/poseidon/engine-txid-merkle-proof.json"))
                .unwrap_or_else(|error| {
                    panic!("engine txid merkle proof fixture should parse: {error}")
                })
        })
    }
}
