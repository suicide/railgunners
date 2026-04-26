//! Canonical Merkle proof creation and local verification.

use railgun_types::{
    MerkleNodeHash, MerkleProof, MerkleProofElement, MerkleProofIndices, MerkleRoot, TREE_DEPTH,
};
use num_bigint::BigUint;

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
    use ark_bn254::Fr;
    use ark_ff::{BigInteger, PrimeField};
    use light_poseidon::{Poseidon, PoseidonHasher};
    use railgun_types::{MerkleProofElement, MerkleProofIndices, MerkleRoot};

    use super::{
        MerkleNodeHash, MerkleProof, MerkleProofError, create_dummy_merkle_proof,
        verify_merkle_proof,
    };

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
        let mut poseidon = Poseidon::<Fr>::new_circom(3)
            .unwrap_or_else(|_| panic!("three-input poseidon should initialize"));
        let hash = poseidon
            .hash(&[
                Fr::from_be_bytes_mod_order(&decode_hex::<32>(railgun_txid)),
                Fr::from(utxo_tree_in),
                Fr::from(global_tree_position),
            ])
            .unwrap_or_else(|_| panic!("txid leaf hash should derive"));

        let bytes = hash.into_bigint().to_bytes_be();
        let mut padded = [0_u8; 32];
        let start = 32 - bytes.len();
        padded[start..].copy_from_slice(&bytes);
        MerkleNodeHash::new(padded)
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
        let leaf = txid_leaf_hash(
            "018d6143a22e09c18ba2a713985bd1e43a095605d5d259d72d96da2cca604f3e",
            0,
            1,
        );
        let elements = [
            "0488f89b25bc7011eaf6a5edce71aeafb9fe706faa3c0a5cd9cbe868ae3b9ffc",
            "01c405064436affeae1fc8e30b2e417b4243bbb819adca3b55bb32efc3e43a4f",
            "0888d37652d10d1781db54b70af87b42a2916e87118f507218f9a42a58e85ed2",
            "183f531ead7217ebc316b4c02a2aad5ad87a1d56d4fb9ed81bf84f644549eaf5",
            "093c48f1ecedf2baec231f0af848a57a76c6cf05b290a396707972e1defd17df",
            "1437bb465994e0453357c17a676b9fdba554e215795ebc17ea5012770dfb77c7",
            "12359ef9572912b49f44556b8bbbfa69318955352f54cfa35cb0f41309ed445a",
            "2dc656dadc82cf7a4707786f4d682b0f130b6515f7927bde48214d37ec25a46c",
            "2500bdfc1592791583acefd050bc439a87f1d8e8697eb773e8e69b44973e6fdc",
            "244ae3b19397e842778b254cd15c037ed49190141b288ff10eb1390b34dc2c31",
            "0ca2b107491c8ca6e5f7e22403ea8529c1e349a1057b8713e09ca9f5b9294d46",
            "18593c75a9e42af27b5e5b56b99c4c6a5d7e7d6e362f00c8e3f69aeebce52313",
            "17aca915b237b04f873518947a1f440f0c1477a6ac79299b3be46858137d4bfb",
            "2726c22ad3d9e23414887e8233ee83cc51603f58c48a9c9e33cb1f306d4365c0",
            "08c5bd0f85cef2f8c3c1412a2b69ee943c6925ecf79798bb2b84e1b76d26871f",
            "27f7c465045e0a4d8bec7c13e41d793734c50006ca08920732ce8c3096261435",
        ]
        .into_iter()
        .map(|element| MerkleProofElement::new(decode_hex::<32>(element)))
        .collect();
        let proof = MerkleProof::new(
            MerkleRoot::new(decode_hex::<32>(
                "185cc7d2c8e1c3954ee5421a6589cd05036708ff059b97b9c10e0261ad7d6875",
            )),
            MerkleProofIndices::new([0_u8; 32]),
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
}
