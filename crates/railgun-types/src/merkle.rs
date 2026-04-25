use crate::ParseDomainError;

/// Canonical Merkle tree depth used by local UTXO and txid proof helpers.
pub const TREE_DEPTH: usize = 16;

/// Typed 32-byte Merkle leaf hash used for UTXO and txid membership checks.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct MerkleNodeHash([u8; 32]);

impl MerkleNodeHash {
    /// Length of a Merkle node hash in bytes.
    pub const LENGTH: usize = 32;

    /// Creates a Merkle node hash from raw bytes.
    #[must_use]
    pub const fn new(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    /// Creates a Merkle node hash from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns an error if `bytes` is not exactly 32 bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ParseDomainError> {
        let array: [u8; Self::LENGTH] = bytes
            .try_into()
            .map_err(|_| ParseDomainError::new("merkle node hash must be exactly 32 bytes"))?;
        Ok(Self::new(array))
    }

    /// Returns the raw Merkle node-hash bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}

/// Typed 32-byte Merkle root.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct MerkleRoot([u8; 32]);

impl MerkleRoot {
    /// Length of a Merkle root in bytes.
    pub const LENGTH: usize = 32;

    /// Creates a Merkle root from raw bytes.
    #[must_use]
    pub const fn new(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    /// Creates a Merkle root from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns an error if `bytes` is not exactly 32 bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ParseDomainError> {
        let array: [u8; Self::LENGTH] = bytes
            .try_into()
            .map_err(|_| ParseDomainError::new("merkle root must be exactly 32 bytes"))?;
        Ok(Self::new(array))
    }

    /// Returns the raw Merkle-root bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}

/// Typed 32-byte Merkle proof index bitfield.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct MerkleProofIndices([u8; 32]);

impl MerkleProofIndices {
    /// Length of the proof index bitfield in bytes.
    pub const LENGTH: usize = 32;

    /// Creates a Merkle proof index bitfield from raw bytes.
    #[must_use]
    pub const fn new(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    /// Creates a Merkle proof index bitfield from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns an error if `bytes` is not exactly 32 bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ParseDomainError> {
        let array: [u8; Self::LENGTH] = bytes
            .try_into()
            .map_err(|_| ParseDomainError::new("merkle proof indices must be exactly 32 bytes"))?;
        Ok(Self::new(array))
    }

    /// Returns the raw proof-index bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}

/// Typed 32-byte Merkle proof path element.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct MerkleProofElement([u8; 32]);

impl MerkleProofElement {
    /// Length of one Merkle proof path element in bytes.
    pub const LENGTH: usize = 32;

    /// Creates a proof element from raw bytes.
    #[must_use]
    pub const fn new(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    /// Creates a proof element from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns an error if `bytes` is not exactly 32 bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ParseDomainError> {
        let array: [u8; Self::LENGTH] = bytes
            .try_into()
            .map_err(|_| ParseDomainError::new("merkle proof element must be exactly 32 bytes"))?;
        Ok(Self::new(array))
    }

    /// Returns the raw path-element bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}

/// Canonical Merkle proof model used for local membership verification.
///
/// The leaf is provided separately to verification helpers so the same proof
/// model can be reused across UTXO and txid membership checks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MerkleProof {
    root: MerkleRoot,
    indices: MerkleProofIndices,
    elements: Vec<MerkleProofElement>,
}

impl MerkleProof {
    /// Creates a Merkle proof from explicit typed components.
    ///
    /// # Errors
    ///
    /// Returns an error if `elements` does not contain exactly `TREE_DEPTH`
    /// path elements.
    pub fn new(
        root: MerkleRoot,
        indices: MerkleProofIndices,
        elements: Vec<MerkleProofElement>,
    ) -> Result<Self, ParseDomainError> {
        if elements.len() != TREE_DEPTH {
            return Err(ParseDomainError::new(
                "merkle proof must contain exactly TREE_DEPTH path elements",
            ));
        }

        Ok(Self { root, indices, elements })
    }

    /// Returns the Merkle root.
    #[must_use]
    pub const fn root(&self) -> &MerkleRoot {
        &self.root
    }

    /// Returns the proof index bitfield.
    #[must_use]
    pub const fn indices(&self) -> &MerkleProofIndices {
        &self.indices
    }

    /// Returns the Merkle proof path elements.
    #[must_use]
    pub fn elements(&self) -> &[MerkleProofElement] {
        &self.elements
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MerkleNodeHash, MerkleProof, MerkleProofElement, MerkleProofIndices, MerkleRoot,
        ParseDomainError, TREE_DEPTH,
    };

    #[test]
    fn rejects_invalid_merkle_node_hash_length() {
        let Err(error) = MerkleNodeHash::from_slice(&[7_u8; 31]) else {
            panic!("invalid merkle node hash length should fail");
        };

        assert_eq!(error, ParseDomainError::new("merkle node hash must be exactly 32 bytes"));
    }

    #[test]
    fn rejects_invalid_merkle_root_length() {
        let Err(error) = MerkleRoot::from_slice(&[7_u8; 31]) else {
            panic!("invalid merkle root length should fail");
        };

        assert_eq!(error, ParseDomainError::new("merkle root must be exactly 32 bytes"));
    }

    #[test]
    fn rejects_invalid_merkle_indices_length() {
        let Err(error) = MerkleProofIndices::from_slice(&[7_u8; 31]) else {
            panic!("invalid merkle proof indices length should fail");
        };

        assert_eq!(error, ParseDomainError::new("merkle proof indices must be exactly 32 bytes"));
    }

    #[test]
    fn rejects_invalid_merkle_element_length() {
        let Err(error) = MerkleProofElement::from_slice(&[7_u8; 31]) else {
            panic!("invalid merkle proof element length should fail");
        };

        assert_eq!(error, ParseDomainError::new("merkle proof element must be exactly 32 bytes"));
    }

    #[test]
    fn merkle_proof_preserves_typed_fields() {
        let root = MerkleRoot::new([1_u8; 32]);
        let indices = MerkleProofIndices::new([2_u8; 32]);
        let elements = vec![MerkleProofElement::new([3_u8; 32]); TREE_DEPTH];
        let proof = MerkleProof::new(root, indices, elements.clone())
            .unwrap_or_else(|error| panic!("valid proof should construct: {error}"));

        assert_eq!(proof.root(), &root);
        assert_eq!(proof.indices(), &indices);
        assert_eq!(proof.elements(), elements.as_slice());
    }

    #[test]
    fn rejects_invalid_merkle_proof_length() {
        let Err(error) = MerkleProof::new(
            MerkleRoot::new([1_u8; 32]),
            MerkleProofIndices::new([2_u8; 32]),
            vec![MerkleProofElement::new([3_u8; 32]); TREE_DEPTH - 1],
        ) else {
            panic!("invalid proof element count should fail");
        };

        assert_eq!(
            error,
            ParseDomainError::new("merkle proof must contain exactly TREE_DEPTH path elements")
        );
    }
}
