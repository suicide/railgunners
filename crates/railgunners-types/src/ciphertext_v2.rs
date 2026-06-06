use crate::{MasterPublicKey, NoteRandom, NoteValue, ParseDomainError, TokenHash};

/// Typed 32-byte V2 ciphertext block.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct V2CiphertextBlock([u8; 32]);

impl V2CiphertextBlock {
    /// Length of a V2 ciphertext block in bytes.
    pub const LENGTH: usize = 32;

    /// Creates a ciphertext block from raw bytes.
    #[must_use]
    pub const fn new(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    /// Creates a ciphertext block from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns an error if `bytes` is not exactly 32 bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ParseDomainError> {
        let array: [u8; Self::LENGTH] = bytes
            .try_into()
            .map_err(|_| ParseDomainError::new("v2 ciphertext block must be exactly 32 bytes"))?;
        Ok(Self::new(array))
    }

    /// Returns the raw ciphertext-block bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}

/// Canonical V2 note plaintext layout.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct V2Plaintext {
    encoded_master_public_key: MasterPublicKey,
    token_hash: TokenHash,
    random: NoteRandom,
    value: NoteValue,
    memo: Vec<u8>,
}

impl V2Plaintext {
    /// Creates a V2 plaintext payload from explicit components.
    #[must_use]
    pub fn new(
        encoded_master_public_key: MasterPublicKey,
        token_hash: TokenHash,
        random: NoteRandom,
        value: NoteValue,
        memo: Vec<u8>,
    ) -> Self {
        Self { encoded_master_public_key, token_hash, random, value, memo }
    }

    /// Returns the encoded master public key.
    #[must_use]
    pub const fn encoded_master_public_key(&self) -> &MasterPublicKey {
        &self.encoded_master_public_key
    }

    /// Returns the token hash.
    #[must_use]
    pub const fn token_hash(&self) -> &TokenHash {
        &self.token_hash
    }

    /// Returns the note random.
    #[must_use]
    pub const fn random(&self) -> &NoteRandom {
        &self.random
    }

    /// Returns the note value.
    #[must_use]
    pub const fn value(&self) -> NoteValue {
        self.value
    }

    /// Returns the raw memo bytes.
    #[must_use]
    pub fn memo(&self) -> &[u8] {
        &self.memo
    }
}

/// Canonical V2 note ciphertext bundle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct V2CiphertextBundle {
    iv_tag: V2CiphertextBlock,
    data: [V2CiphertextBlock; 3],
    annotation_data: Vec<u8>,
    memo: Vec<u8>,
}

impl V2CiphertextBundle {
    /// Creates a V2 ciphertext bundle from explicit components.
    #[must_use]
    pub fn new(
        iv_tag: V2CiphertextBlock,
        data: [V2CiphertextBlock; 3],
        annotation_data: Vec<u8>,
        memo: Vec<u8>,
    ) -> Self {
        Self { iv_tag, data, annotation_data, memo }
    }

    /// Returns the combined `iv | tag` block.
    #[must_use]
    pub const fn iv_tag(&self) -> &V2CiphertextBlock {
        &self.iv_tag
    }

    /// Returns the three fixed ciphertext blocks.
    #[must_use]
    pub const fn data(&self) -> &[V2CiphertextBlock; 3] {
        &self.data
    }

    /// Returns the opaque annotation data bytes.
    #[must_use]
    pub fn annotation_data(&self) -> &[u8] {
        &self.annotation_data
    }

    /// Returns the detached memo bytes.
    #[must_use]
    pub fn memo(&self) -> &[u8] {
        &self.memo
    }
}

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;

    use super::{V2CiphertextBlock, V2CiphertextBundle, V2Plaintext};
    use crate::{MasterPublicKey, NoteRandom, NoteValue, ParseDomainError, TokenHash};

    #[test]
    fn rejects_invalid_v2_ciphertext_block_length() {
        let Err(error) = V2CiphertextBlock::from_slice(&[7_u8; 31]) else {
            panic!("invalid v2 ciphertext block length should fail");
        };

        assert_eq!(error, ParseDomainError::new("v2 ciphertext block must be exactly 32 bytes"));
    }

    #[test]
    fn v2_plaintext_preserves_empty_memo() {
        let plaintext = V2Plaintext::new(
            MasterPublicKey::new(BigUint::from(1_u8))
                .unwrap_or_else(|_| panic!("master public key should be valid")),
            TokenHash::new([2_u8; 32]),
            NoteRandom::new([3_u8; 16]),
            NoteValue::new(4_u128),
            Vec::new(),
        );

        assert!(plaintext.memo().is_empty());
    }

    #[test]
    fn v2_ciphertext_bundle_preserves_empty_detached_fields() {
        let bundle = V2CiphertextBundle::new(
            V2CiphertextBlock::new([1_u8; 32]),
            [
                V2CiphertextBlock::new([2_u8; 32]),
                V2CiphertextBlock::new([3_u8; 32]),
                V2CiphertextBlock::new([4_u8; 32]),
            ],
            Vec::new(),
            Vec::new(),
        );

        assert!(bundle.annotation_data().is_empty());
        assert!(bundle.memo().is_empty());
    }
}
