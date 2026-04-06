use crate::{MasterPublicKey, NoteRandom, NoteValue, ParseDomainError, SenderRandom, TokenHash};

/// Typed 16-byte stored nonce for the canonical Railgun V3 ciphertext layout.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct V3StoredNonce([u8; 16]);

impl V3StoredNonce {
    /// Length of the stored V3 nonce in bytes.
    pub const LENGTH: usize = 16;

    /// Creates a stored V3 nonce from raw bytes.
    #[must_use]
    pub const fn new(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    /// Creates a stored V3 nonce from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns an error if `bytes` is not exactly 16 bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ParseDomainError> {
        let array: [u8; Self::LENGTH] = bytes
            .try_into()
            .map_err(|_| ParseDomainError::new("v3 stored nonce must be exactly 16 bytes"))?;
        Ok(Self::new(array))
    }

    /// Returns the raw stored nonce bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}

/// Canonical V3 note plaintext layout.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct V3Plaintext {
    encoded_master_public_key: MasterPublicKey,
    random: NoteRandom,
    value: NoteValue,
    token_hash: TokenHash,
    sender_random: SenderRandom,
    memo: Vec<u8>,
}

impl V3Plaintext {
    /// Creates a V3 plaintext payload from explicit components.
    #[must_use]
    pub fn new(
        encoded_master_public_key: MasterPublicKey,
        random: NoteRandom,
        value: NoteValue,
        token_hash: TokenHash,
        sender_random: SenderRandom,
        memo: Vec<u8>,
    ) -> Self {
        Self { encoded_master_public_key, random, value, token_hash, sender_random, memo }
    }

    /// Returns the encoded master public key.
    #[must_use]
    pub const fn encoded_master_public_key(&self) -> &MasterPublicKey {
        &self.encoded_master_public_key
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

    /// Returns the token hash.
    #[must_use]
    pub const fn token_hash(&self) -> &TokenHash {
        &self.token_hash
    }

    /// Returns the sender-random bytes.
    #[must_use]
    pub const fn sender_random(&self) -> &SenderRandom {
        &self.sender_random
    }

    /// Returns the raw memo bytes.
    #[must_use]
    pub fn memo(&self) -> &[u8] {
        &self.memo
    }
}

/// Canonical V3 note ciphertext bundle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct V3CiphertextBundle {
    nonce: V3StoredNonce,
    bundle: Vec<u8>,
    sender_ciphertext: Vec<u8>,
}

impl V3CiphertextBundle {
    /// Creates a V3 ciphertext bundle from explicit components.
    #[must_use]
    pub fn new(nonce: V3StoredNonce, bundle: Vec<u8>, sender_ciphertext: Vec<u8>) -> Self {
        Self { nonce, bundle, sender_ciphertext }
    }

    /// Returns the stored V3 nonce bytes.
    #[must_use]
    pub const fn nonce(&self) -> &V3StoredNonce {
        &self.nonce
    }

    /// Returns the opaque ciphertext bundle bytes.
    #[must_use]
    pub fn bundle(&self) -> &[u8] {
        &self.bundle
    }

    /// Returns the opaque sender-ciphertext bytes carried in V3 global bound params.
    #[must_use]
    pub fn sender_ciphertext(&self) -> &[u8] {
        &self.sender_ciphertext
    }
}

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;

    use super::{V3CiphertextBundle, V3Plaintext, V3StoredNonce};
    use crate::{
        MasterPublicKey, NoteRandom, NoteValue, ParseDomainError, SenderRandom, TokenHash,
    };

    #[test]
    fn rejects_invalid_v3_nonce_length() {
        let Err(error) = V3StoredNonce::from_slice(&[7_u8; 15]) else {
            panic!("invalid v3 nonce length should fail");
        };

        assert_eq!(error, ParseDomainError::new("v3 stored nonce must be exactly 16 bytes"));
    }

    #[test]
    fn v3_plaintext_preserves_empty_memo() {
        let plaintext = V3Plaintext::new(
            MasterPublicKey::new(BigUint::from(1_u8))
                .unwrap_or_else(|_| panic!("master public key should be valid")),
            NoteRandom::new([2_u8; 16]),
            NoteValue::new(3_u128),
            TokenHash::new([4_u8; 32]),
            SenderRandom::new([5_u8; 15]),
            Vec::new(),
        );

        assert!(plaintext.memo().is_empty());
    }

    #[test]
    fn v3_ciphertext_bundle_preserves_sender_ciphertext() {
        let bundle =
            V3CiphertextBundle::new(V3StoredNonce::new([1_u8; 16]), vec![2_u8; 48], vec![3_u8; 11]);

        assert_eq!(bundle.nonce().as_bytes(), &[1_u8; 16]);
        assert_eq!(bundle.bundle(), &[2_u8; 48]);
        assert_eq!(bundle.sender_ciphertext(), &[3_u8; 11]);
    }
}
