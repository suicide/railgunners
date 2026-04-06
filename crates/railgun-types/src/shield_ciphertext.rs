use crate::ViewingPublicKey;

/// Opaque serialized shield-ciphertext bundle block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShieldCiphertextBlock(Vec<u8>);

impl ShieldCiphertextBlock {
    /// Creates a shield-ciphertext block from raw bytes.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Returns the raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Parsed shield ciphertext emitted by shield note serialization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShieldCiphertext {
    encrypted_bundle: [ShieldCiphertextBlock; 3],
    shield_key: ViewingPublicKey,
}

impl ShieldCiphertext {
    /// Creates a parsed shield ciphertext from explicit components.
    #[must_use]
    pub const fn new(
        encrypted_bundle: [ShieldCiphertextBlock; 3],
        shield_key: ViewingPublicKey,
    ) -> Self {
        Self { encrypted_bundle, shield_key }
    }

    /// Returns the three-part encrypted bundle exactly as serialized on-chain.
    #[must_use]
    pub const fn encrypted_bundle(&self) -> &[ShieldCiphertextBlock; 3] {
        &self.encrypted_bundle
    }

    /// Returns the parsed shield key.
    #[must_use]
    pub const fn shield_key(&self) -> &ViewingPublicKey {
        &self.shield_key
    }
}

#[cfg(test)]
mod tests {
    use super::{ShieldCiphertext, ShieldCiphertextBlock};
    use crate::ViewingPublicKey;

    #[test]
    fn shield_ciphertext_preserves_three_part_bundle() {
        let ciphertext = ShieldCiphertext::new(
            [
                ShieldCiphertextBlock::new(vec![1_u8; 32]),
                ShieldCiphertextBlock::new(vec![2_u8; 32]),
                ShieldCiphertextBlock::new(vec![3_u8; 16]),
            ],
            ViewingPublicKey::new([4_u8; 32]),
        );

        assert_eq!(ciphertext.encrypted_bundle()[0].as_bytes(), &[1_u8; 32]);
        assert_eq!(ciphertext.encrypted_bundle()[1].as_bytes(), &[2_u8; 32]);
        assert_eq!(ciphertext.encrypted_bundle()[2].as_bytes(), &[3_u8; 16]);
        assert_eq!(ciphertext.shield_key().as_bytes(), &[4_u8; 32]);
    }
}
