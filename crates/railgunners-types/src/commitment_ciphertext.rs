use crate::{BlindedViewingPublicKey, V2CiphertextBundle, V3CiphertextBundle, V3StoredNonce};

/// Parsed V2 commitment ciphertext container emitted by the V2 transaction format.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitmentCiphertextV2 {
    ciphertext: V2CiphertextBundle,
    blinded_sender_viewing_key: BlindedViewingPublicKey,
    blinded_receiver_viewing_key: BlindedViewingPublicKey,
}

impl CommitmentCiphertextV2 {
    /// Creates a parsed V2 commitment ciphertext container.
    #[must_use]
    pub const fn new(
        ciphertext: V2CiphertextBundle,
        blinded_sender_viewing_key: BlindedViewingPublicKey,
        blinded_receiver_viewing_key: BlindedViewingPublicKey,
    ) -> Self {
        Self { ciphertext, blinded_sender_viewing_key, blinded_receiver_viewing_key }
    }

    /// Returns the normalized V2 ciphertext payload.
    #[must_use]
    pub const fn ciphertext(&self) -> &V2CiphertextBundle {
        &self.ciphertext
    }

    /// Returns the blinded sender viewing key.
    #[must_use]
    pub const fn blinded_sender_viewing_key(&self) -> &BlindedViewingPublicKey {
        &self.blinded_sender_viewing_key
    }

    /// Returns the blinded receiver viewing key.
    #[must_use]
    pub const fn blinded_receiver_viewing_key(&self) -> &BlindedViewingPublicKey {
        &self.blinded_receiver_viewing_key
    }
}

/// Parsed V3 commitment ciphertext container emitted by the V3 transaction format.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitmentCiphertextV3 {
    ciphertext: V3CiphertextBundle,
    blinded_sender_viewing_key: BlindedViewingPublicKey,
    blinded_receiver_viewing_key: BlindedViewingPublicKey,
}

impl CommitmentCiphertextV3 {
    /// Creates a parsed V3 commitment ciphertext container.
    #[must_use]
    pub const fn new(
        ciphertext: V3CiphertextBundle,
        blinded_sender_viewing_key: BlindedViewingPublicKey,
        blinded_receiver_viewing_key: BlindedViewingPublicKey,
    ) -> Self {
        Self { ciphertext, blinded_sender_viewing_key, blinded_receiver_viewing_key }
    }

    /// Returns the normalized V3 ciphertext payload.
    #[must_use]
    pub const fn ciphertext(&self) -> &V3CiphertextBundle {
        &self.ciphertext
    }

    /// Returns the stored V3 nonce.
    #[must_use]
    pub const fn nonce(&self) -> &V3StoredNonce {
        self.ciphertext.nonce()
    }

    /// Returns the opaque V3 ciphertext bundle bytes.
    #[must_use]
    pub fn bundle(&self) -> &[u8] {
        self.ciphertext.bundle()
    }

    /// Returns the blinded sender viewing key.
    #[must_use]
    pub const fn blinded_sender_viewing_key(&self) -> &BlindedViewingPublicKey {
        &self.blinded_sender_viewing_key
    }

    /// Returns the blinded receiver viewing key.
    #[must_use]
    pub const fn blinded_receiver_viewing_key(&self) -> &BlindedViewingPublicKey {
        &self.blinded_receiver_viewing_key
    }
}

/// Version-aware parsed commitment ciphertext container.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VersionedCommitmentCiphertext {
    /// Parsed V2 commitment ciphertext.
    V2(CommitmentCiphertextV2),
    /// Parsed V3 commitment ciphertext.
    V3(CommitmentCiphertextV3),
}

#[cfg(test)]
mod tests {
    use super::{CommitmentCiphertextV2, CommitmentCiphertextV3, VersionedCommitmentCiphertext};
    use crate::{
        BlindedViewingPublicKey, V2CiphertextBlock, V2CiphertextBundle, V3CiphertextBundle,
        V3StoredNonce,
    };

    #[test]
    fn v2_container_preserves_normalized_payload() {
        let payload = V2CiphertextBundle::new(
            V2CiphertextBlock::new([1_u8; 32]),
            [
                V2CiphertextBlock::new([2_u8; 32]),
                V2CiphertextBlock::new([3_u8; 32]),
                V2CiphertextBlock::new([4_u8; 32]),
            ],
            vec![5_u8; 7],
            vec![6_u8; 8],
        );
        let parsed = CommitmentCiphertextV2::new(
            payload.clone(),
            BlindedViewingPublicKey::new([7_u8; 32]),
            BlindedViewingPublicKey::new([8_u8; 32]),
        );

        assert_eq!(parsed.ciphertext(), &payload);
    }

    #[test]
    fn v3_container_exposes_nonce_and_bundle() {
        let payload =
            V3CiphertextBundle::new(V3StoredNonce::new([1_u8; 16]), vec![2_u8; 17], Vec::new());
        let parsed = CommitmentCiphertextV3::new(
            payload,
            BlindedViewingPublicKey::new([3_u8; 32]),
            BlindedViewingPublicKey::new([4_u8; 32]),
        );

        assert_eq!(parsed.nonce().as_bytes(), &[1_u8; 16]);
        assert_eq!(parsed.bundle(), &[2_u8; 17]);
    }

    #[test]
    fn versioned_container_remains_distinct() {
        let v2 = VersionedCommitmentCiphertext::V2(CommitmentCiphertextV2::new(
            V2CiphertextBundle::new(
                V2CiphertextBlock::new([1_u8; 32]),
                [
                    V2CiphertextBlock::new([2_u8; 32]),
                    V2CiphertextBlock::new([3_u8; 32]),
                    V2CiphertextBlock::new([4_u8; 32]),
                ],
                Vec::new(),
                Vec::new(),
            ),
            BlindedViewingPublicKey::new([5_u8; 32]),
            BlindedViewingPublicKey::new([6_u8; 32]),
        ));
        let v3 = VersionedCommitmentCiphertext::V3(CommitmentCiphertextV3::new(
            V3CiphertextBundle::new(V3StoredNonce::new([7_u8; 16]), vec![8_u8; 9], Vec::new()),
            BlindedViewingPublicKey::new([9_u8; 32]),
            BlindedViewingPublicKey::new([10_u8; 32]),
        ));

        assert_ne!(v2, v3);
    }
}
