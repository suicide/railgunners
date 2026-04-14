use num_bigint::BigUint;

use crate::{
    MasterPublicKey, ParseDomainError, TokenHash, ViewingPublicKey, validate_bn254_scalar,
};

/// Canonical all-zero sender-random sentinel used for visible-sender notes.
pub const MEMO_SENDER_RANDOM_NULL_BYTES: [u8; 15] = [0_u8; 15];

/// Typed 15-byte sender-random field controlling sender visibility in notes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SenderRandom([u8; 15]);

impl SenderRandom {
    /// Length of a sender-random value in bytes.
    pub const LENGTH: usize = 15;

    /// Creates a sender-random value from raw bytes.
    #[must_use]
    pub const fn new(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    /// Returns the canonical all-zero visible-sender sentinel.
    #[must_use]
    pub const fn null_sentinel() -> Self {
        Self(MEMO_SENDER_RANDOM_NULL_BYTES)
    }

    /// Creates a sender-random value from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns an error if `bytes` is not exactly 15 bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ParseDomainError> {
        let array: [u8; Self::LENGTH] = bytes
            .try_into()
            .map_err(|_| ParseDomainError::new("sender random must be exactly 15 bytes"))?;
        Ok(Self::new(array))
    }

    /// Returns whether this value is the visible-sender null sentinel.
    #[must_use]
    pub fn is_null_sentinel(&self) -> bool {
        self.0 == MEMO_SENDER_RANDOM_NULL_BYTES
    }

    /// Returns the raw sender-random bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}

/// Sender visibility mode derived from the sender-random field.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SenderVisibility {
    /// Sender identity is recoverable by the receiver.
    Visible,
    /// Sender identity is hidden from the receiver.
    Hidden,
}

/// Minimal note party identity used during note construction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NoteParty {
    master_public_key: MasterPublicKey,
    viewing_public_key: ViewingPublicKey,
}

impl NoteParty {
    /// Creates a note party from explicit key components.
    #[must_use]
    pub const fn new(
        master_public_key: MasterPublicKey,
        viewing_public_key: ViewingPublicKey,
    ) -> Self {
        Self { master_public_key, viewing_public_key }
    }

    /// Returns the party master public key.
    #[must_use]
    pub const fn master_public_key(&self) -> &MasterPublicKey {
        &self.master_public_key
    }

    /// Returns the party viewing public key.
    #[must_use]
    pub const fn viewing_public_key(&self) -> &ViewingPublicKey {
        &self.viewing_public_key
    }
}

/// Perspective used when reconstructing a note from decrypted ciphertext.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum NotePerspective {
    /// The note was received by the current wallet.
    Received,
    /// The note was sent by the current wallet.
    Sent,
}

/// Typed 16-byte note random used in note public key derivation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct NoteRandom([u8; 16]);

impl NoteRandom {
    /// Length of a note random in bytes.
    pub const LENGTH: usize = 16;

    /// Creates a note random from raw bytes.
    #[must_use]
    pub const fn new(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    /// Creates a note random from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns an error if `bytes` is not exactly 16 bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ParseDomainError> {
        let array: [u8; Self::LENGTH] = bytes
            .try_into()
            .map_err(|_| ParseDomainError::new("note random must be exactly 16 bytes"))?;
        Ok(Self::new(array))
    }

    /// Returns the raw note-random bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}

/// Typed 16-byte shared random used in note blinding derivation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SharedRandom([u8; 16]);

impl SharedRandom {
    /// Length of a shared random in bytes.
    pub const LENGTH: usize = 16;

    /// Creates a shared random from raw bytes.
    #[must_use]
    pub const fn new(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    /// Creates a shared random from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns an error if `bytes` is not exactly 16 bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ParseDomainError> {
        let array: [u8; Self::LENGTH] = bytes
            .try_into()
            .map_err(|_| ParseDomainError::new("shared random must be exactly 16 bytes"))?;
        Ok(Self::new(array))
    }

    /// Returns the raw shared-random bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}

/// Typed Railgun note public key derived from receiver identity and note randomness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotePublicKey(BigUint);

impl NotePublicKey {
    /// Creates a note public key from a field-element integer value.
    ///
    /// # Errors
    ///
    /// Returns an error if `value` is not a valid BN254 scalar field element.
    pub fn new(value: BigUint) -> Result<Self, ParseDomainError> {
        validate_bn254_scalar(&value, "note public key must fit within the BN254 scalar field")?;
        Ok(Self(value))
    }

    /// Returns the underlying field-element integer value.
    #[must_use]
    pub const fn value(&self) -> &BigUint {
        &self.0
    }
}

/// Typed uint128 note value used in commitment derivation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct NoteValue(u128);

impl NoteValue {
    /// Length of a canonical note value encoding in bytes.
    pub const LENGTH: usize = 16;

    /// Creates a note value from a native uint128.
    #[must_use]
    pub const fn new(value: u128) -> Self {
        Self(value)
    }

    /// Creates a note value from a canonical 16-byte big-endian byte slice.
    ///
    /// # Errors
    ///
    /// Returns an error if `bytes` is not exactly 16 bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ParseDomainError> {
        let array: [u8; Self::LENGTH] = bytes
            .try_into()
            .map_err(|_| ParseDomainError::new("note value must be exactly 16 bytes"))?;
        Ok(Self::from_be_bytes(array))
    }

    /// Creates a note value from canonical 16-byte big-endian bytes.
    #[must_use]
    pub const fn from_be_bytes(bytes: [u8; Self::LENGTH]) -> Self {
        Self(u128::from_be_bytes(bytes))
    }

    /// Returns the inner uint128 value.
    #[must_use]
    pub const fn get(self) -> u128 {
        self.0
    }

    /// Returns the canonical 16-byte big-endian encoding.
    #[must_use]
    pub const fn to_be_bytes(self) -> [u8; Self::LENGTH] {
        self.0.to_be_bytes()
    }
}

/// Typed Railgun note commitment stored as the UTXO tree leaf.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NoteCommitment(BigUint);

impl NoteCommitment {
    /// Creates a note commitment from a field-element integer value.
    ///
    /// # Errors
    ///
    /// Returns an error if `value` is not a valid BN254 scalar field element.
    pub fn new(value: BigUint) -> Result<Self, ParseDomainError> {
        validate_bn254_scalar(&value, "note commitment must fit within the BN254 scalar field")?;
        Ok(Self(value))
    }

    /// Returns the underlying field-element integer value.
    #[must_use]
    pub const fn value(&self) -> &BigUint {
        &self.0
    }
}

/// Canonical note recovered from ciphertext or other protocol data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Note {
    receiver: NoteParty,
    sender: Option<NoteParty>,
    token_hash: TokenHash,
    random: NoteRandom,
    value: NoteValue,
    sender_random: Option<SenderRandom>,
    memo: Vec<u8>,
    public_key: NotePublicKey,
    commitment: NoteCommitment,
}

impl Note {
    /// Creates a note from explicit components.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        receiver: NoteParty,
        sender: Option<NoteParty>,
        token_hash: TokenHash,
        random: NoteRandom,
        value: NoteValue,
        sender_random: Option<SenderRandom>,
        memo: Vec<u8>,
        note_public_key: NotePublicKey,
        commitment: NoteCommitment,
    ) -> Self {
        Self {
            receiver,
            sender,
            token_hash,
            random,
            value,
            sender_random,
            memo,
            public_key: note_public_key,
            commitment,
        }
    }

    /// Returns the receiver party.
    #[must_use]
    pub const fn receiver(&self) -> &NoteParty {
        &self.receiver
    }

    /// Returns the sender party when sender visibility allows reconstruction.
    #[must_use]
    pub const fn sender(&self) -> Option<&NoteParty> {
        self.sender.as_ref()
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

    /// Returns the sender random when available.
    #[must_use]
    pub const fn sender_random(&self) -> Option<&SenderRandom> {
        self.sender_random.as_ref()
    }

    /// Returns the raw memo bytes.
    #[must_use]
    pub fn memo(&self) -> &[u8] {
        &self.memo
    }

    /// Returns the recomputed note public key.
    #[must_use]
    pub const fn note_public_key(&self) -> &NotePublicKey {
        &self.public_key
    }

    /// Returns the recomputed commitment.
    #[must_use]
    pub const fn commitment(&self) -> &NoteCommitment {
        &self.commitment
    }
}

/// Note plus reconstruction provenance recovered from decrypted ciphertext.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconstructedNote {
    note: Note,
    perspective: NotePerspective,
    encoded_master_public_key: MasterPublicKey,
}

impl ReconstructedNote {
    /// Creates a reconstructed note and its provenance wrapper.
    #[must_use]
    pub const fn new(
        note: Note,
        perspective: NotePerspective,
        encoded_master_public_key: MasterPublicKey,
    ) -> Self {
        Self { note, perspective, encoded_master_public_key }
    }

    /// Returns the reconstructed note.
    #[must_use]
    pub const fn note(&self) -> &Note {
        &self.note
    }

    /// Returns the reconstruction perspective.
    #[must_use]
    pub const fn perspective(&self) -> NotePerspective {
        self.perspective
    }

    /// Returns the encoded master public key recovered from ciphertext.
    #[must_use]
    pub const fn encoded_master_public_key(&self) -> &MasterPublicKey {
        &self.encoded_master_public_key
    }
}

/// Typed non-negative UTXO leaf index used in nullifier derivation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LeafIndex(u64);

impl LeafIndex {
    /// Creates a leaf index from an explicit non-negative integer value.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the inner integer value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Typed Railgun nullifier derived from nullifying key and leaf index.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Nullifier(BigUint);

impl Nullifier {
    /// Creates a nullifier from a field-element integer value.
    ///
    /// # Errors
    ///
    /// Returns an error if `value` is not a valid BN254 scalar field element.
    pub fn new(value: BigUint) -> Result<Self, ParseDomainError> {
        validate_bn254_scalar(&value, "nullifier must fit within the BN254 scalar field")?;
        Ok(Self(value))
    }

    /// Returns the underlying field-element integer value.
    #[must_use]
    pub const fn value(&self) -> &BigUint {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::{
        LeafIndex, MEMO_SENDER_RANDOM_NULL_BYTES, Note, NoteCommitment, NoteParty, NotePerspective,
        NotePublicKey, NoteRandom, NoteValue, Nullifier, ReconstructedNote, SenderRandom,
        SenderVisibility, SharedRandom,
    };
    use crate::{
        MasterPublicKey, ParseDomainError, TokenHash, ViewingPublicKey, bn254_scalar_field_modulus,
    };

    #[test]
    fn rejects_invalid_note_random_length() {
        let Err(error) = NoteRandom::from_slice(&[7_u8; 15]) else {
            panic!("invalid note random length should fail");
        };
        assert_eq!(error, ParseDomainError::new("note random must be exactly 16 bytes"));
    }

    #[test]
    fn rejects_invalid_shared_random_length() {
        let Err(error) = SharedRandom::from_slice(&[7_u8; 15]) else {
            panic!("invalid shared random length should fail");
        };
        assert_eq!(error, ParseDomainError::new("shared random must be exactly 16 bytes"));
    }

    #[test]
    fn rejects_invalid_note_value_length() {
        let Err(error) = NoteValue::from_slice(&[7_u8; 15]) else {
            panic!("invalid note value length should fail");
        };
        assert_eq!(error, ParseDomainError::new("note value must be exactly 16 bytes"));
    }

    #[test]
    fn rejects_invalid_sender_random_length() {
        let Err(error) = SenderRandom::from_slice(&[7_u8; 14]) else {
            panic!("invalid sender random length should fail");
        };
        assert_eq!(error, ParseDomainError::new("sender random must be exactly 15 bytes"));
    }

    #[test]
    fn rejects_invalid_note_public_key_field_element() {
        let Err(error) = NotePublicKey::new(bn254_scalar_field_modulus()) else {
            panic!("invalid note public key should fail");
        };
        assert_eq!(
            error,
            ParseDomainError::new("note public key must fit within the BN254 scalar field")
        );
    }

    #[test]
    fn rejects_invalid_nullifier_field_element() {
        let Err(error) = Nullifier::new(bn254_scalar_field_modulus()) else {
            panic!("invalid nullifier should fail");
        };
        assert_eq!(
            error,
            ParseDomainError::new("nullifier must fit within the BN254 scalar field")
        );
    }

    #[test]
    fn note_value_round_trips_big_endian_bytes() {
        let value = NoteValue::from_be_bytes([
            0, 0, 0, 0, 0, 0, 0, 0, 8, 0x6a, 0xa1, 0xad, 0xe6, 0x1c, 0xcb, 0x53,
        ]);

        assert_eq!(
            value.to_be_bytes(),
            [0, 0, 0, 0, 0, 0, 0, 0, 8, 0x6a, 0xa1, 0xad, 0xe6, 0x1c, 0xcb, 0x53]
        );
    }

    #[test]
    fn leaf_index_round_trips_value() {
        let leaf_index = LeafIndex::new(6_500);

        assert_eq!(leaf_index.get(), 6_500);
    }

    #[test]
    fn sender_random_null_sentinel_matches_constant() {
        assert_eq!(SenderRandom::null_sentinel().as_bytes(), &MEMO_SENDER_RANDOM_NULL_BYTES);
        assert!(SenderRandom::null_sentinel().is_null_sentinel());
    }

    #[test]
    fn sender_visibility_variants_are_distinct() {
        assert_ne!(SenderVisibility::Visible, SenderVisibility::Hidden);
    }

    #[test]
    fn note_party_preserves_keys() {
        let master_public_key = MasterPublicKey::new(1_u8.into())
            .unwrap_or_else(|error| panic!("master public key should validate: {error}"));
        let viewing_public_key = ViewingPublicKey::new([2_u8; 32]);
        let party = NoteParty::new(master_public_key.clone(), viewing_public_key);

        assert_eq!(party.master_public_key(), &master_public_key);
        assert_eq!(party.viewing_public_key(), &viewing_public_key);
    }

    #[test]
    fn note_and_reconstructed_note_preserve_canonical_fields() {
        let receiver = NoteParty::new(
            MasterPublicKey::new(1_u8.into()).unwrap_or_else(|error| {
                panic!("receiver master public key should validate: {error}")
            }),
            ViewingPublicKey::new([2_u8; 32]),
        );
        let sender = NoteParty::new(
            MasterPublicKey::new(3_u8.into()).unwrap_or_else(|error| {
                panic!("sender master public key should validate: {error}")
            }),
            ViewingPublicKey::new([4_u8; 32]),
        );
        let encoded_master_public_key = MasterPublicKey::new(5_u8.into())
            .unwrap_or_else(|error| panic!("encoded master public key should validate: {error}"));
        let token_hash = TokenHash::new([6_u8; 32]);
        let random = NoteRandom::new([7_u8; 16]);
        let value = NoteValue::new(8_u128);
        let sender_random = SenderRandom::new([9_u8; 15]);
        let note_public_key = NotePublicKey::new(10_u8.into())
            .unwrap_or_else(|error| panic!("note public key should validate: {error}"));
        let commitment = NoteCommitment::new(11_u8.into())
            .unwrap_or_else(|error| panic!("commitment should validate: {error}"));
        let note = Note::new(
            receiver.clone(),
            Some(sender.clone()),
            token_hash,
            random,
            value,
            Some(sender_random),
            b"memo".to_vec(),
            note_public_key.clone(),
            commitment.clone(),
        );

        assert_eq!(note.receiver(), &receiver);
        assert_eq!(note.sender(), Some(&sender));
        assert_eq!(note.random(), &random);
        assert_eq!(note.value(), value);
        assert_eq!(note.sender_random(), Some(&sender_random));
        assert_eq!(note.memo(), b"memo");
        assert_eq!(note.note_public_key(), &note_public_key);
        assert_eq!(note.commitment(), &commitment);

        let reconstructed = ReconstructedNote::new(
            note.clone(),
            NotePerspective::Sent,
            encoded_master_public_key.clone(),
        );

        assert_eq!(reconstructed.note(), &note);
        assert_eq!(reconstructed.perspective(), NotePerspective::Sent);
        assert_eq!(reconstructed.encoded_master_public_key(), &encoded_master_public_key);
    }
}
