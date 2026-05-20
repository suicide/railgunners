//! Canonical note public key, commitment, and nullifier derivation.

use num_bigint::BigUint;
use railgun_types::{
    BlindedViewingPublicKey, EmittedNullifier, LeafIndex, MasterPublicKey, Note, NoteCommitment,
    NoteParty, NotePerspective, NotePublicKey, NoteRandom, NoteSpentState, NoteValue, Nullifier,
    NullifyingKey, ReconstructedNote, SenderRandom, SenderRecovery, SenderVisibility, SharedRandom,
    TokenHash, TrackedNoteNullifier, V2Plaintext, V3Plaintext, WalletNoteOwnership,
    WalletScanKeyBundle,
};

use crate::{blinding::BlindingError, crypto::poseidon, hd::KeyDerivationError, unblind_note_key};

/// Error returned when note reconstruction or validation fails.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NoteReconstructionError {
    /// The sender random required to reconstruct a V2 sent note was not provided.
    MissingV2SentSenderRandom,
    /// A viewing key could not be unblinded from the ciphertext metadata.
    InvalidBlindedViewingKey,
    /// The recovered master public key did not validate.
    InvalidMasterPublicKey,
    /// Note-public-key or commitment derivation failed unexpectedly.
    DerivationFailed,
    /// The recomputed commitment does not match the expected on-chain leaf.
    CommitmentMismatch,
}

impl core::fmt::Display for NoteReconstructionError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MissingV2SentSenderRandom => {
                formatter.write_str("v2 sent-note reconstruction requires sender random")
            }
            Self::InvalidBlindedViewingKey => formatter.write_str("invalid blinded viewing key"),
            Self::InvalidMasterPublicKey => formatter.write_str("invalid master public key"),
            Self::DerivationFailed => formatter.write_str("failed to derive note fields"),
            Self::CommitmentMismatch => {
                formatter.write_str("recomputed commitment does not match expected commitment")
            }
        }
    }
}

impl std::error::Error for NoteReconstructionError {}

impl From<KeyDerivationError> for NoteReconstructionError {
    fn from(_: KeyDerivationError) -> Self {
        Self::DerivationFailed
    }
}

impl From<BlindingError> for NoteReconstructionError {
    fn from(error: BlindingError) -> Self {
        match error {
            BlindingError::InvalidViewingPublicKey
            | BlindingError::InvalidBlindedViewingPublicKey => Self::InvalidBlindedViewingKey,
        }
    }
}

/// Resolves sender visibility from the optional sender-random field.
///
/// This is the low-level encoded-MPK rule used by note plaintexts: missing
/// sender-random and the all-zero sentinel both mean visible-sender mode.
/// Higher-level V2 received-note reconstruction still needs an ambiguity guard
/// because V2 plaintext does not carry `sender_random` directly.
#[must_use]
pub fn sender_visibility(sender_random: Option<&SenderRandom>) -> SenderVisibility {
    match sender_random {
        Some(sender_random) if !sender_random.is_null_sentinel() => SenderVisibility::Hidden,
        Some(_) | None => SenderVisibility::Visible,
    }
}

/// Encodes the receiver master public key according to sender visibility rules.
///
/// Hidden-sender notes preserve the receiver MPK. Visible-sender notes XOR the
/// canonical 32-byte MPK encodings so both sides match upstream plaintext rules.
///
/// # Errors
///
/// Returns an error if the encoded master public key does not fit the canonical
/// 32-byte MPK encoding.
pub fn encode_master_public_key(
    receiver_master_public_key: &MasterPublicKey,
    sender_master_public_key: &MasterPublicKey,
    sender_random: Option<&SenderRandom>,
) -> Result<MasterPublicKey, KeyDerivationError> {
    match sender_visibility(sender_random) {
        SenderVisibility::Hidden => {
            MasterPublicKey::new(receiver_master_public_key.value().clone())
                .map_err(|_| KeyDerivationError::DerivationFailure)
        }
        SenderVisibility::Visible => {
            // Upstream note plaintexts XOR the fixed-width 32-byte MPK encodings,
            // not the trimmed BigUint byte slices.
            let encoded_bytes: [u8; 32] = core::array::from_fn(|index| {
                receiver_master_public_key.to_be_bytes()[index]
                    ^ sender_master_public_key.to_be_bytes()[index]
            });
            MasterPublicKey::new(BigUint::from_bytes_be(&encoded_bytes))
                .map_err(|_| KeyDerivationError::DerivationFailure)
        }
    }
}

/// Decodes a note master public key according to sender visibility rules.
///
/// Hidden-sender notes carry the receiver MPK directly. Visible-sender notes XOR
/// the current wallet MPK with the encoded MPK to recover the counterparty key.
/// Missing sender-random is treated the same as the visible-sender null sentinel.
///
/// Callers reconstructing whole notes should prefer `reconstruct_v2_note` or
/// `reconstruct_v3_note`, because V2 received notes can remain ambiguous even
/// when this low-level decode rule resolves to visible mode.
///
/// # Errors
///
/// Returns an error if the recovered master public key does not fit the canonical
/// 32-byte MPK encoding.
pub fn decode_master_public_key(
    current_wallet_master_public_key: &MasterPublicKey,
    encoded_master_public_key: &MasterPublicKey,
    sender_random: Option<&SenderRandom>,
) -> Result<MasterPublicKey, KeyDerivationError> {
    match sender_visibility(sender_random) {
        SenderVisibility::Hidden => MasterPublicKey::new(encoded_master_public_key.value().clone())
            .map_err(|_| KeyDerivationError::DerivationFailure),
        SenderVisibility::Visible => {
            // Upstream visibility decoding XORs the canonical fixed-width encodings.
            let decoded_bytes: [u8; 32] = core::array::from_fn(|index| {
                current_wallet_master_public_key.to_be_bytes()[index]
                    ^ encoded_master_public_key.to_be_bytes()[index]
            });
            MasterPublicKey::new(BigUint::from_bytes_be(&decoded_bytes))
                .map_err(|_| KeyDerivationError::DerivationFailure)
        }
    }
}

/// Recovers sender identity from an encoded MPK under the sender-visibility rules.
///
/// Hidden-sender notes carry the receiver MPK directly, so recovery must not infer
/// a sender from `encoded_master_public_key`. Visible-sender notes XOR the fixed-
/// width receiver and sender MPK encodings, so recovery reverses that XOR.
/// Missing sender-random is treated the same as the visible-sender null sentinel.
///
/// This function only applies the encoded-MPK visibility rule. Callers
/// reconstructing V2 received notes should prefer `reconstruct_v2_note`, which
/// preserves the upstream ambiguity rule when plaintext omits `sender_random`.
///
/// # Errors
///
/// Returns an error if visible-sender recovery produces a master public key that
/// does not fit the canonical 32-byte MPK encoding.
pub fn recover_sender(
    encoded_master_public_key: &MasterPublicKey,
    receiver_master_public_key: &MasterPublicKey,
    sender_random: Option<&SenderRandom>,
) -> Result<SenderRecovery, KeyDerivationError> {
    match sender_visibility(sender_random) {
        SenderVisibility::Hidden => Ok(SenderRecovery::new(SenderVisibility::Hidden, None)),
        SenderVisibility::Visible => Ok(SenderRecovery::new(
            SenderVisibility::Visible,
            Some(decode_master_public_key(
                receiver_master_public_key,
                encoded_master_public_key,
                Some(&SenderRandom::null_sentinel()),
            )?),
        )),
    }
}

/// Derives a note public key from a receiver master public key and 16-byte note random.
///
/// Poseidon input ordering is exactly `[receiver_master_public_key, random]`
/// over the BN254 scalar field.
///
/// # Errors
///
/// Returns an error if `receiver_master_public_key` is not a valid BN254 field
/// element or if Poseidon hashing fails unexpectedly.
pub fn derive_note_public_key(
    receiver_master_public_key: &MasterPublicKey,
    random: &NoteRandom,
) -> Result<NotePublicKey, KeyDerivationError> {
    let inputs = [
        poseidon::field_from_biguint(receiver_master_public_key.value())
            .map_err(|_| KeyDerivationError::DerivationFailure)?,
        poseidon::field_from_bytes_mod_order(random.as_bytes()),
    ];
    let hash = poseidon::hash_fields(&inputs).map_err(|_| KeyDerivationError::DerivationFailure)?;

    NotePublicKey::new(poseidon::field_to_biguint(hash))
        .map_err(|_| KeyDerivationError::DerivationFailure)
}

/// Derives the canonical UTXO tree leaf commitment from note inputs.
///
/// Poseidon input ordering is exactly `[note_public_key, token_hash, value]`
/// over the BN254 scalar field.
///
/// # Errors
///
/// Returns an error if any input is not a valid BN254 field element or if
/// Poseidon hashing fails unexpectedly.
pub fn derive_note_commitment(
    note_public_key: &NotePublicKey,
    token_hash: &TokenHash,
    value: NoteValue,
) -> Result<NoteCommitment, KeyDerivationError> {
    let inputs = [
        poseidon::field_from_biguint(note_public_key.value())
            .map_err(|_| KeyDerivationError::DerivationFailure)?,
        poseidon::field_from_bytes_mod_order(token_hash.as_bytes()),
        value.get().into(),
    ];
    let hash = poseidon::hash_fields(&inputs).map_err(|_| KeyDerivationError::DerivationFailure)?;

    NoteCommitment::new(poseidon::field_to_biguint(hash))
        .map_err(|_| KeyDerivationError::DerivationFailure)
}

/// Recomputes a note public key and commitment, rejecting mismatches.
///
/// # Errors
///
/// Returns an error if derivation fails or if the recomputed commitment does not
/// match `expected_commitment`.
pub fn validate_note_commitment(
    receiver_master_public_key: &MasterPublicKey,
    random: &NoteRandom,
    token_hash: &TokenHash,
    value: NoteValue,
    expected_commitment: &NoteCommitment,
) -> Result<(NotePublicKey, NoteCommitment), NoteReconstructionError> {
    let note_public_key = derive_note_public_key(receiver_master_public_key, random)?;
    let commitment = derive_note_commitment(&note_public_key, token_hash, value)?;

    if &commitment != expected_commitment {
        return Err(NoteReconstructionError::CommitmentMismatch);
    }

    Ok((note_public_key, commitment))
}

/// Resolves whether a reconstructed note belongs to the wallet scan bundle.
#[must_use]
pub fn wallet_note_ownership(
    scan_keys: &WalletScanKeyBundle,
    note: &ReconstructedNote,
) -> WalletNoteOwnership {
    let wallet_master_public_key = scan_keys.master_public_key();
    let is_received_by_wallet =
        note.note().receiver().master_public_key() == wallet_master_public_key;
    let is_sent_by_wallet = note
        .note()
        .sender()
        .is_some_and(|sender| sender.master_public_key() == wallet_master_public_key);

    WalletNoteOwnership::new(is_received_by_wallet, is_sent_by_wallet)
}

/// Returns whether the reconstructed note receiver matches the wallet bundle.
#[must_use]
pub fn is_received_by_wallet(scan_keys: &WalletScanKeyBundle, note: &ReconstructedNote) -> bool {
    wallet_note_ownership(scan_keys, note).is_received_by_wallet()
}

/// Returns whether the reconstructed note sender matches the wallet bundle.
#[must_use]
pub fn is_sent_by_wallet(scan_keys: &WalletScanKeyBundle, note: &ReconstructedNote) -> bool {
    wallet_note_ownership(scan_keys, note).is_sent_by_wallet()
}

fn shared_random_from_note_random(random: &NoteRandom) -> SharedRandom {
    SharedRandom::new(*random.as_bytes())
}

struct ReconstructionInputs<'a> {
    wallet: &'a NoteParty,
    encoded_master_public_key: &'a MasterPublicKey,
    token_hash: &'a TokenHash,
    random: &'a NoteRandom,
    value: NoteValue,
    sender_random: Option<SenderRandom>,
    memo: Vec<u8>,
    expected_commitment: &'a NoteCommitment,
}

fn reconstruct_received_note(
    inputs: ReconstructionInputs<'_>,
    blinded_sender_viewing_key: &BlindedViewingPublicKey,
) -> Result<ReconstructedNote, NoteReconstructionError> {
    let receiver = inputs.wallet.clone();
    let shared_random = shared_random_from_note_random(inputs.random);
    let sender_recovery = recover_sender(
        inputs.encoded_master_public_key,
        inputs.wallet.master_public_key(),
        inputs.sender_random.as_ref(),
    )
    .map_err(|_| NoteReconstructionError::InvalidMasterPublicKey)?;
    let sender = match sender_recovery.visibility() {
        SenderVisibility::Hidden => None,
        SenderVisibility::Visible
            if inputs.sender_random.is_none()
                && inputs.encoded_master_public_key == inputs.wallet.master_public_key() =>
        {
            None
        }
        SenderVisibility::Visible => {
            let visible_sender_random = SenderRandom::null_sentinel();
            // V2 received notes do not carry sender_random, so `encodedMPK == receiverMPK`
            // remains ambiguous. Keep treating that case as hidden to avoid inventing a
            // visible sender that was not actually disclosed by the sender.
            let sender_master_public_key = sender_recovery
                .sender_master_public_key()
                .cloned()
                .ok_or(NoteReconstructionError::InvalidMasterPublicKey)?;
            let sender_viewing_public_key = unblind_note_key(
                blinded_sender_viewing_key,
                &shared_random,
                &visible_sender_random,
            )?;

            Some(NoteParty::new(sender_master_public_key, sender_viewing_public_key))
        }
    };
    let (note_public_key, commitment) = validate_note_commitment(
        receiver.master_public_key(),
        inputs.random,
        inputs.token_hash,
        inputs.value,
        inputs.expected_commitment,
    )?;

    let note = Note::new(
        receiver,
        sender,
        *inputs.token_hash,
        *inputs.random,
        inputs.value,
        inputs.sender_random,
        inputs.memo,
        note_public_key,
        commitment,
    );

    Ok(ReconstructedNote::new(
        note,
        NotePerspective::Received,
        inputs.encoded_master_public_key.clone(),
    ))
}

fn reconstruct_sent_note(
    inputs: ReconstructionInputs<'_>,
    blinded_receiver_viewing_key: &BlindedViewingPublicKey,
) -> Result<ReconstructedNote, NoteReconstructionError> {
    let sender_random =
        inputs.sender_random.ok_or(NoteReconstructionError::MissingV2SentSenderRandom)?;
    let shared_random = shared_random_from_note_random(inputs.random);
    let receiver_master_public_key = decode_master_public_key(
        inputs.wallet.master_public_key(),
        inputs.encoded_master_public_key,
        Some(&sender_random),
    )
    .map_err(|_| NoteReconstructionError::InvalidMasterPublicKey)?;
    let receiver_viewing_public_key =
        unblind_note_key(blinded_receiver_viewing_key, &shared_random, &sender_random)?;
    let receiver = NoteParty::new(receiver_master_public_key, receiver_viewing_public_key);
    let (note_public_key, commitment) = validate_note_commitment(
        receiver.master_public_key(),
        inputs.random,
        inputs.token_hash,
        inputs.value,
        inputs.expected_commitment,
    )?;

    let note = Note::new(
        receiver,
        Some(inputs.wallet.clone()),
        *inputs.token_hash,
        *inputs.random,
        inputs.value,
        Some(sender_random),
        inputs.memo,
        note_public_key,
        commitment,
    );

    Ok(ReconstructedNote::new(
        note,
        NotePerspective::Sent,
        inputs.encoded_master_public_key.clone(),
    ))
}

/// Reconstructs and validates a canonical V2 note from decrypted plaintext.
///
/// V2 sent-note reconstruction requires the caller to provide the decrypted
/// annotation sender-random, because V2 plaintext does not carry it directly.
///
/// # Errors
///
/// Returns an error if reconstruction inputs are inconsistent, a blinded viewing
/// key cannot be unblinded, or the recomputed commitment mismatches.
pub fn reconstruct_v2_note(
    plaintext: &V2Plaintext,
    wallet: &NoteParty,
    blinded_sender_viewing_key: &BlindedViewingPublicKey,
    blinded_receiver_viewing_key: &BlindedViewingPublicKey,
    perspective: NotePerspective,
    sender_random: Option<SenderRandom>,
    expected_commitment: &NoteCommitment,
) -> Result<ReconstructedNote, NoteReconstructionError> {
    match perspective {
        NotePerspective::Received => reconstruct_received_note(
            ReconstructionInputs {
                wallet,
                encoded_master_public_key: plaintext.encoded_master_public_key(),
                token_hash: plaintext.token_hash(),
                random: plaintext.random(),
                value: plaintext.value(),
                sender_random: None,
                memo: plaintext.memo().to_vec(),
                expected_commitment,
            },
            blinded_sender_viewing_key,
        ),
        NotePerspective::Sent => reconstruct_sent_note(
            ReconstructionInputs {
                wallet,
                encoded_master_public_key: plaintext.encoded_master_public_key(),
                token_hash: plaintext.token_hash(),
                random: plaintext.random(),
                value: plaintext.value(),
                sender_random,
                memo: plaintext.memo().to_vec(),
                expected_commitment,
            },
            blinded_receiver_viewing_key,
        ),
    }
}

/// Reconstructs and validates a canonical V3 note from decrypted plaintext.
///
/// # Errors
///
/// Returns an error if reconstruction inputs are inconsistent, a blinded viewing
/// key cannot be unblinded, or the recomputed commitment mismatches.
pub fn reconstruct_v3_note(
    plaintext: &V3Plaintext,
    wallet: &NoteParty,
    blinded_sender_viewing_key: &BlindedViewingPublicKey,
    blinded_receiver_viewing_key: &BlindedViewingPublicKey,
    perspective: NotePerspective,
    expected_commitment: &NoteCommitment,
) -> Result<ReconstructedNote, NoteReconstructionError> {
    match perspective {
        NotePerspective::Received => reconstruct_received_note(
            ReconstructionInputs {
                wallet,
                encoded_master_public_key: plaintext.encoded_master_public_key(),
                token_hash: plaintext.token_hash(),
                random: plaintext.random(),
                value: plaintext.value(),
                sender_random: Some(*plaintext.sender_random()),
                memo: plaintext.memo().to_vec(),
                expected_commitment,
            },
            blinded_sender_viewing_key,
        ),
        NotePerspective::Sent => reconstruct_sent_note(
            ReconstructionInputs {
                wallet,
                encoded_master_public_key: plaintext.encoded_master_public_key(),
                token_hash: plaintext.token_hash(),
                random: plaintext.random(),
                value: plaintext.value(),
                sender_random: Some(*plaintext.sender_random()),
                memo: plaintext.memo().to_vec(),
                expected_commitment,
            },
            blinded_receiver_viewing_key,
        ),
    }
}

/// Derives the canonical nullifier from a nullifying key and UTXO leaf index.
///
/// Poseidon input ordering is exactly `[nullifying_key, leaf_index]`
/// over the BN254 scalar field.
///
/// # Errors
///
/// Returns an error if `nullifying_key` is not a valid BN254 field element or
/// if Poseidon hashing fails unexpectedly.
pub fn derive_nullifier(
    nullifying_key: &NullifyingKey,
    leaf_index: LeafIndex,
) -> Result<Nullifier, KeyDerivationError> {
    let inputs = [
        poseidon::field_from_biguint(nullifying_key.value())
            .map_err(|_| KeyDerivationError::DerivationFailure)?,
        leaf_index.get().into(),
    ];
    let hash = poseidon::hash_fields(&inputs).map_err(|_| KeyDerivationError::DerivationFailure)?;

    Nullifier::new(poseidon::field_to_biguint(hash))
        .map_err(|_| KeyDerivationError::DerivationFailure)
}

/// Computes the tracked-note nullifier record from wallet scan keys and leaf metadata.
///
/// # Errors
///
/// Returns an error if canonical nullifier derivation fails unexpectedly.
pub fn compute_tracked_note_nullifier(
    scan_keys: &WalletScanKeyBundle,
    leaf_index: LeafIndex,
    tree_number: Option<u16>,
) -> Result<TrackedNoteNullifier, KeyDerivationError> {
    Ok(TrackedNoteNullifier::new(
        derive_nullifier(scan_keys.nullifying_key(), leaf_index)?,
        tree_number,
    ))
}

/// Returns whether an emitted nullifier marks the tracked note as spent.
///
/// When both sides provide tree context, the tree number must also match. If one
/// side lacks tree context, matching falls back to the canonical nullifier value.
#[must_use]
pub fn matches_emitted_nullifier(
    tracked: &TrackedNoteNullifier,
    emitted: &EmittedNullifier,
) -> bool {
    if tracked.nullifier() != emitted.nullifier() {
        return false;
    }

    match (tracked.tree_number(), emitted.tree_number()) {
        (Some(tracked_tree_number), Some(emitted_tree_number)) => {
            tracked_tree_number == emitted_tree_number
        }
        _ => true,
    }
}

/// Resolves the spent state for one tracked note against emitted nullifier events.
#[must_use]
pub fn spent_state_for_tracked_note(
    tracked: &TrackedNoteNullifier,
    emitted: &[EmittedNullifier],
) -> NoteSpentState {
    emitted
        .iter()
        .find(|candidate| matches_emitted_nullifier(tracked, candidate))
        .map_or(NoteSpentState::unspent(), |matched| {
            NoteSpentState::spent(matched.tree_number().or(tracked.tree_number()))
        })
}

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;
    use railgun_types::{
        BlindedViewingPublicKey, EmittedNullifier, LeafIndex, MasterPublicKey, Note,
        NoteCommitment, NoteParty, NotePerspective, NotePublicKey, NoteRandom, NoteSpentState,
        NoteValue, Nullifier, NullifyingKey, ReconstructedNote, SenderRandom, SenderRecovery,
        SenderVisibility, SharedRandom, TokenHash, TrackedNoteNullifier, V2Plaintext, V3Plaintext,
        ViewingPrivateKey, WalletNoteOwnership,
    };

    use super::{
        NoteReconstructionError, compute_tracked_note_nullifier, decode_master_public_key,
        derive_note_commitment, derive_note_public_key, derive_nullifier, encode_master_public_key,
        is_received_by_wallet, is_sent_by_wallet, matches_emitted_nullifier, reconstruct_v2_note,
        reconstruct_v3_note, recover_sender, sender_visibility, spent_state_for_tracked_note,
        validate_note_commitment, wallet_note_ownership,
    };
    use crate::{
        build_wallet_scan_key_bundle, derive_note_blinding_keys, derive_nullifying_key_from_bytes,
        derive_viewing_public_key, hd::KeyDerivationError,
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

    fn master_public_key(value: &str) -> MasterPublicKey {
        MasterPublicKey::new(
            BigUint::parse_bytes(value.as_bytes(), 10)
                .unwrap_or_else(|| panic!("master public key should parse")),
        )
        .unwrap_or_else(|error| panic!("master public key should validate: {error}"))
    }

    fn note_party(master_public_key_decimal: &str, viewing_private_key_hex: &str) -> NoteParty {
        let viewing_private_key = ViewingPrivateKey::new(decode_hex(viewing_private_key_hex));
        NoteParty::new(
            master_public_key(master_public_key_decimal),
            derive_viewing_public_key(&viewing_private_key),
        )
    }

    fn compute_blinded_keys(
        sender: &NoteParty,
        receiver: &NoteParty,
        random: &NoteRandom,
        sender_random: &SenderRandom,
    ) -> (BlindedViewingPublicKey, BlindedViewingPublicKey) {
        derive_note_blinding_keys(
            sender.viewing_public_key(),
            receiver.viewing_public_key(),
            &SharedRandom::new(*random.as_bytes()),
            sender_random,
        )
        .unwrap_or_else(|error| panic!("note blinding should succeed: {error}"))
    }

    #[test]
    fn derives_note_public_key_from_issue_vector() {
        let master_public_key = MasterPublicKey::new(
            BigUint::parse_bytes(
                b"20060431504059690749153982049210720252589378133547582826474262520121417617087",
                10,
            )
            .unwrap_or_else(|| panic!("master public key should parse")),
        )
        .unwrap_or_else(|error| panic!("master public key should validate: {error}"));
        let random = NoteRandom::from_slice(&[
            0x67, 0xc6, 0x00, 0xe7, 0x77, 0xb8, 0x6d, 0x3a, 0x1e, 0x72, 0xa5, 0x30, 0x92, 0xe9,
            0xfe, 0x85,
        ])
        .unwrap_or_else(|error| panic!("note random should validate: {error}"));

        let note_public_key = derive_note_public_key(&master_public_key, &random)
            .unwrap_or_else(|error| panic!("note public key should derive: {error}"));

        assert_eq!(
            note_public_key.value(),
            &BigUint::parse_bytes(
                b"6401386539363233023821237080626891507664131047949709897410333742190241828916",
                10,
            )
            .unwrap_or_else(|| panic!("note public key should parse"))
        );
    }

    #[test]
    fn derives_note_commitment_from_hex_vector() {
        let note_public_key = NotePublicKey::new(BigUint::from_bytes_be(&decode_hex::<32>(
            "23da85e72baa8d77f476a893de0964ce1ec2957d056b591a19d05bb4b9a549ed",
        )))
        .unwrap_or_else(|error| panic!("note public key should validate: {error}"));
        let token_hash = TokenHash::from_slice(&decode_hex::<32>(
            "0000000000000000000000007f4925cdf66ddf5b88016df1fe915e68eff8f192",
        ))
        .unwrap_or_else(|error| panic!("token hash should validate: {error}"));
        let value = NoteValue::from_be_bytes(decode_hex::<16>("0000000000000000086aa1ade61ccb53"));

        let commitment = derive_note_commitment(&note_public_key, &token_hash, value)
            .unwrap_or_else(|error| panic!("note commitment should derive: {error}"));

        assert_eq!(
            commitment.value(),
            &BigUint::from_bytes_be(&decode_hex::<32>(
                "29decce78b2f43c718ebb7c6825617ea6881836d88d9551dd2530c44f0d790c5",
            ))
        );
    }

    #[test]
    fn derives_note_commitment_from_decimal_vector() {
        let note_public_key = NotePublicKey::new(
            BigUint::parse_bytes(
                b"6401386539363233023821237080626891507664131047949709897410333742190241828916",
                10,
            )
            .unwrap_or_else(|| panic!("note public key should parse")),
        )
        .unwrap_or_else(|error| panic!("note public key should validate: {error}"));
        let token_hash = TokenHash::from_slice(&decode_hex::<32>(
            "0000000000000000000000009fe46736679d2d9a65f0992f2272de9f3c7fa6e0",
        ))
        .unwrap_or_else(|error| panic!("token hash should validate: {error}"));
        let value = NoteValue::new(109_725_000_000_000_000_000_000_u128);

        let commitment = derive_note_commitment(&note_public_key, &token_hash, value)
            .unwrap_or_else(|error| panic!("note commitment should derive: {error}"));

        assert_eq!(
            commitment.value(),
            &BigUint::parse_bytes(
                b"6442080113031815261226726790601252395803415545769290265212232865825296902085",
                10,
            )
            .unwrap_or_else(|| panic!("commitment should parse"))
        );
    }

    #[test]
    fn derives_nullifier_from_vector_one() {
        let nullifying_key = NullifyingKey::new(BigUint::from_bytes_be(&decode_hex::<32>(
            "08ad9143ae793cdfe94b77e4e52bc4e9f13666966cffa395e3d412ea4e20480f",
        )))
        .unwrap_or_else(|error| panic!("nullifying key should validate: {error}"));

        let nullifier = derive_nullifier(&nullifying_key, LeafIndex::new(0))
            .unwrap_or_else(|error| panic!("nullifier should derive: {error}"));

        assert_eq!(
            nullifier.value(),
            &BigUint::from_bytes_be(&decode_hex::<32>(
                "03f68801f3ee2ed10178c162b4f7f1bd466bc9718f4f98175fc04934c5caba6e",
            ))
        );
    }

    #[test]
    fn derives_nullifier_from_vector_two() {
        let nullifying_key = NullifyingKey::new(BigUint::from_bytes_be(&decode_hex::<32>(
            "11299eb10424d82de500a440a2874d12f7c477afb5a3eb31dbb96295cdbcf165",
        )))
        .unwrap_or_else(|error| panic!("nullifying key should validate: {error}"));

        let nullifier = derive_nullifier(&nullifying_key, LeafIndex::new(12))
            .unwrap_or_else(|error| panic!("nullifier should derive: {error}"));

        assert_eq!(
            nullifier.value(),
            &BigUint::from_bytes_be(&decode_hex::<32>(
                "1aeadb64bf8faff93dfe26bcf0b2e2d0e9724293cc7a455f028b6accabee13b8",
            ))
        );
    }

    #[test]
    fn derives_nullifier_from_vector_three() {
        let nullifying_key = NullifyingKey::new(BigUint::from_bytes_be(&decode_hex::<32>(
            "09b57736523cda7412ddfed0d2f1f4a86d8a7e26de6b0638cd092c2a2b524705",
        )))
        .unwrap_or_else(|error| panic!("nullifying key should validate: {error}"));

        let nullifier = derive_nullifier(&nullifying_key, LeafIndex::new(6_500))
            .unwrap_or_else(|error| panic!("nullifier should derive: {error}"));

        assert_eq!(
            nullifier.value(),
            &BigUint::from_bytes_be(&decode_hex::<32>(
                "091961ce11c244db49a25668e57dfa2b5ffb1fe63055dd64a14af6f2be58b0e7",
            ))
        );
    }

    #[test]
    fn computes_tracked_note_nullifier_from_scan_bundle() {
        let bundle = build_wallet_scan_key_bundle(
            ViewingPrivateKey::new([7_u8; 32]),
            master_public_key("123456789"),
        )
        .unwrap_or_else(|error| panic!("scan bundle should build: {error}"));

        let tracked = compute_tracked_note_nullifier(&bundle, LeafIndex::new(9), Some(2))
            .unwrap_or_else(|error| panic!("tracked nullifier should compute: {error}"));
        let expected = derive_nullifier(bundle.nullifying_key(), LeafIndex::new(9))
            .unwrap_or_else(|error| panic!("nullifier should derive: {error}"));

        assert_eq!(tracked, TrackedNoteNullifier::new(expected, Some(2)));
    }

    #[test]
    fn matching_emitted_nullifier_marks_tracked_note_spent() {
        let tracked = TrackedNoteNullifier::new(
            Nullifier::new(BigUint::from_bytes_be(&decode_hex::<32>(
                "03f68801f3ee2ed10178c162b4f7f1bd466bc9718f4f98175fc04934c5caba6e",
            )))
            .unwrap_or_else(|error| panic!("nullifier should validate: {error}")),
            Some(4),
        );
        let emitted = [EmittedNullifier::new(tracked.nullifier().clone(), Some(4))];

        assert!(matches_emitted_nullifier(&tracked, &emitted[0]));
        assert_eq!(
            spent_state_for_tracked_note(&tracked, &emitted),
            NoteSpentState::spent(Some(4))
        );
    }

    #[test]
    fn non_matching_emitted_nullifier_keeps_tracked_note_unspent() {
        let tracked = TrackedNoteNullifier::new(
            Nullifier::new(BigUint::from_bytes_be(&decode_hex::<32>(
                "03f68801f3ee2ed10178c162b4f7f1bd466bc9718f4f98175fc04934c5caba6e",
            )))
            .unwrap_or_else(|error| panic!("tracked nullifier should validate: {error}")),
            Some(4),
        );
        let emitted = [EmittedNullifier::new(
            Nullifier::new(BigUint::from_bytes_be(&decode_hex::<32>(
                "1aeadb64bf8faff93dfe26bcf0b2e2d0e9724293cc7a455f028b6accabee13b8",
            )))
            .unwrap_or_else(|error| panic!("emitted nullifier should validate: {error}")),
            Some(4),
        )];

        assert!(!matches_emitted_nullifier(&tracked, &emitted[0]));
        assert_eq!(spent_state_for_tracked_note(&tracked, &emitted), NoteSpentState::unspent());
    }

    #[test]
    fn tree_aware_matching_rejects_same_nullifier_with_different_tree_number() {
        let nullifier = Nullifier::new(BigUint::from(1_u8))
            .unwrap_or_else(|error| panic!("nullifier should validate: {error}"));
        let tracked = TrackedNoteNullifier::new(nullifier.clone(), Some(1));
        let emitted = EmittedNullifier::new(nullifier, Some(2));

        assert!(!matches_emitted_nullifier(&tracked, &emitted));
        assert_eq!(spent_state_for_tracked_note(&tracked, &[emitted]), NoteSpentState::unspent());
    }

    #[test]
    fn missing_tree_context_falls_back_to_nullifier_only_matching() {
        let nullifier = Nullifier::new(BigUint::from(1_u8))
            .unwrap_or_else(|error| panic!("nullifier should validate: {error}"));
        let tracked = TrackedNoteNullifier::new(nullifier.clone(), Some(7));
        let emitted = EmittedNullifier::new(nullifier, None);

        assert!(matches_emitted_nullifier(&tracked, &emitted));
        assert_eq!(
            spent_state_for_tracked_note(&tracked, &[emitted]),
            NoteSpentState::spent(Some(7))
        );
    }

    #[test]
    fn hidden_sender_mode_preserves_receiver_master_public_key() {
        let receiver_master_public_key = master_public_key(
            "20060431504059690749153982049210720252589378133547582826474262520121417617087",
        );
        let sender_master_public_key = master_public_key("123456789");
        let sender_random = SenderRandom::from_slice(&[7_u8; SenderRandom::LENGTH])
            .unwrap_or_else(|error| panic!("sender random should validate: {error}"));

        let encoded = encode_master_public_key(
            &receiver_master_public_key,
            &sender_master_public_key,
            Some(&sender_random),
        )
        .unwrap_or_else(|error| panic!("encoded master public key should derive: {error}"));

        assert_eq!(sender_visibility(Some(&sender_random)), SenderVisibility::Hidden);
        assert_eq!(encoded, receiver_master_public_key);
    }

    #[test]
    fn visible_sender_mode_xors_receiver_and_sender_master_public_keys() {
        let receiver_master_public_key = master_public_key(
            "20060431504059690749153982049210720252589378133547582826474262520121417617087",
        );
        let sender_master_public_key = master_public_key("123456789");

        let encoded_without_sender_random =
            encode_master_public_key(&receiver_master_public_key, &sender_master_public_key, None)
                .unwrap_or_else(|error| {
                    panic!("visible sender derivation should succeed: {error}")
                });
        let encoded_with_null_sentinel = encode_master_public_key(
            &receiver_master_public_key,
            &sender_master_public_key,
            Some(&SenderRandom::null_sentinel()),
        )
        .unwrap_or_else(|error| panic!("null-sentinel derivation should succeed: {error}"));

        let receiver_bytes = receiver_master_public_key.to_be_bytes();
        let sender_bytes = sender_master_public_key.to_be_bytes();
        let expected_bytes: [u8; 32] =
            core::array::from_fn(|index| receiver_bytes[index] ^ sender_bytes[index]);
        let expected = MasterPublicKey::new(BigUint::from_bytes_be(&expected_bytes))
            .unwrap_or_else(|error| {
                panic!("expected encoded master public key should validate: {error}")
            });

        assert_eq!(sender_visibility(None), SenderVisibility::Visible);
        assert_eq!(
            sender_visibility(Some(&SenderRandom::null_sentinel())),
            SenderVisibility::Visible
        );
        assert_eq!(encoded_without_sender_random, expected);
        assert_eq!(encoded_with_null_sentinel, expected);
    }

    #[test]
    fn note_public_key_derivation_is_deterministic() {
        let master_public_key = MasterPublicKey::new(BigUint::from(42_u8))
            .unwrap_or_else(|error| panic!("master public key should validate: {error}"));
        let random = NoteRandom::new([9_u8; NoteRandom::LENGTH]);

        let first = derive_note_public_key(&master_public_key, &random)
            .unwrap_or_else(|error| panic!("first derivation should succeed: {error}"));
        let second = derive_note_public_key(&master_public_key, &random)
            .unwrap_or_else(|error| panic!("second derivation should succeed: {error}"));

        assert_eq!(first, second);
    }

    #[test]
    fn note_commitment_derivation_is_deterministic() {
        let note_public_key = NotePublicKey::new(BigUint::from(42_u8))
            .unwrap_or_else(|error| panic!("note public key should validate: {error}"));
        let token_hash = TokenHash::from_slice(&[3_u8; TokenHash::LENGTH])
            .unwrap_or_else(|error| panic!("token hash should validate: {error}"));
        let value = NoteValue::new(9_u128);

        let first = derive_note_commitment(&note_public_key, &token_hash, value)
            .unwrap_or_else(|error| panic!("first derivation should succeed: {error}"));
        let second = derive_note_commitment(&note_public_key, &token_hash, value)
            .unwrap_or_else(|error| panic!("second derivation should succeed: {error}"));

        assert_eq!(first, second);
    }

    #[test]
    fn nullifier_derivation_is_deterministic() {
        let nullifying_key = derive_nullifying_key_from_bytes(&[7_u8; 32])
            .unwrap_or_else(|error| panic!("nullifying key should derive: {error}"));

        let first = derive_nullifier(&nullifying_key, LeafIndex::new(9))
            .unwrap_or_else(|error| panic!("first derivation should succeed: {error}"));
        let second = derive_nullifier(&nullifying_key, LeafIndex::new(9))
            .unwrap_or_else(|error| panic!("second derivation should succeed: {error}"));

        assert_eq!(first, second);
    }

    #[test]
    fn note_public_key_derivation_depends_on_input_ordering() {
        let master_public_key = MasterPublicKey::new(BigUint::from(42_u8))
            .unwrap_or_else(|error| panic!("master public key should validate: {error}"));
        let random = NoteRandom::new([9_u8; NoteRandom::LENGTH]);

        let ordered = derive_note_public_key(&master_public_key, &random)
            .unwrap_or_else(|error| panic!("ordered derivation should succeed: {error}"));
        let swapped_master_public_key = MasterPublicKey::new(BigUint::from_bytes_be(
            random.as_bytes(),
        ))
        .unwrap_or_else(|error| panic!("swapped master public key should validate: {error}"));
        let swapped_random = NoteRandom::new([0_u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 42]);
        let swapped = derive_note_public_key(&swapped_master_public_key, &swapped_random)
            .unwrap_or_else(|error| panic!("swapped derivation should succeed: {error}"));

        assert_ne!(ordered, swapped);
    }

    #[test]
    fn note_commitment_derivation_depends_on_input_ordering() {
        let note_public_key = NotePublicKey::new(BigUint::from(42_u8))
            .unwrap_or_else(|error| panic!("note public key should validate: {error}"));
        let token_hash = TokenHash::from_slice(&[3_u8; TokenHash::LENGTH])
            .unwrap_or_else(|error| panic!("token hash should validate: {error}"));
        let value = NoteValue::new(9_u128);

        let ordered = derive_note_commitment(&note_public_key, &token_hash, value)
            .unwrap_or_else(|error| panic!("ordered derivation should succeed: {error}"));
        let swapped_note_public_key =
            NotePublicKey::new(BigUint::from_bytes_be(token_hash.as_bytes()))
                .unwrap_or_else(|error| panic!("swapped note public key should validate: {error}"));
        let mut swapped_token_hash_bytes = [0_u8; TokenHash::LENGTH];
        swapped_token_hash_bytes[31] = 42;
        let swapped_token_hash = TokenHash::from_slice(&swapped_token_hash_bytes)
            .unwrap_or_else(|error| panic!("swapped token hash should validate: {error}"));
        let swapped = derive_note_commitment(
            &swapped_note_public_key,
            &swapped_token_hash,
            NoteValue::new(3_u128),
        )
        .unwrap_or_else(|error| panic!("swapped derivation should succeed: {error}"));

        assert_ne!(ordered, swapped);
    }

    #[test]
    fn nullifier_derivation_depends_on_input_ordering() {
        let nullifying_key = derive_nullifying_key_from_bytes(&[7_u8; 32])
            .unwrap_or_else(|error| panic!("nullifying key should derive: {error}"));

        let ordered = derive_nullifier(&nullifying_key, LeafIndex::new(9))
            .unwrap_or_else(|error| panic!("ordered derivation should succeed: {error}"));
        let swapped_nullifying_key = derive_nullifying_key_from_bytes(
            &[0_u8; 31].iter().copied().chain(core::iter::once(9_u8)).collect::<Vec<_>>(),
        )
        .unwrap_or_else(|error| panic!("swapped nullifying key should derive: {error}"));
        let swapped = derive_nullifier(&swapped_nullifying_key, LeafIndex::new(7))
            .unwrap_or_else(|error| panic!("swapped derivation should succeed: {error}"));

        assert_ne!(ordered, swapped);
    }

    #[test]
    fn decodes_visible_sender_master_public_key() {
        let receiver_master_public_key = master_public_key(
            "20060431504059690749153982049210720252589378133547582826474262520121417617087",
        );
        let sender_master_public_key = master_public_key("123456789");
        let encoded = encode_master_public_key(
            &receiver_master_public_key,
            &sender_master_public_key,
            Some(&SenderRandom::null_sentinel()),
        )
        .unwrap_or_else(|error| panic!("encoded master public key should derive: {error}"));

        let decoded = decode_master_public_key(
            &receiver_master_public_key,
            &encoded,
            Some(&SenderRandom::null_sentinel()),
        )
        .unwrap_or_else(|error| panic!("decoded master public key should derive: {error}"));

        assert_eq!(decoded, sender_master_public_key);
    }

    #[test]
    fn recover_sender_returns_visible_sender_master_public_key() {
        let receiver_master_public_key = master_public_key(
            "20060431504059690749153982049210720252589378133547582826474262520121417617087",
        );
        let sender_master_public_key = master_public_key("123456789");
        let encoded = encode_master_public_key(
            &receiver_master_public_key,
            &sender_master_public_key,
            Some(&SenderRandom::null_sentinel()),
        )
        .unwrap_or_else(|error| panic!("encoded master public key should derive: {error}"));

        let recovered = recover_sender(
            &encoded,
            &receiver_master_public_key,
            Some(&SenderRandom::null_sentinel()),
        )
        .unwrap_or_else(|error| panic!("visible sender recovery should succeed: {error}"));

        assert_eq!(
            recovered,
            SenderRecovery::new(SenderVisibility::Visible, Some(sender_master_public_key))
        );
        assert!(recovered.sender_visible());
    }

    #[test]
    fn recover_sender_returns_none_in_hidden_mode() {
        let receiver_master_public_key = master_public_key(
            "20060431504059690749153982049210720252589378133547582826474262520121417617087",
        );
        let sender_master_public_key = master_public_key("123456789");
        let sender_random = SenderRandom::from_slice(&[7_u8; SenderRandom::LENGTH])
            .unwrap_or_else(|error| panic!("sender random should validate: {error}"));
        let encoded = encode_master_public_key(
            &receiver_master_public_key,
            &sender_master_public_key,
            Some(&sender_random),
        )
        .unwrap_or_else(|error| panic!("encoded master public key should derive: {error}"));

        let recovered = recover_sender(&encoded, &receiver_master_public_key, Some(&sender_random))
            .unwrap_or_else(|error| panic!("hidden sender recovery should succeed: {error}"));

        assert_eq!(recovered, SenderRecovery::new(SenderVisibility::Hidden, None));
        assert!(!recovered.sender_visible());
    }

    #[test]
    fn recover_sender_treats_missing_sender_random_as_visible() {
        let receiver_master_public_key = master_public_key(
            "20060431504059690749153982049210720252589378133547582826474262520121417617087",
        );
        let sender_master_public_key = master_public_key("123456789");
        let encoded =
            encode_master_public_key(&receiver_master_public_key, &sender_master_public_key, None)
                .unwrap_or_else(|error| panic!("encoded master public key should derive: {error}"));

        let recovered = recover_sender(&encoded, &receiver_master_public_key, None)
            .unwrap_or_else(|error| panic!("sender recovery should succeed: {error}"));

        assert_eq!(
            recovered,
            SenderRecovery::new(SenderVisibility::Visible, Some(sender_master_public_key))
        );
    }

    #[test]
    fn validates_note_commitment_against_issue_vector() {
        let receiver_master_public_key = master_public_key(
            "20060431504059690749153982049210720252589378133547582826474262520121417617087",
        );
        let random = NoteRandom::new(decode_hex("67c600e777b86d3a1e72a53092e9fe85"));
        let token_hash = TokenHash::new(decode_hex(
            "0000000000000000000000009fe46736679d2d9a65f0992f2272de9f3c7fa6e0",
        ));
        let value = NoteValue::new(109_725_000_000_000_000_000_000_u128);
        let expected_commitment = NoteCommitment::new(
            BigUint::parse_bytes(
                b"6442080113031815261226726790601252395803415545769290265212232865825296902085",
                10,
            )
            .unwrap_or_else(|| panic!("commitment should parse")),
        )
        .unwrap_or_else(|error| panic!("commitment should validate: {error}"));

        let (note_public_key, commitment) = validate_note_commitment(
            &receiver_master_public_key,
            &random,
            &token_hash,
            value,
            &expected_commitment,
        )
        .unwrap_or_else(|error| panic!("commitment should validate: {error}"));

        assert_eq!(
            note_public_key.value(),
            &BigUint::parse_bytes(
                b"6401386539363233023821237080626891507664131047949709897410333742190241828916",
                10,
            )
            .unwrap_or_else(|| panic!("note public key should parse"))
        );
        assert_eq!(commitment, expected_commitment);
    }

    #[test]
    fn wallet_note_ownership_marks_matching_receiver() {
        let wallet = note_party(
            "20060431504059690749153982049210720252589378133547582826474262520121417617087",
            "3428cfc939320328501174a4e76e869197ffc894b58dbf4d0e953c484d66cb5e",
        );
        let other_sender = note_party(
            "123456789",
            "67d7d19d00e6e3b3517fe68ac46505dd207df6e8fe3aa06ba3face352e7599ef",
        );
        let ownership = wallet_note_ownership(
            &build_wallet_scan_key_bundle(
                ViewingPrivateKey::new([9_u8; 32]),
                wallet.master_public_key().clone(),
            )
            .unwrap_or_else(|error| panic!("scan bundle should build: {error}")),
            &ReconstructedNote::new(
                Note::new(
                    wallet.clone(),
                    Some(other_sender),
                    TokenHash::new([1_u8; 32]),
                    NoteRandom::new([2_u8; 16]),
                    NoteValue::new(3_u128),
                    None,
                    Vec::new(),
                    NotePublicKey::new(BigUint::from(4_u8))
                        .unwrap_or_else(|error| panic!("note public key should validate: {error}")),
                    NoteCommitment::new(BigUint::from(5_u8))
                        .unwrap_or_else(|error| panic!("commitment should validate: {error}")),
                ),
                NotePerspective::Received,
                wallet.master_public_key().clone(),
            ),
        );

        assert_eq!(ownership, WalletNoteOwnership::new(true, false));
        assert!(is_received_by_wallet(
            &build_wallet_scan_key_bundle(
                ViewingPrivateKey::new([9_u8; 32]),
                wallet.master_public_key().clone(),
            )
            .unwrap_or_else(|error| panic!("scan bundle should build: {error}")),
            &ReconstructedNote::new(
                Note::new(
                    wallet,
                    None,
                    TokenHash::new([1_u8; 32]),
                    NoteRandom::new([2_u8; 16]),
                    NoteValue::new(3_u128),
                    None,
                    Vec::new(),
                    NotePublicKey::new(BigUint::from(4_u8))
                        .unwrap_or_else(|error| panic!("note public key should validate: {error}")),
                    NoteCommitment::new(BigUint::from(5_u8))
                        .unwrap_or_else(|error| panic!("commitment should validate: {error}")),
                ),
                NotePerspective::Received,
                MasterPublicKey::new(BigUint::from(0_u8))
                    .unwrap_or_else(|error| panic!("encoded mpk should validate: {error}")),
            )
        ));
    }

    #[test]
    fn wallet_note_ownership_marks_non_owner_note() {
        let receiver = note_party(
            "20060431504059690749153982049210720252589378133547582826474262520121417617087",
            "3428cfc939320328501174a4e76e869197ffc894b58dbf4d0e953c484d66cb5e",
        );
        let wallet_bundle = build_wallet_scan_key_bundle(
            ViewingPrivateKey::new([9_u8; 32]),
            master_public_key("987654321"),
        )
        .unwrap_or_else(|error| panic!("scan bundle should build: {error}"));
        let note = ReconstructedNote::new(
            Note::new(
                receiver,
                None,
                TokenHash::new([1_u8; 32]),
                NoteRandom::new([2_u8; 16]),
                NoteValue::new(3_u128),
                None,
                Vec::new(),
                NotePublicKey::new(BigUint::from(4_u8))
                    .unwrap_or_else(|error| panic!("note public key should validate: {error}")),
                NoteCommitment::new(BigUint::from(5_u8))
                    .unwrap_or_else(|error| panic!("commitment should validate: {error}")),
            ),
            NotePerspective::Received,
            master_public_key("1"),
        );

        assert_eq!(
            wallet_note_ownership(&wallet_bundle, &note),
            WalletNoteOwnership::new(false, false)
        );
        assert!(!is_received_by_wallet(&wallet_bundle, &note));
        assert!(!is_sent_by_wallet(&wallet_bundle, &note));
    }

    #[test]
    fn wallet_note_ownership_marks_matching_sender_when_present() {
        let wallet = note_party(
            "123456789",
            "67d7d19d00e6e3b3517fe68ac46505dd207df6e8fe3aa06ba3face352e7599ef",
        );
        let receiver = note_party(
            "20060431504059690749153982049210720252589378133547582826474262520121417617087",
            "3428cfc939320328501174a4e76e869197ffc894b58dbf4d0e953c484d66cb5e",
        );
        let wallet_bundle = build_wallet_scan_key_bundle(
            ViewingPrivateKey::new([9_u8; 32]),
            wallet.master_public_key().clone(),
        )
        .unwrap_or_else(|error| panic!("scan bundle should build: {error}"));
        let note = ReconstructedNote::new(
            Note::new(
                receiver,
                Some(wallet),
                TokenHash::new([1_u8; 32]),
                NoteRandom::new([2_u8; 16]),
                NoteValue::new(3_u128),
                Some(SenderRandom::null_sentinel()),
                Vec::new(),
                NotePublicKey::new(BigUint::from(4_u8))
                    .unwrap_or_else(|error| panic!("note public key should validate: {error}")),
                NoteCommitment::new(BigUint::from(5_u8))
                    .unwrap_or_else(|error| panic!("commitment should validate: {error}")),
            ),
            NotePerspective::Sent,
            master_public_key("2"),
        );

        assert_eq!(
            wallet_note_ownership(&wallet_bundle, &note),
            WalletNoteOwnership::new(false, true)
        );
        assert!(is_sent_by_wallet(&wallet_bundle, &note));
    }

    #[test]
    fn wallet_note_ownership_requires_sender_metadata_for_sent_detection() {
        let receiver = note_party(
            "20060431504059690749153982049210720252589378133547582826474262520121417617087",
            "3428cfc939320328501174a4e76e869197ffc894b58dbf4d0e953c484d66cb5e",
        );
        let wallet_bundle = build_wallet_scan_key_bundle(
            ViewingPrivateKey::new([9_u8; 32]),
            master_public_key("123456789"),
        )
        .unwrap_or_else(|error| panic!("scan bundle should build: {error}"));
        let note = ReconstructedNote::new(
            Note::new(
                receiver,
                None,
                TokenHash::new([1_u8; 32]),
                NoteRandom::new([2_u8; 16]),
                NoteValue::new(3_u128),
                Some(SenderRandom::new([7_u8; SenderRandom::LENGTH])),
                Vec::new(),
                NotePublicKey::new(BigUint::from(4_u8))
                    .unwrap_or_else(|error| panic!("note public key should validate: {error}")),
                NoteCommitment::new(BigUint::from(5_u8))
                    .unwrap_or_else(|error| panic!("commitment should validate: {error}")),
            ),
            NotePerspective::Received,
            master_public_key("3"),
        );

        assert_eq!(
            wallet_note_ownership(&wallet_bundle, &note),
            WalletNoteOwnership::new(false, false)
        );
        assert!(!is_sent_by_wallet(&wallet_bundle, &note));
    }

    #[test]
    fn reconstructs_v2_received_note_with_visible_sender() {
        let sender = note_party(
            "123456789",
            "67d7d19d00e6e3b3517fe68ac46505dd207df6e8fe3aa06ba3face352e7599ef",
        );
        let receiver = note_party(
            "20060431504059690749153982049210720252589378133547582826474262520121417617087",
            "3428cfc939320328501174a4e76e869197ffc894b58dbf4d0e953c484d66cb5e",
        );
        let random = NoteRandom::new(decode_hex("85b08a7cd73ee433072f1d410aeb4801"));
        let sender_random = SenderRandom::null_sentinel();
        let token_hash = TokenHash::new(decode_hex(
            "0000000000000000000000007f4925cdf66ddf5b88016df1fe915e68eff8f192",
        ));
        let value = NoteValue::new(0x086a_a1ad_e61c_cb53);
        let encoded_master_public_key = encode_master_public_key(
            receiver.master_public_key(),
            sender.master_public_key(),
            Some(&sender_random),
        )
        .unwrap_or_else(|error| panic!("encoded master public key should derive: {error}"));
        let plaintext = V2Plaintext::new(
            encoded_master_public_key,
            token_hash,
            random,
            value,
            b"visible-v2".to_vec(),
        );
        let (blinded_sender_viewing_key, blinded_receiver_viewing_key) =
            compute_blinded_keys(&sender, &receiver, &random, &sender_random);
        let expected_commitment = derive_note_commitment(
            &derive_note_public_key(receiver.master_public_key(), &random)
                .unwrap_or_else(|error| panic!("note public key should derive: {error}")),
            &token_hash,
            value,
        )
        .unwrap_or_else(|error| panic!("commitment should derive: {error}"));

        let reconstructed = reconstruct_v2_note(
            &plaintext,
            &receiver,
            &blinded_sender_viewing_key,
            &blinded_receiver_viewing_key,
            NotePerspective::Received,
            None,
            &expected_commitment,
        )
        .unwrap_or_else(|error| panic!("v2 received reconstruction should succeed: {error}"));

        assert_eq!(reconstructed.note().receiver(), &receiver);
        assert_eq!(reconstructed.note().sender(), Some(&sender));
        assert_eq!(reconstructed.note().sender_random(), None);
        assert_eq!(reconstructed.note().memo(), b"visible-v2");
        assert_eq!(reconstructed.note().commitment(), &expected_commitment);
    }

    #[test]
    fn v2_received_note_does_not_invent_sender_when_encoded_mpk_equals_receiver() {
        let sender = note_party(
            "123456789",
            "67d7d19d00e6e3b3517fe68ac46505dd207df6e8fe3aa06ba3face352e7599ef",
        );
        let receiver = note_party(
            "20060431504059690749153982049210720252589378133547582826474262520121417617087",
            "3428cfc939320328501174a4e76e869197ffc894b58dbf4d0e953c484d66cb5e",
        );
        let random = NoteRandom::new(decode_hex("85b08a7cd73ee433072f1d410aeb4801"));
        let sender_random = SenderRandom::null_sentinel();
        let token_hash = TokenHash::new(decode_hex(
            "0000000000000000000000007f4925cdf66ddf5b88016df1fe915e68eff8f192",
        ));
        let value = NoteValue::new(0x086a_a1ad_e61c_cb53);
        let plaintext = V2Plaintext::new(
            receiver.master_public_key().clone(),
            token_hash,
            random,
            value,
            b"ambiguous-v2".to_vec(),
        );
        let (blinded_sender_viewing_key, blinded_receiver_viewing_key) =
            compute_blinded_keys(&sender, &receiver, &random, &sender_random);
        let expected_commitment = derive_note_commitment(
            &derive_note_public_key(receiver.master_public_key(), &random)
                .unwrap_or_else(|error| panic!("note public key should derive: {error}")),
            &token_hash,
            value,
        )
        .unwrap_or_else(|error| panic!("commitment should derive: {error}"));

        let reconstructed = reconstruct_v2_note(
            &plaintext,
            &receiver,
            &blinded_sender_viewing_key,
            &blinded_receiver_viewing_key,
            NotePerspective::Received,
            None,
            &expected_commitment,
        )
        .unwrap_or_else(|error| {
            panic!("ambiguous v2 received reconstruction should succeed: {error}")
        });

        assert_eq!(reconstructed.note().receiver(), &receiver);
        assert_eq!(reconstructed.note().sender(), None);
        assert_eq!(reconstructed.note().sender_random(), None);
        assert_eq!(reconstructed.note().memo(), b"ambiguous-v2");
        assert_eq!(reconstructed.note().commitment(), &expected_commitment);
    }

    #[test]
    fn reconstructs_v2_sent_note_with_hidden_sender() {
        let sender = note_party(
            "123456789",
            "67d7d19d00e6e3b3517fe68ac46505dd207df6e8fe3aa06ba3face352e7599ef",
        );
        let receiver = note_party(
            "20060431504059690749153982049210720252589378133547582826474262520121417617087",
            "3428cfc939320328501174a4e76e869197ffc894b58dbf4d0e953c484d66cb5e",
        );
        let random = NoteRandom::new(decode_hex("22222222222222222222222222222222"));
        let sender_random = SenderRandom::new(decode_hex("86727859e3fe7c0d81e27dfafaf0d9"));
        let token_hash = TokenHash::new(decode_hex(
            "0000000000000000000000009fe46736679d2d9a65f0992f2272de9f3c7fa6e0",
        ));
        let value = NoteValue::new(0x0003_635c_9adc_5dea_0000);
        let encoded_master_public_key = encode_master_public_key(
            receiver.master_public_key(),
            sender.master_public_key(),
            Some(&sender_random),
        )
        .unwrap_or_else(|error| panic!("encoded master public key should derive: {error}"));
        let plaintext = V2Plaintext::new(
            encoded_master_public_key,
            token_hash,
            random,
            value,
            b"hidden-v2".to_vec(),
        );
        let (blinded_sender_viewing_key, blinded_receiver_viewing_key) =
            compute_blinded_keys(&sender, &receiver, &random, &sender_random);
        let expected_commitment = derive_note_commitment(
            &derive_note_public_key(receiver.master_public_key(), &random)
                .unwrap_or_else(|error| panic!("note public key should derive: {error}")),
            &token_hash,
            value,
        )
        .unwrap_or_else(|error| panic!("commitment should derive: {error}"));

        let reconstructed = reconstruct_v2_note(
            &plaintext,
            &sender,
            &blinded_sender_viewing_key,
            &blinded_receiver_viewing_key,
            NotePerspective::Sent,
            Some(sender_random),
            &expected_commitment,
        )
        .unwrap_or_else(|error| panic!("v2 sent reconstruction should succeed: {error}"));

        assert_eq!(reconstructed.note().receiver(), &receiver);
        assert_eq!(reconstructed.note().sender(), Some(&sender));
        assert_eq!(reconstructed.note().sender_random(), Some(&sender_random));
        assert_eq!(reconstructed.note().memo(), b"hidden-v2");
    }

    #[test]
    fn v2_sent_note_requires_sender_random() {
        let sender = note_party(
            "123456789",
            "67d7d19d00e6e3b3517fe68ac46505dd207df6e8fe3aa06ba3face352e7599ef",
        );
        let receiver = note_party(
            "20060431504059690749153982049210720252589378133547582826474262520121417617087",
            "3428cfc939320328501174a4e76e869197ffc894b58dbf4d0e953c484d66cb5e",
        );
        let random = NoteRandom::new([7_u8; NoteRandom::LENGTH]);
        let sender_random = SenderRandom::null_sentinel();
        let token_hash = TokenHash::new([8_u8; TokenHash::LENGTH]);
        let value = NoteValue::new(9_u128);
        let plaintext = V2Plaintext::new(
            encode_master_public_key(
                receiver.master_public_key(),
                sender.master_public_key(),
                Some(&sender_random),
            )
            .unwrap_or_else(|error| panic!("encoded master public key should derive: {error}")),
            token_hash,
            random,
            value,
            Vec::new(),
        );
        let (blinded_sender_viewing_key, blinded_receiver_viewing_key) =
            compute_blinded_keys(&sender, &receiver, &random, &sender_random);
        let expected_commitment = derive_note_commitment(
            &derive_note_public_key(receiver.master_public_key(), &random)
                .unwrap_or_else(|error| panic!("note public key should derive: {error}")),
            &token_hash,
            value,
        )
        .unwrap_or_else(|error| panic!("commitment should derive: {error}"));

        let Err(error) = reconstruct_v2_note(
            &plaintext,
            &sender,
            &blinded_sender_viewing_key,
            &blinded_receiver_viewing_key,
            NotePerspective::Sent,
            None,
            &expected_commitment,
        ) else {
            panic!("v2 sent reconstruction without sender random should fail");
        };

        assert_eq!(error, NoteReconstructionError::MissingV2SentSenderRandom);
    }

    #[test]
    fn reconstructs_v3_received_note_with_hidden_sender() {
        let sender = note_party(
            "123456789",
            "67d7d19d00e6e3b3517fe68ac46505dd207df6e8fe3aa06ba3face352e7599ef",
        );
        let receiver = note_party(
            "20060431504059690749153982049210720252589378133547582826474262520121417617087",
            "3428cfc939320328501174a4e76e869197ffc894b58dbf4d0e953c484d66cb5e",
        );
        let random = NoteRandom::new(decode_hex("85b08a7cd73ee433072f1d410aeb4801"));
        let sender_random = SenderRandom::new(decode_hex("222222222222222222222222222222"));
        let token_hash = TokenHash::new(decode_hex(
            "0000000000000000000000007f4925cdf66ddf5b88016df1fe915e68eff8f192",
        ));
        let value = NoteValue::new(0x086a_a1ad_e61c_cb53);
        let plaintext = V3Plaintext::new(
            encode_master_public_key(
                receiver.master_public_key(),
                sender.master_public_key(),
                Some(&sender_random),
            )
            .unwrap_or_else(|error| panic!("encoded master public key should derive: {error}")),
            random,
            value,
            token_hash,
            sender_random,
            b"hidden-v3".to_vec(),
        );
        let (blinded_sender_viewing_key, blinded_receiver_viewing_key) =
            compute_blinded_keys(&sender, &receiver, &random, &sender_random);
        let expected_commitment = derive_note_commitment(
            &derive_note_public_key(receiver.master_public_key(), &random)
                .unwrap_or_else(|error| panic!("note public key should derive: {error}")),
            &token_hash,
            value,
        )
        .unwrap_or_else(|error| panic!("commitment should derive: {error}"));

        let reconstructed = reconstruct_v3_note(
            &plaintext,
            &receiver,
            &blinded_sender_viewing_key,
            &blinded_receiver_viewing_key,
            NotePerspective::Received,
            &expected_commitment,
        )
        .unwrap_or_else(|error| panic!("v3 received reconstruction should succeed: {error}"));

        assert_eq!(reconstructed.note().receiver(), &receiver);
        assert_eq!(reconstructed.note().sender(), None);
        assert_eq!(reconstructed.note().sender_random(), Some(&sender_random));
        assert_eq!(reconstructed.note().memo(), b"hidden-v3");
    }

    #[test]
    fn reconstructs_v3_sent_note_with_visible_sender() {
        let sender = note_party(
            "123456789",
            "67d7d19d00e6e3b3517fe68ac46505dd207df6e8fe3aa06ba3face352e7599ef",
        );
        let receiver = note_party(
            "20060431504059690749153982049210720252589378133547582826474262520121417617087",
            "3428cfc939320328501174a4e76e869197ffc894b58dbf4d0e953c484d66cb5e",
        );
        let random = NoteRandom::new(decode_hex("11111111111111111111111111111111"));
        let sender_random = SenderRandom::null_sentinel();
        let token_hash = TokenHash::new(decode_hex(
            "0000000000000000000000009fe46736679d2d9a65f0992f2272de9f3c7fa6e0",
        ));
        let value = NoteValue::new(1_000_000_u128);
        let plaintext = V3Plaintext::new(
            encode_master_public_key(
                receiver.master_public_key(),
                sender.master_public_key(),
                Some(&sender_random),
            )
            .unwrap_or_else(|error| panic!("encoded master public key should derive: {error}")),
            random,
            value,
            token_hash,
            sender_random,
            b"visible-v3".to_vec(),
        );
        let (blinded_sender_viewing_key, blinded_receiver_viewing_key) =
            compute_blinded_keys(&sender, &receiver, &random, &sender_random);
        let expected_commitment = derive_note_commitment(
            &derive_note_public_key(receiver.master_public_key(), &random)
                .unwrap_or_else(|error| panic!("note public key should derive: {error}")),
            &token_hash,
            value,
        )
        .unwrap_or_else(|error| panic!("commitment should derive: {error}"));

        let reconstructed = reconstruct_v3_note(
            &plaintext,
            &sender,
            &blinded_sender_viewing_key,
            &blinded_receiver_viewing_key,
            NotePerspective::Sent,
            &expected_commitment,
        )
        .unwrap_or_else(|error| panic!("v3 sent reconstruction should succeed: {error}"));

        assert_eq!(reconstructed.note().receiver(), &receiver);
        assert_eq!(reconstructed.note().sender(), Some(&sender));
        assert_eq!(reconstructed.note().sender_random(), Some(&sender_random));
        assert_eq!(reconstructed.note().memo(), b"visible-v3");
    }

    #[test]
    fn rejects_commitment_mismatch_during_reconstruction() {
        let sender = note_party(
            "123456789",
            "67d7d19d00e6e3b3517fe68ac46505dd207df6e8fe3aa06ba3face352e7599ef",
        );
        let receiver = note_party(
            "20060431504059690749153982049210720252589378133547582826474262520121417617087",
            "3428cfc939320328501174a4e76e869197ffc894b58dbf4d0e953c484d66cb5e",
        );
        let random = NoteRandom::new([5_u8; NoteRandom::LENGTH]);
        let sender_random = SenderRandom::null_sentinel();
        let token_hash = TokenHash::new([6_u8; TokenHash::LENGTH]);
        let value = NoteValue::new(7_u128);
        let plaintext = V3Plaintext::new(
            encode_master_public_key(
                receiver.master_public_key(),
                sender.master_public_key(),
                Some(&sender_random),
            )
            .unwrap_or_else(|error| panic!("encoded master public key should derive: {error}")),
            random,
            value,
            token_hash,
            sender_random,
            Vec::new(),
        );
        let (blinded_sender_viewing_key, blinded_receiver_viewing_key) =
            compute_blinded_keys(&sender, &receiver, &random, &sender_random);
        let wrong_commitment = NoteCommitment::new(BigUint::from(1_u8))
            .unwrap_or_else(|error| panic!("wrong commitment should validate: {error}"));

        let Err(error) = reconstruct_v3_note(
            &plaintext,
            &receiver,
            &blinded_sender_viewing_key,
            &blinded_receiver_viewing_key,
            NotePerspective::Received,
            &wrong_commitment,
        ) else {
            panic!("reconstruction with wrong commitment should fail");
        };

        assert_eq!(error, NoteReconstructionError::CommitmentMismatch);
    }

    #[test]
    fn rejects_master_public_key_outside_bn254_scalar_field() {
        let invalid_master_public_key = MasterPublicKey::new(BigUint::from_bytes_be(&[
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff,
        ]))
        .unwrap_or_else(|error| panic!("master public key should fit 32 bytes: {error}"));
        let random = NoteRandom::new([0_u8; NoteRandom::LENGTH]);

        let Err(error) = derive_note_public_key(&invalid_master_public_key, &random) else {
            panic!("invalid master public key should fail");
        };

        assert_eq!(error, KeyDerivationError::DerivationFailure);
    }
}
