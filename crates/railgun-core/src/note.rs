//! Canonical note public key, commitment, and nullifier derivation.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonHasher};
use num_bigint::BigUint;
use railgun_types::{
    LeafIndex, MasterPublicKey, NoteCommitment, NotePublicKey, NoteRandom, NoteValue, Nullifier,
    NullifyingKey, TokenHash,
};

use crate::hd::KeyDerivationError;

fn biguint_to_bn254_field(value: &BigUint) -> Result<Fr, KeyDerivationError> {
    let bytes = value.to_bytes_be();
    let field = Fr::from_be_bytes_mod_order(&bytes);
    let roundtrip = BigUint::from_bytes_be(&field.into_bigint().to_bytes_be());

    if roundtrip == *value { Ok(field) } else { Err(KeyDerivationError::DerivationFailure) }
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
        biguint_to_bn254_field(receiver_master_public_key.value())?,
        Fr::from_be_bytes_mod_order(random.as_bytes()),
    ];
    let mut poseidon =
        Poseidon::<Fr>::new_circom(2).map_err(|_| KeyDerivationError::DerivationFailure)?;
    let hash = poseidon.hash(&inputs).map_err(|_| KeyDerivationError::DerivationFailure)?;

    NotePublicKey::new(BigUint::from_bytes_be(&hash.into_bigint().to_bytes_be()))
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
        biguint_to_bn254_field(note_public_key.value())?,
        Fr::from_be_bytes_mod_order(token_hash.as_bytes()),
        Fr::from(value.get()),
    ];
    let mut poseidon =
        Poseidon::<Fr>::new_circom(3).map_err(|_| KeyDerivationError::DerivationFailure)?;
    let hash = poseidon.hash(&inputs).map_err(|_| KeyDerivationError::DerivationFailure)?;

    NoteCommitment::new(BigUint::from_bytes_be(&hash.into_bigint().to_bytes_be()))
        .map_err(|_| KeyDerivationError::DerivationFailure)
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
    let inputs = [biguint_to_bn254_field(nullifying_key.value())?, Fr::from(leaf_index.get())];
    let mut poseidon =
        Poseidon::<Fr>::new_circom(2).map_err(|_| KeyDerivationError::DerivationFailure)?;
    let hash = poseidon.hash(&inputs).map_err(|_| KeyDerivationError::DerivationFailure)?;

    Nullifier::new(BigUint::from_bytes_be(&hash.into_bigint().to_bytes_be()))
        .map_err(|_| KeyDerivationError::DerivationFailure)
}

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;
    use railgun_types::{
        LeafIndex, MasterPublicKey, NotePublicKey, NoteRandom, NoteValue, NullifyingKey, TokenHash,
    };

    use super::{derive_note_commitment, derive_note_public_key, derive_nullifier};
    use crate::{derive_nullifying_key_from_bytes, hd::KeyDerivationError};

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
            bytes[index] = ((high << 4) | low) as u8;
        }
        bytes
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
