//! Canonical note public key derivation.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonHasher};
use num_bigint::BigUint;
use railgun_types::{MasterPublicKey, NotePublicKey, NoteRandom};

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

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;
    use railgun_types::{MasterPublicKey, NoteRandom};

    use super::derive_note_public_key;
    use crate::hd::KeyDerivationError;

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
