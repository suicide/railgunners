//! Railgun spending and viewing keypair derivation.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use babyjubjub_rs::Fr as BabyJubJubField;
use babyjubjub_rs::PrivateKey as BabyJubJubPrivateKey;
use ed25519_dalek::SigningKey;
use ff::{PrimeField as _, PrimeFieldRepr as _};
use light_poseidon::{Poseidon, PoseidonHasher};
use num_bigint::BigUint;
use railgun_types::{
    NullifyingKey, SpendingKeyPair, SpendingPrivateKey, SpendingPublicKey, ViewingKeyPair,
    ViewingPrivateKey, ViewingPublicKey,
};

use crate::hd::{KeyDerivationError, WalletNode};

// This module currently touches two different field-element types that both use
// the conventional `Fr` name:
// - `ark_bn254::Fr` is the BN254 scalar field used by `light-poseidon`.
// - `babyjubjub_rs::Fr` is the BabyJubJub field type used for public-key
//   coordinates returned by `babyjubjub-rs`.
//
// They come from different libraries and trait ecosystems, so we alias the
// BabyJubJub one and import both trait sets explicitly.
fn parse_coordinate(value: &BabyJubJubField) -> Result<BigUint, KeyDerivationError> {
    let repr = value.into_repr();
    let mut bytes = Vec::with_capacity(core::mem::size_of_val(repr.as_ref()));
    repr.write_be(&mut bytes).map_err(|_| KeyDerivationError::DerivationFailure)?;
    Ok(BigUint::from_bytes_be(&bytes))
}

/// Converts a wallet node into a typed spending private key.
#[must_use]
pub fn spending_private_key_from_node(node: &WalletNode) -> SpendingPrivateKey {
    SpendingPrivateKey::new(*node.chain_key())
}

/// Converts a wallet node into a typed viewing private key.
#[must_use]
pub fn viewing_private_key_from_node(node: &WalletNode) -> ViewingPrivateKey {
    ViewingPrivateKey::new(*node.chain_key())
}

/// Derives a spending public key from a typed 32-byte spending private key.
///
/// # Errors
///
/// Returns an error if the underlying `BabyJubJub` implementation rejects the
/// key or if key derivation fails unexpectedly.
pub fn derive_spending_public_key(
    private_key: &SpendingPrivateKey,
) -> Result<SpendingPublicKey, KeyDerivationError> {
    let private_key = BabyJubJubPrivateKey::import(private_key.as_bytes().to_vec())
        .map_err(|_| KeyDerivationError::DerivationFailure)?;
    let public_key = private_key.public();
    let x = parse_coordinate(&public_key.x)?;
    let y = parse_coordinate(&public_key.y)?;
    Ok(SpendingPublicKey::new(x, y))
}

/// Derives a spending public key from raw private-key bytes.
///
/// # Errors
///
/// Returns an error if `private_key` is not exactly 32 bytes long or if the
/// underlying `BabyJubJub` derivation fails.
pub fn derive_spending_public_key_from_bytes(
    private_key: &[u8],
) -> Result<SpendingPublicKey, KeyDerivationError> {
    let private_key: [u8; SpendingPrivateKey::LENGTH] = private_key
        .try_into()
        .map_err(|_| KeyDerivationError::InvalidPrivateKeyLength(private_key.len()))?;
    derive_spending_public_key(&SpendingPrivateKey::new(private_key))
}

/// Derives a typed spending keypair from a 32-byte spending private key.
///
/// # Errors
///
/// Returns an error if public-key derivation fails unexpectedly.
pub fn derive_spending_key_pair(
    private_key: SpendingPrivateKey,
) -> Result<SpendingKeyPair, KeyDerivationError> {
    let public_key = derive_spending_public_key(&private_key)?;
    Ok(SpendingKeyPair::new(private_key, public_key))
}

/// Derives a viewing public key from a typed 32-byte viewing private key.
#[must_use]
pub fn derive_viewing_public_key(private_key: &ViewingPrivateKey) -> ViewingPublicKey {
    let signing_key = SigningKey::from_bytes(private_key.as_bytes());
    ViewingPublicKey::new(signing_key.verifying_key().to_bytes())
}

/// Derives a viewing public key from raw private-key bytes.
///
/// # Errors
///
/// Returns an error if `private_key` is not exactly 32 bytes long.
pub fn derive_viewing_public_key_from_bytes(
    private_key: &[u8],
) -> Result<ViewingPublicKey, KeyDerivationError> {
    let private_key: [u8; ViewingPrivateKey::LENGTH] = private_key
        .try_into()
        .map_err(|_| KeyDerivationError::InvalidPrivateKeyLength(private_key.len()))?;
    Ok(derive_viewing_public_key(&ViewingPrivateKey::new(private_key)))
}

/// Derives a typed viewing keypair from a 32-byte viewing private key.
#[must_use]
pub fn derive_viewing_key_pair(private_key: ViewingPrivateKey) -> ViewingKeyPair {
    let public_key = derive_viewing_public_key(&private_key);
    ViewingKeyPair::new(private_key, public_key)
}

/// Derives a nullifying key from a typed 32-byte viewing private key.
///
/// The viewing private key bytes are interpreted as a big-endian integer before
/// hashing with Poseidon over the BN254 scalar field.
///
/// # Errors
///
/// Returns an error if Poseidon hashing fails unexpectedly.
pub fn derive_nullifying_key(
    private_key: &ViewingPrivateKey,
) -> Result<NullifyingKey, KeyDerivationError> {
    let input = Fr::from_be_bytes_mod_order(private_key.as_bytes());
    let mut poseidon =
        Poseidon::<Fr>::new_circom(1).map_err(|_| KeyDerivationError::DerivationFailure)?;
    let hash = poseidon.hash(&[input]).map_err(|_| KeyDerivationError::DerivationFailure)?;
    let bytes = hash.into_bigint().to_bytes_be();

    Ok(NullifyingKey::new(BigUint::from_bytes_be(&bytes)))
}

/// Derives a nullifying key from raw viewing-private-key bytes.
///
/// # Errors
///
/// Returns an error if `private_key` is not exactly 32 bytes long or if
/// Poseidon hashing fails unexpectedly.
pub fn derive_nullifying_key_from_bytes(
    private_key: &[u8],
) -> Result<NullifyingKey, KeyDerivationError> {
    let private_key: [u8; ViewingPrivateKey::LENGTH] = private_key
        .try_into()
        .map_err(|_| KeyDerivationError::InvalidPrivateKeyLength(private_key.len()))?;
    derive_nullifying_key(&ViewingPrivateKey::new(private_key))
}

#[cfg(test)]
mod tests {
    use super::{
        derive_nullifying_key, derive_nullifying_key_from_bytes, derive_spending_key_pair,
        derive_spending_public_key_from_bytes, derive_viewing_key_pair,
        derive_viewing_public_key_from_bytes, spending_private_key_from_node,
        viewing_private_key_from_node,
    };
    use crate::hd::{KeyDerivationError, derive_node_from_str};
    use railgun_types::{SpendingPrivateKey, ViewingPrivateKey};

    #[test]
    fn derives_spending_keypair_from_issue_vector_one() {
        let private_key =
            hex_array::<32>("67d7d19d00e6e3b3517fe68ac46505dd207df6e8fe3aa06ba3face352e7599ef");
        let pair = derive_spending_key_pair(SpendingPrivateKey::new(private_key))
            .unwrap_or_else(|_| panic!("spending derivation should succeed"));

        assert_eq!(
            pair.public_key().x().to_string(),
            "1700559105542139805112168139351320601853033442476682590258553412078471731431"
        );
        assert_eq!(
            pair.public_key().y().to_string(),
            "20772987336827599306927277921643441679141423747083423413320022373456048866305"
        );
    }

    #[test]
    fn derives_viewing_keypair_from_issue_vector_one() {
        let private_key =
            hex_array::<32>("67d7d19d00e6e3b3517fe68ac46505dd207df6e8fe3aa06ba3face352e7599ef");
        let pair = derive_viewing_key_pair(ViewingPrivateKey::new(private_key));

        assert_eq!(
            hex_encode(pair.public_key().as_bytes()),
            "0debf77d8e9436fc07a0dc3fe8bd90c2f592a08cab8dbe5f972a4783465cd6d4"
        );
    }

    #[test]
    fn derives_spending_keypair_from_issue_vector_two() {
        let private_key =
            hex_array::<32>("3428cfc939320328501174a4e76e869197ffc894b58dbf4d0e953c484d66cb5e");
        let pair = derive_spending_key_pair(SpendingPrivateKey::new(private_key))
            .unwrap_or_else(|_| panic!("spending derivation should succeed"));

        assert_eq!(
            pair.public_key().x().to_string(),
            "16684668252477829187059584092631702151145377657154285130424212860540363370357"
        );
        assert_eq!(
            pair.public_key().y().to_string(),
            "12981690610069374219327647242965768905998412239681315744257339323456415609107"
        );
    }

    #[test]
    fn derives_viewing_keypair_from_issue_vector_two() {
        let private_key =
            hex_array::<32>("3428cfc939320328501174a4e76e869197ffc894b58dbf4d0e953c484d66cb5e");
        let pair = derive_viewing_key_pair(ViewingPrivateKey::new(private_key));

        assert_eq!(
            hex_encode(pair.public_key().as_bytes()),
            "bc0a8514361c5227817636c0698f1eb7d94d52f07acb58e06bf1db919fe64514"
        );
    }

    #[test]
    fn rejects_invalid_spending_private_key_length() {
        let Err(error) = derive_spending_public_key_from_bytes(&[7_u8; 31]) else {
            panic!("invalid spending private key length should fail");
        };
        assert_eq!(error, KeyDerivationError::InvalidPrivateKeyLength(31));
    }

    #[test]
    fn rejects_invalid_viewing_private_key_length() {
        let Err(error) = derive_viewing_public_key_from_bytes(&[7_u8; 33]) else {
            panic!("invalid viewing private key length should fail");
        };
        assert_eq!(error, KeyDerivationError::InvalidPrivateKeyLength(33));
    }

    #[test]
    fn derives_nullifying_key_from_issue_vector_one() {
        let private_key =
            hex_array::<32>("67d7d19d00e6e3b3517fe68ac46505dd207df6e8fe3aa06ba3face352e7599ef");
        let nullifying_key = derive_nullifying_key(&ViewingPrivateKey::new(private_key))
            .unwrap_or_else(|_| panic!("nullifying key derivation should succeed"));

        assert_eq!(
            nullifying_key.value().to_string(),
            "12835268173099116305231859677177501123414588269721547120001227054861606950622"
        );
    }

    #[test]
    fn derives_nullifying_key_from_issue_vector_two() {
        let private_key =
            hex_array::<32>("3428cfc939320328501174a4e76e869197ffc894b58dbf4d0e953c484d66cb5e");
        let nullifying_key = derive_nullifying_key(&ViewingPrivateKey::new(private_key))
            .unwrap_or_else(|_| panic!("nullifying key derivation should succeed"));

        assert_eq!(
            nullifying_key.value().to_string(),
            "12433581129726328896745774227574786958991377531034322249715552469191536529193"
        );
    }

    #[test]
    fn rejects_invalid_nullifying_private_key_length() {
        let Err(error) = derive_nullifying_key_from_bytes(&[7_u8; 31]) else {
            panic!("invalid nullifying private key length should fail");
        };
        assert_eq!(error, KeyDerivationError::InvalidPrivateKeyLength(31));
    }

    #[test]
    fn derives_keypairs_from_issue_child_node() {
        let seed = hex_decode(
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
        );

        let node = derive_node_from_str(&seed, "m/0'")
            .unwrap_or_else(|_| panic!("issue child node derivation should succeed"));

        let spending_pair = derive_spending_key_pair(spending_private_key_from_node(&node))
            .unwrap_or_else(|_| panic!("spending keypair derivation should succeed"));
        let viewing_pair = derive_viewing_key_pair(viewing_private_key_from_node(&node));

        assert_eq!(
            spending_pair.public_key().x().to_string(),
            "1700559105542139805112168139351320601853033442476682590258553412078471731431"
        );
        assert_eq!(
            spending_pair.public_key().y().to_string(),
            "20772987336827599306927277921643441679141423747083423413320022373456048866305"
        );
        assert_eq!(
            hex_encode(viewing_pair.public_key().as_bytes()),
            "0debf77d8e9436fc07a0dc3fe8bd90c2f592a08cab8dbe5f972a4783465cd6d4"
        );
    }

    fn hex_array<const N: usize>(value: &str) -> [u8; N] {
        let bytes = hex_decode(value);
        let mut array = [0_u8; N];
        array.copy_from_slice(&bytes);
        array
    }

    fn hex_decode(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0, "hex input must be even-length");
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|chunk| {
                let text = core::str::from_utf8(chunk)
                    .unwrap_or_else(|_| panic!("test hex should be utf-8"));
                u8::from_str_radix(text, 16).unwrap_or_else(|_| panic!("test hex should be valid"))
            })
            .collect()
    }

    fn hex_encode(bytes: &[u8]) -> String {
        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            use core::fmt::Write as _;
            let result = write!(&mut encoded, "{byte:02x}");
            assert!(result.is_ok(), "writing to a string should succeed");
        }
        encoded
    }
}
