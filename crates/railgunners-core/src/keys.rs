//! Railgun spending and viewing keypair derivation.

use ark_ff::PrimeField;
use ed25519_dalek::SigningKey;
use num_bigint::BigUint;
use railgunners_types::{
    MasterPublicKey, NullifyingKey, SpendingKeyPair, SpendingPrivateKey, SpendingPublicKey,
    ViewingKeyPair, ViewingPrivateKey, ViewingPublicKey, WalletScanKeyBundle,
};

use crate::crypto::{CryptoError, babyjubjub, poseidon};
use crate::hd::{KeyDerivationError, WalletNode, derive_spending_and_viewing_nodes};

impl From<CryptoError> for KeyDerivationError {
    fn from(_: CryptoError) -> Self {
        Self::DerivationFailure
    }
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
    babyjubjub::derive_spending_public_key(private_key).map_err(Into::into)
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

/// Builds the canonical wallet scan-key bundle from the minimum required inputs.
///
/// The bundle keeps the caller-supplied master public key and derives the other
/// scan-time fields from the viewing private key so later scan code can operate
/// on one stable typed package.
///
/// # Errors
///
/// Returns an error if nullifying-key derivation fails unexpectedly.
pub fn build_wallet_scan_key_bundle(
    viewing_private_key: ViewingPrivateKey,
    master_public_key: MasterPublicKey,
) -> Result<WalletScanKeyBundle, KeyDerivationError> {
    let viewing_public_key = derive_viewing_public_key(&viewing_private_key);
    let nullifying_key = derive_nullifying_key(&viewing_private_key)?;

    Ok(WalletScanKeyBundle::new(
        viewing_private_key,
        viewing_public_key,
        nullifying_key,
        master_public_key,
    ))
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
    let input = poseidon::field_from_bytes_mod_order(private_key.as_bytes());
    let hash = poseidon::hash_fields(&[input])?;

    NullifyingKey::new(poseidon::field_to_biguint(hash))
        .map_err(|_| KeyDerivationError::DerivationFailure)
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

/// Derives a master public key from a spending public key and nullifying key.
///
/// Poseidon input ordering is exactly `[spending_public_key.x,
/// spending_public_key.y, nullifying_key]` over the BN254 scalar field.
///
/// # Errors
///
/// Returns an error if an input integer is not a valid BN254 field element or
/// if Poseidon hashing fails unexpectedly.
pub fn derive_master_public_key(
    spending_public_key: &SpendingPublicKey,
    nullifying_key: &NullifyingKey,
) -> Result<MasterPublicKey, KeyDerivationError> {
    babyjubjub::validate_spending_public_key(spending_public_key)?;
    master_public_key_from_canonical_inputs(
        spending_public_key.x(),
        spending_public_key.y(),
        nullifying_key.value(),
    )
}

/// Derives a master public key from canonical `BigUint` inputs that have already
/// been validated as BN254 field elements.
///
/// Unlike `derive_master_public_key`, this skips revalidating the spending
/// public key and skips the round-trip check inside `field_from_biguint`. It
/// is intended for the search fast path where inputs come from a freshly
/// derived spending public key and a freshly derived nullifying key.
pub(crate) fn master_public_key_from_canonical_inputs(
    spending_public_key_x: &BigUint,
    spending_public_key_y: &BigUint,
    nullifying_key: &BigUint,
) -> Result<MasterPublicKey, KeyDerivationError> {
    let x_field = ark_bn254::Fr::from_be_bytes_mod_order(&spending_public_key_x.to_bytes_be());
    let y_field = ark_bn254::Fr::from_be_bytes_mod_order(&spending_public_key_y.to_bytes_be());
    let n_field = ark_bn254::Fr::from_be_bytes_mod_order(&nullifying_key.to_bytes_be());
    let hash = poseidon::hash_fields(&[x_field, y_field, n_field])?;

    MasterPublicKey::new(poseidon::field_to_biguint(hash))
        .map_err(|_| KeyDerivationError::DerivationFailure)
}

/// Search-only key material sufficient to evaluate the fast stem prefix filter.
///
/// This intentionally omits the viewing public key because the address prefix
/// used by leading-zero and prefix searches depends only on the version byte,
/// the master public key, and the network identifier. Callers must derive the
/// viewing public key, the full address, and the packed spending public key
/// only after a candidate survives the fast stem filter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SearchCandidateKeys {
    index: u32,
    spending_private_key: SpendingPrivateKey,
    spending_public_key: SpendingPublicKey,
    viewing_private_key: ViewingPrivateKey,
    nullifying_key: NullifyingKey,
    master_public_key: MasterPublicKey,
}

impl SearchCandidateKeys {
    /// Returns the wallet index used for derivation.
    #[must_use]
    pub const fn index(&self) -> u32 {
        self.index
    }

    /// Returns the typed spending private key.
    #[must_use]
    pub const fn spending_private_key(&self) -> &SpendingPrivateKey {
        &self.spending_private_key
    }

    /// Returns the typed spending public key.
    #[must_use]
    pub const fn spending_public_key(&self) -> &SpendingPublicKey {
        &self.spending_public_key
    }

    /// Returns the typed viewing private key.
    #[must_use]
    pub const fn viewing_private_key(&self) -> &ViewingPrivateKey {
        &self.viewing_private_key
    }

    /// Returns the typed nullifying key.
    #[must_use]
    pub const fn nullifying_key(&self) -> &NullifyingKey {
        &self.nullifying_key
    }

    /// Returns the typed master public key.
    #[must_use]
    pub const fn master_public_key(&self) -> &MasterPublicKey {
        &self.master_public_key
    }
}

/// Derives the minimum key material required for search fast-stem filtering
/// from a canonical 64-byte BIP-39 seed.
///
/// This helper shares the master node HMAC across the spending and viewing
/// branches and intentionally omits the viewing public key. Callers that need
/// the full wallet output should call `derive_viewing_public_key` and finish
/// the full address encoding only after a candidate matches the fast filter.
///
/// # Errors
///
/// Returns an error if the seed is not 64 bytes long, if `wallet_index` is
/// invalid, or if any internal cryptographic primitive fails unexpectedly.
pub fn derive_search_keys_from_seed(
    seed: &[u8],
    wallet_index: u32,
) -> Result<SearchCandidateKeys, KeyDerivationError> {
    let (spending_node, viewing_node) = derive_spending_and_viewing_nodes(seed, wallet_index)?;
    let spending_private_key = spending_private_key_from_node(&spending_node);
    let viewing_private_key = viewing_private_key_from_node(&viewing_node);
    let spending_public_key = derive_spending_public_key(&spending_private_key)?;
    let nullifying_key = derive_nullifying_key(&viewing_private_key)?;
    let master_public_key = master_public_key_from_canonical_inputs(
        spending_public_key.x(),
        spending_public_key.y(),
        nullifying_key.value(),
    )?;

    Ok(SearchCandidateKeys {
        index: wallet_index,
        spending_private_key,
        spending_public_key,
        viewing_private_key,
        nullifying_key,
        master_public_key,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        build_wallet_scan_key_bundle, derive_master_public_key, derive_nullifying_key,
        derive_nullifying_key_from_bytes, derive_spending_key_pair, derive_spending_public_key,
        derive_spending_public_key_from_bytes, derive_viewing_key_pair,
        derive_viewing_public_key_from_bytes, spending_private_key_from_node,
        viewing_private_key_from_node,
    };
    use crate::hd::{KeyDerivationError, derive_node_from_str};
    use num_bigint::BigUint;
    use railgunners_types::{
        MasterPublicKey, NullifyingKey, SpendingPrivateKey, SpendingPublicKey, ViewingPrivateKey,
    };

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
    fn derives_master_public_key_from_issue_vector_one() {
        let spending_public_key = SpendingPublicKey::new(
            parse_decimal(
                "15684838006997671713939066069845237677934334329285343229142447933587909549584",
            ),
            parse_decimal(
                "11878614856120328179849762231924033298788609151532558727282528569229552954628",
            ),
        )
        .unwrap_or_else(|_| panic!("issue vector spending public key should validate"));
        let nullifying_key = NullifyingKey::new(parse_decimal(
            "8368299126798249740586535953124199418524409103803955764525436743456763691384",
        ))
        .unwrap_or_else(|_| panic!("issue vector nullifying key should validate"));
        let master_public_key = derive_master_public_key(&spending_public_key, &nullifying_key)
            .unwrap_or_else(|_| panic!("master public key derivation should succeed"));

        assert_eq!(
            master_public_key.value().to_string(),
            "20060431504059690749153982049210720252589378133547582826474262520121417617087"
        );
    }

    #[test]
    fn master_public_key_depends_on_input_material() {
        let spending_public_key = SpendingPublicKey::new(
            parse_decimal(
                "15684838006997671713939066069845237677934334329285343229142447933587909549584",
            ),
            parse_decimal(
                "11878614856120328179849762231924033298788609151532558727282528569229552954628",
            ),
        )
        .unwrap_or_else(|_| panic!("issue vector spending public key should validate"));
        let canonical_nullifying_key = NullifyingKey::new(parse_decimal(
            "8368299126798249740586535953124199418524409103803955764525436743456763691384",
        ))
        .unwrap_or_else(|_| panic!("issue vector nullifying key should validate"));
        let canonical = derive_master_public_key(&spending_public_key, &canonical_nullifying_key)
            .unwrap_or_else(|_| panic!("canonical master public key derivation should succeed"));

        let alternate_spending_public_key = derive_spending_public_key(&SpendingPrivateKey::new(
            hex_array::<32>("67d7d19d00e6e3b3517fe68ac46505dd207df6e8fe3aa06ba3face352e7599ef"),
        ))
        .unwrap_or_else(|_| panic!("alternate spending public key should derive"));
        let alternate =
            derive_master_public_key(&alternate_spending_public_key, &canonical_nullifying_key)
                .unwrap_or_else(|_| {
                    panic!("alternate master public key derivation should succeed")
                });

        assert_ne!(canonical, alternate);
    }

    #[test]
    fn derives_master_public_key_from_composed_key_material() {
        let spending_private_key = SpendingPrivateKey::new(hex_array::<32>(
            "67d7d19d00e6e3b3517fe68ac46505dd207df6e8fe3aa06ba3face352e7599ef",
        ));
        let viewing_private_key = ViewingPrivateKey::new(hex_array::<32>(
            "67d7d19d00e6e3b3517fe68ac46505dd207df6e8fe3aa06ba3face352e7599ef",
        ));
        let spending_public_key = derive_spending_public_key(&spending_private_key)
            .unwrap_or_else(|_| panic!("spending public key derivation should succeed"));
        let nullifying_key = derive_nullifying_key(&viewing_private_key)
            .unwrap_or_else(|_| panic!("nullifying key derivation should succeed"));
        let master_public_key = derive_master_public_key(&spending_public_key, &nullifying_key)
            .unwrap_or_else(|_| panic!("master public key derivation should succeed"));

        assert_eq!(
            master_public_key.value().to_string(),
            "15607618471549356314064749634364841401625982784343012680230632021308514635691"
        );
    }

    #[test]
    fn builds_wallet_scan_key_bundle_from_viewing_private_key_and_master_public_key() {
        let viewing_private_key = ViewingPrivateKey::new(hex_array::<32>(
            "67d7d19d00e6e3b3517fe68ac46505dd207df6e8fe3aa06ba3face352e7599ef",
        ));
        let master_public_key = MasterPublicKey::new(parse_decimal(
            "20060431504059690749153982049210720252589378133547582826474262520121417617087",
        ))
        .unwrap_or_else(|error| panic!("master public key should validate: {error}"));

        let bundle = build_wallet_scan_key_bundle(viewing_private_key, master_public_key.clone())
            .unwrap_or_else(|error| panic!("scan bundle should build: {error}"));

        assert_eq!(bundle.viewing_private_key(), &viewing_private_key);
        assert_eq!(
            bundle.viewing_public_key(),
            &derive_viewing_key_pair(viewing_private_key).public_key().to_owned()
        );
        assert_eq!(
            bundle.nullifying_key(),
            &derive_nullifying_key(&viewing_private_key)
                .unwrap_or_else(|error| panic!("nullifying key should derive: {error}"))
        );
        assert_eq!(bundle.master_public_key(), &master_public_key);
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

    fn parse_decimal(value: &str) -> BigUint {
        BigUint::parse_bytes(value.as_bytes(), 10)
            .unwrap_or_else(|| panic!("test decimal should be valid"))
    }
}
