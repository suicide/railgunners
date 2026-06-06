use railgunners_core::{
    Bip39Mnemonic, DerivationPath, KeyDerivationError, derive_master_public_key,
    derive_nullifying_key, derive_spending_public_key, derive_viewing_public_key, spending_path,
    spending_private_key_from_node, viewing_path, viewing_private_key_from_node,
};
use railgunners_types::{
    MasterPublicKey, NullifyingKey, PackedSpendingPublicKey, SpendingPrivateKey, SpendingPublicKey,
    ViewingPrivateKey, ViewingPublicKey,
};

/// Full canonical Railgun key material derived for a wallet index.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DerivedWalletKeys {
    index: u32,
    spending_path: DerivationPath,
    viewing_path: DerivationPath,
    spending_private_key: SpendingPrivateKey,
    spending_public_key: SpendingPublicKey,
    viewing_private_key: ViewingPrivateKey,
    viewing_public_key: ViewingPublicKey,
    nullifying_key: NullifyingKey,
    master_public_key: MasterPublicKey,
}

impl DerivedWalletKeys {
    #[must_use]
    pub(crate) const fn index(&self) -> u32 {
        self.index
    }
    #[must_use]
    pub(crate) const fn spending_path(&self) -> &DerivationPath {
        &self.spending_path
    }
    #[must_use]
    pub(crate) const fn viewing_path(&self) -> &DerivationPath {
        &self.viewing_path
    }
    #[must_use]
    pub(crate) const fn spending_private_key(&self) -> &SpendingPrivateKey {
        &self.spending_private_key
    }
    #[must_use]
    pub(crate) const fn spending_public_key(&self) -> &SpendingPublicKey {
        &self.spending_public_key
    }
    #[must_use]
    pub(crate) const fn viewing_private_key(&self) -> &ViewingPrivateKey {
        &self.viewing_private_key
    }
    #[must_use]
    pub(crate) const fn viewing_public_key(&self) -> &ViewingPublicKey {
        &self.viewing_public_key
    }
    #[must_use]
    pub(crate) const fn nullifying_key(&self) -> &NullifyingKey {
        &self.nullifying_key
    }
    #[must_use]
    pub(crate) const fn master_public_key(&self) -> &MasterPublicKey {
        &self.master_public_key
    }
}

/// Derived values inspectable from a viewing private key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ViewingKeyInspection {
    viewing_public_key: ViewingPublicKey,
    nullifying_key: NullifyingKey,
}

impl ViewingKeyInspection {
    #[must_use]
    pub(crate) const fn new(
        viewing_public_key: ViewingPublicKey,
        nullifying_key: NullifyingKey,
    ) -> Self {
        Self { viewing_public_key, nullifying_key }
    }
    #[must_use]
    pub(crate) const fn viewing_public_key(&self) -> &ViewingPublicKey {
        &self.viewing_public_key
    }
    #[must_use]
    pub(crate) const fn nullifying_key(&self) -> &NullifyingKey {
        &self.nullifying_key
    }
}

pub(crate) fn derive_wallet_keys(
    mnemonic: &Bip39Mnemonic,
    wallet_index: u32,
) -> Result<DerivedWalletKeys, KeyDerivationError> {
    let seed = mnemonic.seed(None);
    derive_wallet_keys_from_seed(&seed, wallet_index)
}

pub(crate) fn derive_wallet_keys_from_seed(
    seed: &[u8],
    wallet_index: u32,
) -> Result<DerivedWalletKeys, KeyDerivationError> {
    let spending_path = spending_path(wallet_index)?;
    let viewing_path = viewing_path(wallet_index)?;
    let spending_node = railgunners_core::derive_spending_node(seed, wallet_index)?;
    let viewing_node = railgunners_core::derive_viewing_node(seed, wallet_index)?;
    let spending_private_key = spending_private_key_from_node(&spending_node);
    let viewing_private_key = viewing_private_key_from_node(&viewing_node);
    let spending_public_key = derive_spending_public_key(&spending_private_key)?;
    let viewing_public_key = derive_viewing_public_key(&viewing_private_key);
    let nullifying_key = derive_nullifying_key(&viewing_private_key)?;
    let master_public_key = derive_master_public_key(&spending_public_key, &nullifying_key)?;

    Ok(DerivedWalletKeys {
        index: wallet_index,
        spending_path,
        viewing_path,
        spending_private_key,
        spending_public_key,
        viewing_private_key,
        viewing_public_key,
        nullifying_key,
        master_public_key,
    })
}

pub(crate) fn inspect_viewing_private_key(
    private_key: &ViewingPrivateKey,
) -> Result<ViewingKeyInspection, KeyDerivationError> {
    let viewing_public_key = derive_viewing_public_key(private_key);
    let nullifying_key = derive_nullifying_key(private_key)?;
    Ok(ViewingKeyInspection::new(viewing_public_key, nullifying_key))
}

pub(crate) fn inspect_spending_private_key(
    private_key: &SpendingPrivateKey,
) -> Result<SpendingPublicKey, KeyDerivationError> {
    derive_spending_public_key(private_key)
}

pub(crate) fn inspect_master_public_key(
    spending_public_key: &SpendingPublicKey,
    nullifying_key: &NullifyingKey,
) -> Result<MasterPublicKey, KeyDerivationError> {
    derive_master_public_key(spending_public_key, nullifying_key)
}

pub(crate) fn pack_derived_spending_public_key(
    spending_public_key: &SpendingPublicKey,
) -> Result<PackedSpendingPublicKey, railgunners_core::ShareableViewingKeyError> {
    railgunners_core::pack_spending_public_key(spending_public_key)
}
