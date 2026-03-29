use core::fmt;

use railgun_core::{
    AddressEncodingError, decode_shareable_viewing_key, derive_master_public_key,
    derive_nullifying_key, derive_viewing_public_key, encode_railgun_address,
    unpack_spending_public_key,
};
use railgun_types::{
    ChainScope, RailgunAddress, ShareableViewingKeyData, SpendingPublicKey, ViewingPublicKey,
};

/// Fully inspected shareable viewing key data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ShareableViewingKeyInspection {
    payload: ShareableViewingKeyData,
    spending_public_key: SpendingPublicKey,
    viewing_public_key: ViewingPublicKey,
    nullifying_key: railgun_types::NullifyingKey,
    master_public_key: railgun_types::MasterPublicKey,
    address: RailgunAddress,
}

impl ShareableViewingKeyInspection {
    #[must_use]
    pub(crate) const fn new(
        payload: ShareableViewingKeyData,
        spending_public_key: SpendingPublicKey,
        viewing_public_key: ViewingPublicKey,
        nullifying_key: railgun_types::NullifyingKey,
        master_public_key: railgun_types::MasterPublicKey,
        address: RailgunAddress,
    ) -> Self {
        Self {
            payload,
            spending_public_key,
            viewing_public_key,
            nullifying_key,
            master_public_key,
            address,
        }
    }

    #[must_use]
    pub(crate) const fn payload(&self) -> &ShareableViewingKeyData {
        &self.payload
    }
    #[must_use]
    pub(crate) const fn spending_public_key(&self) -> &SpendingPublicKey {
        &self.spending_public_key
    }
    #[must_use]
    pub(crate) const fn viewing_public_key(&self) -> &ViewingPublicKey {
        &self.viewing_public_key
    }
    #[must_use]
    pub(crate) const fn nullifying_key(&self) -> &railgun_types::NullifyingKey {
        &self.nullifying_key
    }
    #[must_use]
    pub(crate) const fn master_public_key(&self) -> &railgun_types::MasterPublicKey {
        &self.master_public_key
    }
    #[must_use]
    pub(crate) const fn address(&self) -> &RailgunAddress {
        &self.address
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ShareableViewingKeyInspectionError {
    ShareableViewingKey(railgun_core::ShareableViewingKeyError),
    KeyDerivation,
    AddressEncoding(AddressEncodingError),
}

impl fmt::Display for ShareableViewingKeyInspectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShareableViewingKey(error) => write!(formatter, "{error}"),
            Self::KeyDerivation => formatter.write_str("failed to derive view-only key material"),
            Self::AddressEncoding(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for ShareableViewingKeyInspectionError {}

impl From<railgun_core::ShareableViewingKeyError> for ShareableViewingKeyInspectionError {
    fn from(value: railgun_core::ShareableViewingKeyError) -> Self {
        Self::ShareableViewingKey(value)
    }
}

impl From<AddressEncodingError> for ShareableViewingKeyInspectionError {
    fn from(value: AddressEncodingError) -> Self {
        Self::AddressEncoding(value)
    }
}

pub(crate) fn inspect_shareable_viewing_key(
    payload: &str,
    chain_scope: ChainScope,
) -> Result<ShareableViewingKeyInspection, ShareableViewingKeyInspectionError> {
    let payload = decode_shareable_viewing_key(payload)?;
    let spending_public_key = unpack_spending_public_key(payload.packed_spending_public_key())?;
    let viewing_public_key = derive_viewing_public_key(payload.viewing_private_key());
    let nullifying_key = derive_nullifying_key(payload.viewing_private_key())
        .map_err(|_| ShareableViewingKeyInspectionError::KeyDerivation)?;
    let master_public_key = derive_master_public_key(&spending_public_key, &nullifying_key)
        .map_err(|_| ShareableViewingKeyInspectionError::KeyDerivation)?;
    let address = encode_railgun_address(1, &master_public_key, chain_scope, &viewing_public_key)?;

    Ok(ShareableViewingKeyInspection::new(
        payload,
        spending_public_key,
        viewing_public_key,
        nullifying_key,
        master_public_key,
        address,
    ))
}
