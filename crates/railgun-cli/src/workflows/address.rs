use railgun_core::{
    AddressDecodingError, AddressEncodingError, decode_railgun_address, encode_network_id,
    encode_railgun_address,
};
use railgun_types::{ChainScope, MasterPublicKey, RailgunAddress, ViewingPublicKey};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DecodedAddress {
    version: u8,
    master_public_key: MasterPublicKey,
    network_id_hex: String,
    viewing_public_key: ViewingPublicKey,
    chain_scope: ChainScope,
}

impl DecodedAddress {
    #[must_use]
    pub(crate) const fn new(
        version: u8,
        master_public_key: MasterPublicKey,
        network_id_hex: String,
        viewing_public_key: ViewingPublicKey,
        chain_scope: ChainScope,
    ) -> Self {
        Self { version, master_public_key, network_id_hex, viewing_public_key, chain_scope }
    }

    #[must_use]
    pub(crate) const fn version(&self) -> u8 {
        self.version
    }
    #[must_use]
    pub(crate) const fn master_public_key(&self) -> &MasterPublicKey {
        &self.master_public_key
    }
    #[must_use]
    pub(crate) fn network_id_hex(&self) -> &str {
        &self.network_id_hex
    }
    #[must_use]
    pub(crate) const fn viewing_public_key(&self) -> &ViewingPublicKey {
        &self.viewing_public_key
    }
    #[must_use]
    pub(crate) const fn chain_scope(&self) -> ChainScope {
        self.chain_scope
    }
}

pub(crate) fn encode_address(
    version: u8,
    master_public_key: &MasterPublicKey,
    chain_scope: ChainScope,
    viewing_public_key: &ViewingPublicKey,
) -> Result<RailgunAddress, AddressEncodingError> {
    encode_railgun_address(version, master_public_key, chain_scope, viewing_public_key)
}

pub(crate) fn decode_address(address: &str) -> Result<DecodedAddress, AddressDecodingError> {
    let decoded = decode_railgun_address(address)?;
    let network_id = encode_network_id(decoded.chain_scope())
        .map_err(|_| AddressDecodingError::InvalidNetworkId)?;

    Ok(DecodedAddress::new(
        decoded.version(),
        decoded.master_public_key().clone(),
        hex::encode(network_id.as_bytes()),
        *decoded.viewing_public_key(),
        decoded.chain_scope(),
    ))
}

pub(crate) fn validate_address(address: &str) -> Result<DecodedAddress, AddressDecodingError> {
    decode_address(address)
}
