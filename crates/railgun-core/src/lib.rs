//! Shared protocol traits and errors for the RAILGUN workspace.

pub mod address;
pub mod bip39;
pub mod blinding;
pub mod ciphertext_v2;
pub mod hd;
pub mod keys;
pub mod network_id;
pub mod note;
pub mod shareable_viewing_key;
pub mod shared_key;
pub mod token;

use railgun_types::{Address, ChainId, TxHash};

pub use address::{
    AddressDecodingError, AddressEncodingError, decode_railgun_address, encode_railgun_address,
};
pub use bip39::{Bip39Error, Bip39Mnemonic, Bip39WordCount};
pub use blinding::{BlindingError, derive_note_blinding_keys, unblind_note_key};
pub use ciphertext_v2::{
    V2CiphertextError, decode_v2_plaintext, decrypt_v2_ciphertext, encode_v2_plaintext,
    encrypt_v2_ciphertext,
};
pub use hd::{
    DerivationPath, HardenedIndex, KeyDerivationError, WalletNode, derive_master_node, derive_node,
    derive_node_from_str, derive_spending_node, derive_viewing_node, spending_path, viewing_path,
};
pub use keys::{
    derive_master_public_key, derive_nullifying_key, derive_nullifying_key_from_bytes,
    derive_spending_key_pair, derive_spending_public_key, derive_spending_public_key_from_bytes,
    derive_viewing_key_pair, derive_viewing_public_key, derive_viewing_public_key_from_bytes,
    spending_private_key_from_node, viewing_private_key_from_node,
};
pub use network_id::{NetworkIdError, decode_network_id, encode_network_id};
pub use note::{
    derive_note_commitment, derive_note_public_key, derive_nullifier, encode_master_public_key,
    sender_visibility,
};
pub use shareable_viewing_key::{
    ShareableViewingKeyError, decode_shareable_viewing_key, encode_shareable_viewing_key,
    pack_spending_public_key, unpack_spending_public_key,
};
pub use shared_key::{
    SharedKeyError, derive_shared_symmetric_key, derive_shared_symmetric_key_from_bytes,
};
pub use token::{CanonicalTokenData, derive_token_hash, encode_token_data};

/// Result alias used across foundational crates.
pub type Result<T, E = RailgunError> = core::result::Result<T, E>;

/// Common SDK error scaffold used by early crates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RailgunError {
    /// Invalid external input reached the domain boundary.
    InvalidInput(&'static str),
    /// A feature is intentionally not implemented in the current environment.
    Unsupported(&'static str),
    /// An external system failed without a richer typed error.
    External(&'static str),
}

impl core::fmt::Display for RailgunError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidInput(message) | Self::Unsupported(message) | Self::External(message) => {
                formatter.write_str(message)
            }
        }
    }
}

impl std::error::Error for RailgunError {}

/// Shared crate metadata exposed across surfaces.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SdkInfo {
    /// Workspace crate name.
    pub name: &'static str,
    /// Workspace crate version.
    pub version: &'static str,
}

/// Capability for reading chain information and submitting transactions.
pub trait ChainProvider {
    /// Provider-specific error type.
    type Error;

    /// Returns the active chain identifier.
    ///
    /// # Errors
    ///
    /// Returns any error produced by the underlying provider.
    fn chain_id(&self) -> core::result::Result<ChainId, Self::Error>;

    /// Sends a serialized transaction payload.
    ///
    /// # Errors
    ///
    /// Returns any error produced while submitting the transaction.
    fn send_transaction(&self, payload: &[u8]) -> core::result::Result<TxHash, Self::Error>;
}

/// Capability for signing wallet-controlled messages.
pub trait Signer {
    /// Signer-specific error type.
    type Error;

    /// Returns the controlling address for the signer.
    fn address(&self) -> Address;

    /// Signs an arbitrary message.
    ///
    /// # Errors
    ///
    /// Returns any error produced by the signer implementation.
    fn sign_message(&self, message: &[u8]) -> core::result::Result<Vec<u8>, Self::Error>;
}

/// Capability for storing and loading opaque wallet state.
pub trait WalletStore {
    /// Store-specific error type.
    type Error;

    /// Persists bytes under a namespaced key.
    ///
    /// # Errors
    ///
    /// Returns any error produced while writing to the store.
    fn put(&mut self, key: &str, value: &[u8]) -> core::result::Result<(), Self::Error>;

    /// Loads bytes previously stored for a key.
    ///
    /// # Errors
    ///
    /// Returns any error produced while reading from the store.
    fn get(&self, key: &str) -> core::result::Result<Option<Vec<u8>>, Self::Error>;
}

/// Returns a shared workspace identity value.
#[must_use]
pub const fn sdk_info() -> SdkInfo {
    SdkInfo { name: "railguncli", version: env!("CARGO_PKG_VERSION") }
}
