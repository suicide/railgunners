//! Shared protocol traits and errors for the RAILGUN workspace.

use railgun_types::{Address, ChainId, TxHash};

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
    SdkInfo { name: "railgun-rs", version: env!("CARGO_PKG_VERSION") }
}
