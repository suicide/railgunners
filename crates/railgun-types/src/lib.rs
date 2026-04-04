//! Shared domain types for the RAILGUN workspace.

mod address;
mod error;
mod field;
mod keys;
mod note;
mod token;

pub use address::{
    ChainScope, ChainType, NetworkId, RailgunAddress, RailgunAddressData, RailgunChain,
};
pub use error::ParseDomainError;
pub(crate) use field::validate_bn254_scalar;
pub use field::{BN254_SCALAR_FIELD_MODULUS_BYTES, bn254_scalar_field_modulus};
pub use keys::{
    BlindedViewingPublicKey, MasterPublicKey, NullifyingKey, PackedSpendingPublicKey,
    ShareableViewingKeyData, SharedSymmetricKey, SpendingKeyPair, SpendingPrivateKey,
    SpendingPublicKey, ViewingKeyPair, ViewingPrivateKey, ViewingPublicKey,
};
pub use note::{
    LeafIndex, MEMO_SENDER_RANDOM_NULL_BYTES, NoteCommitment, NotePublicKey, NoteRandom, NoteValue,
    Nullifier, SenderRandom, SenderVisibility, SharedRandom,
};
pub use token::{Address, ChainId, TokenData, TokenHash, TokenSubId, TokenType, TxHash};
