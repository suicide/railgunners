//! Shared domain types for the RAILGUN workspace.

mod address;
mod ciphertext_v2;
mod ciphertext_v3;
mod commitment_ciphertext;
mod error;
mod field;
mod keys;
mod note;
mod position;
mod shield_ciphertext;
mod token;

pub use address::{
    ChainScope, ChainType, NetworkId, RailgunAddress, RailgunAddressData, RailgunChain,
};
pub use ciphertext_v2::{V2CiphertextBlock, V2CiphertextBundle, V2Plaintext};
pub use ciphertext_v3::{V3CiphertextBundle, V3Plaintext, V3StoredNonce};
pub use commitment_ciphertext::{
    CommitmentCiphertextV2, CommitmentCiphertextV3, VersionedCommitmentCiphertext,
};
pub use error::ParseDomainError;
pub(crate) use field::validate_bn254_scalar;
pub use field::{BN254_SCALAR_FIELD_MODULUS_BYTES, bn254_scalar_field_modulus};
pub use keys::{
    BlindedViewingPublicKey, MasterPublicKey, NullifyingKey, PackedSpendingPublicKey,
    ShareableViewingKeyData, SharedSymmetricKey, SpendingKeyPair, SpendingPrivateKey,
    SpendingPublicKey, ViewingKeyPair, ViewingPrivateKey, ViewingPublicKey, WalletScanKeyBundle,
};
pub use note::{
    EmittedNullifier, LeafIndex, MEMO_SENDER_RANDOM_NULL_BYTES, Note, NoteCommitment, NoteParty,
    NotePerspective, NotePublicKey, NoteRandom, NoteSpentState, NoteValue, Nullifier,
    ReconstructedNote, SenderRandom, SenderRecovery, SenderVisibility, SharedRandom,
    TrackedNoteNullifier, WalletNoteOwnership,
};
pub use position::{
    CommitmentLeafPosition, GLOBAL_UTXO_POSITION_PRE_TRANSACTION_POI_PROOF_HARDCODED_VALUE,
    GLOBAL_UTXO_POSITION_UNSHIELD_EVENT_HARDCODED_VALUE,
    GLOBAL_UTXO_TREE_PRE_TRANSACTION_POI_PROOF_HARDCODED_VALUE,
    GLOBAL_UTXO_TREE_UNSHIELD_EVENT_HARDCODED_VALUE, GlobalTreePosition, TREE_MAX_ITEMS,
    UtxoLeafCoordinate, UtxoTreeCoordinate,
};
pub use shield_ciphertext::{ShieldCiphertext, ShieldCiphertextBlock};
pub use token::{Address, ChainId, TokenData, TokenHash, TokenSubId, TokenType, TxHash};
