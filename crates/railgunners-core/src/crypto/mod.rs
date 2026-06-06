pub(crate) mod babyjubjub;
pub(crate) mod poseidon;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CryptoError {
    InvalidFieldElement,
    InvalidSpendingPublicKey,
    InvalidPackedSpendingPublicKey,
    DerivationFailure,
}
