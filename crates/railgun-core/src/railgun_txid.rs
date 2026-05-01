//! Canonical Railgun transaction ID derivation.

use num_bigint::BigUint;
use railgun_types::{
    BoundParamsHash, NoteCommitment, Nullifier, RAILGUN_TXID_INPUTS_LENGTH, RailgunTxid,
};

use crate::crypto::poseidon;

/// Error returned when Railgun txid derivation inputs are malformed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RailgunTxidError {
    /// More than the canonical 13 nullifier slots were provided.
    TooManyNullifiers,
    /// More than the canonical 13 commitment slots were provided.
    TooManyCommitments,
    /// The bound-params hash bytes do not encode a canonical BN254 field element.
    InvalidBoundParamsHash,
    /// Poseidon hashing failed unexpectedly.
    HashingFailure,
}

impl core::fmt::Display for RailgunTxidError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooManyNullifiers => {
                formatter.write_str("railgun txid supports at most 13 nullifiers")
            }
            Self::TooManyCommitments => {
                formatter.write_str("railgun txid supports at most 13 commitments")
            }
            Self::InvalidBoundParamsHash => formatter.write_str("invalid bound params hash"),
            Self::HashingFailure => formatter.write_str("failed to derive railgun txid"),
        }
    }
}

impl std::error::Error for RailgunTxidError {}

fn nullifier_values(nullifiers: &[Nullifier]) -> Result<Vec<BigUint>, RailgunTxidError> {
    if nullifiers.len() > RAILGUN_TXID_INPUTS_LENGTH {
        return Err(RailgunTxidError::TooManyNullifiers);
    }

    Ok(nullifiers.iter().map(|nullifier| nullifier.value().clone()).collect())
}

fn commitment_values(commitments: &[NoteCommitment]) -> Result<Vec<BigUint>, RailgunTxidError> {
    if commitments.len() > RAILGUN_TXID_INPUTS_LENGTH {
        return Err(RailgunTxidError::TooManyCommitments);
    }

    Ok(commitments.iter().map(|commitment| commitment.value().clone()).collect())
}

fn bound_params_hash_value(
    bound_params_hash: &BoundParamsHash,
) -> Result<BigUint, RailgunTxidError> {
    // Public txid derivation rejects non-canonical field-byte encodings here so the
    // typed API preserves the exact interoperability surface used by upstream Railgun.
    poseidon::field_from_canonical_bytes(bound_params_hash.as_bytes())
        .map(poseidon::field_to_biguint)
        .map_err(|_| RailgunTxidError::InvalidBoundParamsHash)
}

/// Derives the canonical padded nullifiers hash used by Railgun txid derivation.
///
/// Railgun pads nullifiers to exactly 13 slots with the canonical Merkle zero
/// before hashing so V2 and V3 transactions commit to the same fixed-width
/// Poseidon input shape.
///
/// # Errors
///
/// Returns an error if more than 13 nullifiers are provided or if hashing fails.
pub fn derive_nullifiers_hash(nullifiers: &[Nullifier]) -> Result<Nullifier, RailgunTxidError> {
    let hash = poseidon::hash_padded_txid_fields(&nullifier_values(nullifiers)?)
        .map_err(|_| RailgunTxidError::HashingFailure)?;

    Nullifier::new(hash).map_err(|_| RailgunTxidError::HashingFailure)
}

/// Derives the canonical padded commitments hash used by Railgun txid derivation.
///
/// Railgun pads commitments to exactly 13 slots with the canonical Merkle zero
/// before hashing so txid derivation remains Circom-compatible for every
/// versioned transaction shape.
///
/// # Errors
///
/// Returns an error if more than 13 commitments are provided or if hashing fails.
pub fn derive_commitments_hash(
    commitments: &[NoteCommitment],
) -> Result<NoteCommitment, RailgunTxidError> {
    let hash = poseidon::hash_padded_txid_fields(&commitment_values(commitments)?)
        .map_err(|_| RailgunTxidError::HashingFailure)?;

    NoteCommitment::new(hash).map_err(|_| RailgunTxidError::HashingFailure)
}

/// Derives the canonical Railgun transaction ID.
///
/// The txid is `poseidon([nullifiersHash, commitmentsHash, boundParamsHash])`
/// after nullifiers and commitments have each been padded to exactly 13 slots
/// with the canonical Railgun Merkle zero value.
///
/// # Errors
///
/// Returns an error if either input vector exceeds 13 items, if
/// `bound_params_hash` is not canonical BN254 field bytes, or if Poseidon
/// hashing fails unexpectedly.
pub fn derive_railgun_txid(
    nullifiers: &[Nullifier],
    commitments: &[NoteCommitment],
    bound_params_hash: &BoundParamsHash,
) -> Result<RailgunTxid, RailgunTxidError> {
    let hash = poseidon::hash_railgun_txid(
        &nullifier_values(nullifiers)?,
        &commitment_values(commitments)?,
        &bound_params_hash_value(bound_params_hash)?,
    )
    .map_err(|_| RailgunTxidError::HashingFailure)?;

    RailgunTxid::new(hash).map_err(|_| RailgunTxidError::HashingFailure)
}

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;
    use railgun_types::{BoundParamsHash, NoteCommitment, Nullifier, RailgunTxid};

    use super::{
        RailgunTxidError, derive_commitments_hash, derive_nullifiers_hash, derive_railgun_txid,
    };

    fn decode_hex<const N: usize>(value: &str) -> [u8; N] {
        let trimmed = value.strip_prefix("0x").unwrap_or(value);
        assert_eq!(trimmed.len(), N * 2, "hex input has unexpected length");

        let mut bytes = [0_u8; N];
        for (index, chunk) in trimmed.as_bytes().chunks_exact(2).enumerate() {
            let high = (chunk[0] as char)
                .to_digit(16)
                .unwrap_or_else(|| panic!("invalid hex nibble at index {}", index * 2));
            let low = (chunk[1] as char)
                .to_digit(16)
                .unwrap_or_else(|| panic!("invalid hex nibble at index {}", index * 2 + 1));
            bytes[index] = u8::try_from((high << 4) | low)
                .unwrap_or_else(|_| panic!("hex byte should fit into u8"));
        }
        bytes
    }

    fn biguint_from_hex(value: &str) -> BigUint {
        BigUint::from_bytes_be(&decode_hex::<32>(value))
    }

    fn nullifier(value: &str) -> Nullifier {
        Nullifier::new(biguint_from_hex(value))
            .unwrap_or_else(|error| panic!("nullifier vector should construct: {error}"))
    }

    fn commitment(value: &str) -> NoteCommitment {
        NoteCommitment::new(biguint_from_hex(value))
            .unwrap_or_else(|error| panic!("commitment vector should construct: {error}"))
    }

    #[test]
    fn nullifiers_hash_depends_on_input_and_padding() {
        let empty = derive_nullifiers_hash(&[])
            .unwrap_or_else(|error| panic!("empty nullifiers hash should derive: {error}"));
        let one = derive_nullifiers_hash(&[nullifier(
            "05802951a46d9e999151eb0eb9e4c7c1260b7ee88539011c207dc169c4dd17ee",
        )])
        .unwrap_or_else(|error| panic!("nullifiers hash should derive: {error}"));

        assert_ne!(empty, one);
    }

    #[test]
    fn commitments_hash_depends_on_order() {
        let forward = derive_commitments_hash(&[
            commitment("007aaf0cbee05066820873170e293e44df6766c29da69ac46fd05d4ff2c0a225"),
            commitment("2d19ecebdbe7eaf95d5e36841de3df4fa84f4d978f00aea308f0edb3deb19586"),
        ])
        .unwrap_or_else(|error| panic!("forward commitments hash should derive: {error}"));
        let reverse = derive_commitments_hash(&[
            commitment("2d19ecebdbe7eaf95d5e36841de3df4fa84f4d978f00aea308f0edb3deb19586"),
            commitment("007aaf0cbee05066820873170e293e44df6766c29da69ac46fd05d4ff2c0a225"),
        ])
        .unwrap_or_else(|error| panic!("reverse commitments hash should derive: {error}"));

        assert_ne!(forward, reverse);
    }

    #[test]
    fn derives_canonical_railgun_txid_vector() {
        let txid = derive_railgun_txid(
            &[nullifier("05802951a46d9e999151eb0eb9e4c7c1260b7ee88539011c207dc169c4dd17ee")],
            &[commitment("007aaf0cbee05066820873170e293e44df6766c29da69ac46fd05d4ff2c0a225")],
            &BoundParamsHash::new(decode_hex::<32>(
                "0a4e7bed8287c629fd064665543dc71fdc09b0ab9df7d556f24a1f2f9f018dc7",
            )),
        )
        .unwrap_or_else(|error| panic!("railgun txid should derive: {error}"));

        assert_eq!(
            txid,
            RailgunTxid::new(biguint_from_hex(
                "018d6143a22e09c18ba2a713985bd1e43a095605d5d259d72d96da2cca604f3e",
            ))
            .unwrap_or_else(|error| panic!("canonical railgun txid should construct: {error}"))
        );
    }

    #[test]
    fn rejects_more_than_thirteen_nullifiers() {
        let nullifiers =
            vec![nullifier("05802951a46d9e999151eb0eb9e4c7c1260b7ee88539011c207dc169c4dd17ee"); 14];
        let Err(error) = derive_nullifiers_hash(&nullifiers) else {
            panic!("too many nullifiers should fail");
        };

        assert_eq!(error, RailgunTxidError::TooManyNullifiers);
    }

    #[test]
    fn rejects_more_than_thirteen_commitments() {
        let commitments =
            vec![
                commitment("007aaf0cbee05066820873170e293e44df6766c29da69ac46fd05d4ff2c0a225");
                14
            ];
        let Err(error) = derive_commitments_hash(&commitments) else {
            panic!("too many commitments should fail");
        };

        assert_eq!(error, RailgunTxidError::TooManyCommitments);
    }

    #[test]
    fn rejects_invalid_bound_params_hash_field_element() {
        let Err(error) = derive_railgun_txid(
            &[nullifier("05802951a46d9e999151eb0eb9e4c7c1260b7ee88539011c207dc169c4dd17ee")],
            &[commitment("007aaf0cbee05066820873170e293e44df6766c29da69ac46fd05d4ff2c0a225")],
            &BoundParamsHash::new([0xff_u8; 32]),
        ) else {
            panic!("invalid bound params hash should fail");
        };

        assert_eq!(error, RailgunTxidError::InvalidBoundParamsHash);
    }
}
