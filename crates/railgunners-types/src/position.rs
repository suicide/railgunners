use crate::ParseDomainError;

/// Maximum number of leaf slots in one canonical UTXO tree.
pub const TREE_MAX_ITEMS: u32 = 65_536;

/// Hardcoded tree value for unshield-only transactions.
///
/// This sentinel is intentionally outside the range of a real single-tree leaf
/// index so txid positioning cannot collide with actual UTXO outputs.
pub const GLOBAL_UTXO_TREE_UNSHIELD_EVENT_HARDCODED_VALUE: u32 = 99_999;

/// Hardcoded position value for unshield-only transactions.
///
/// This sentinel is intentionally outside the range of a real single-tree leaf
/// index so txid positioning cannot collide with actual UTXO outputs.
pub const GLOBAL_UTXO_POSITION_UNSHIELD_EVENT_HARDCODED_VALUE: u32 = 99_999;

/// Hardcoded tree value for pre-transaction POI proof positioning.
///
/// This sentinel is intentionally outside the range of a real single-tree leaf
/// index so txid positioning cannot collide with actual UTXO outputs.
pub const GLOBAL_UTXO_TREE_PRE_TRANSACTION_POI_PROOF_HARDCODED_VALUE: u32 = 199_999;

/// Hardcoded position value for pre-transaction POI proof positioning.
///
/// This sentinel is intentionally outside the range of a real single-tree leaf
/// index so txid positioning cannot collide with actual UTXO outputs.
pub const GLOBAL_UTXO_POSITION_PRE_TRANSACTION_POI_PROOF_HARDCODED_VALUE: u32 = 199_999;

/// Typed UTXO tree coordinate used by txid positioning helpers.
///
/// Normal in-tree coordinates fit within `u16`, while protocol-defined sentinel
/// values are modeled explicitly so callers cannot pass arbitrary `u32` values.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum UtxoTreeCoordinate {
    /// Canonical in-tree coordinate within the real UTXO forest.
    InTree(u16),
    /// Hardcoded tree coordinate used by unshield-only transactions.
    UnshieldEventHardcoded,
    /// Hardcoded tree coordinate used by pre-transaction POI proofs.
    PreTransactionPoiProofHardcoded,
}

impl UtxoTreeCoordinate {
    /// Creates an in-tree coordinate.
    #[must_use]
    pub const fn in_tree(value: u16) -> Self {
        Self::InTree(value)
    }

    /// Creates the hardcoded unshield-only transaction coordinate.
    #[must_use]
    pub const fn unshield_event_hardcoded() -> Self {
        Self::UnshieldEventHardcoded
    }

    /// Creates the hardcoded pre-transaction POI proof coordinate.
    #[must_use]
    pub const fn pre_transaction_poi_proof_hardcoded() -> Self {
        Self::PreTransactionPoiProofHardcoded
    }

    /// Parses a raw coordinate into the canonical domain.
    ///
    /// # Errors
    ///
    /// Returns an error if `value` is neither a canonical in-tree coordinate nor
    /// one of the protocol-defined sentinel values.
    pub fn from_raw(value: u32) -> Result<Self, ParseDomainError> {
        if let Ok(value) = u16::try_from(value) {
            return Ok(Self::InTree(value));
        }

        match value {
            GLOBAL_UTXO_TREE_UNSHIELD_EVENT_HARDCODED_VALUE => Ok(Self::UnshieldEventHardcoded),
            GLOBAL_UTXO_TREE_PRE_TRANSACTION_POI_PROOF_HARDCODED_VALUE => {
                Ok(Self::PreTransactionPoiProofHardcoded)
            }
            _ => Err(ParseDomainError::new(
                "utxo tree coordinate must be in-tree or one of the canonical hardcoded sentinels",
            )),
        }
    }

    /// Returns the canonical numeric representation.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        match self {
            Self::InTree(value) => value as u32,
            Self::UnshieldEventHardcoded => GLOBAL_UTXO_TREE_UNSHIELD_EVENT_HARDCODED_VALUE,
            Self::PreTransactionPoiProofHardcoded => {
                GLOBAL_UTXO_TREE_PRE_TRANSACTION_POI_PROOF_HARDCODED_VALUE
            }
        }
    }

    /// Returns whether this coordinate points to a canonical in-tree position.
    #[must_use]
    pub const fn is_in_tree(self) -> bool {
        matches!(self, Self::InTree(_))
    }

    /// Returns whether this coordinate is one of the hardcoded sentinels.
    #[must_use]
    pub const fn is_hardcoded(self) -> bool {
        !self.is_in_tree()
    }
}

/// Typed UTXO leaf coordinate used by txid positioning helpers.
///
/// Normal in-tree coordinates fit within `u16`, while protocol-defined sentinel
/// values are modeled explicitly so callers cannot pass arbitrary `u32` values.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum UtxoLeafCoordinate {
    /// Canonical in-tree coordinate within one real UTXO tree.
    InTree(u16),
    /// Hardcoded leaf coordinate used by unshield-only transactions.
    UnshieldEventHardcoded,
    /// Hardcoded leaf coordinate used by pre-transaction POI proofs.
    PreTransactionPoiProofHardcoded,
}

impl UtxoLeafCoordinate {
    /// Creates an in-tree coordinate.
    #[must_use]
    pub const fn in_tree(value: u16) -> Self {
        Self::InTree(value)
    }

    /// Creates the hardcoded unshield-only transaction coordinate.
    #[must_use]
    pub const fn unshield_event_hardcoded() -> Self {
        Self::UnshieldEventHardcoded
    }

    /// Creates the hardcoded pre-transaction POI proof coordinate.
    #[must_use]
    pub const fn pre_transaction_poi_proof_hardcoded() -> Self {
        Self::PreTransactionPoiProofHardcoded
    }

    /// Parses a raw coordinate into the canonical domain.
    ///
    /// # Errors
    ///
    /// Returns an error if `value` is neither a canonical in-tree coordinate nor
    /// one of the protocol-defined sentinel values.
    pub fn from_raw(value: u32) -> Result<Self, ParseDomainError> {
        if let Ok(value) = u16::try_from(value) {
            return Ok(Self::InTree(value));
        }

        match value {
            GLOBAL_UTXO_POSITION_UNSHIELD_EVENT_HARDCODED_VALUE => Ok(Self::UnshieldEventHardcoded),
            GLOBAL_UTXO_POSITION_PRE_TRANSACTION_POI_PROOF_HARDCODED_VALUE => {
                Ok(Self::PreTransactionPoiProofHardcoded)
            }
            _ => Err(ParseDomainError::new(
                "utxo leaf coordinate must be in-tree or one of the canonical hardcoded sentinels",
            )),
        }
    }

    /// Returns the canonical numeric representation.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        match self {
            Self::InTree(value) => value as u32,
            Self::UnshieldEventHardcoded => GLOBAL_UTXO_POSITION_UNSHIELD_EVENT_HARDCODED_VALUE,
            Self::PreTransactionPoiProofHardcoded => {
                GLOBAL_UTXO_POSITION_PRE_TRANSACTION_POI_PROOF_HARDCODED_VALUE
            }
        }
    }

    /// Returns whether this coordinate points to a canonical in-tree position.
    #[must_use]
    pub const fn is_in_tree(self) -> bool {
        matches!(self, Self::InTree(_))
    }

    /// Returns whether this coordinate is one of the hardcoded sentinels.
    #[must_use]
    pub const fn is_hardcoded(self) -> bool {
        !self.is_in_tree()
    }
}

/// Typed commitment leaf position within one UTXO tree.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CommitmentLeafPosition(u32);

impl CommitmentLeafPosition {
    /// Creates a commitment leaf position from an explicit integer value.
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Returns the inner integer value.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Typed global UTXO forest position used in txid leaf hashing and POI work.
///
/// This uses `u64` because the canonical pre-transaction POI sentinel position
/// exceeds `u32` once `tree * TREE_MAX_ITEMS + index` is applied.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GlobalTreePosition(u64);

impl GlobalTreePosition {
    /// Creates a global tree position from an explicit integer value.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the inner integer value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CommitmentLeafPosition, GLOBAL_UTXO_POSITION_PRE_TRANSACTION_POI_PROOF_HARDCODED_VALUE,
        GLOBAL_UTXO_POSITION_UNSHIELD_EVENT_HARDCODED_VALUE,
        GLOBAL_UTXO_TREE_PRE_TRANSACTION_POI_PROOF_HARDCODED_VALUE,
        GLOBAL_UTXO_TREE_UNSHIELD_EVENT_HARDCODED_VALUE, GlobalTreePosition, TREE_MAX_ITEMS,
        UtxoLeafCoordinate, UtxoTreeCoordinate,
    };
    use crate::ParseDomainError;

    #[test]
    fn constants_match_canonical_values() {
        assert_eq!(TREE_MAX_ITEMS, 65_536);
        assert_eq!(GLOBAL_UTXO_TREE_UNSHIELD_EVENT_HARDCODED_VALUE, 99_999);
        assert_eq!(GLOBAL_UTXO_POSITION_UNSHIELD_EVENT_HARDCODED_VALUE, 99_999);
        assert_eq!(GLOBAL_UTXO_TREE_PRE_TRANSACTION_POI_PROOF_HARDCODED_VALUE, 199_999);
        assert_eq!(GLOBAL_UTXO_POSITION_PRE_TRANSACTION_POI_PROOF_HARDCODED_VALUE, 199_999);
    }

    #[test]
    fn commitment_leaf_position_preserves_value() {
        let position = CommitmentLeafPosition::new(42);
        assert_eq!(position.get(), 42);
    }

    #[test]
    fn global_tree_position_preserves_value() {
        let position = GlobalTreePosition::new(13_107_134_463);
        assert_eq!(position.get(), 13_107_134_463);
    }

    #[test]
    fn tree_coordinate_preserves_in_tree_and_hardcoded_values() {
        assert_eq!(UtxoTreeCoordinate::in_tree(12).as_u32(), 12);
        assert_eq!(
            UtxoTreeCoordinate::unshield_event_hardcoded().as_u32(),
            GLOBAL_UTXO_TREE_UNSHIELD_EVENT_HARDCODED_VALUE
        );
        assert_eq!(
            UtxoTreeCoordinate::pre_transaction_poi_proof_hardcoded().as_u32(),
            GLOBAL_UTXO_TREE_PRE_TRANSACTION_POI_PROOF_HARDCODED_VALUE
        );
    }

    #[test]
    fn leaf_coordinate_preserves_in_tree_and_hardcoded_values() {
        assert_eq!(UtxoLeafCoordinate::in_tree(12).as_u32(), 12);
        assert_eq!(
            UtxoLeafCoordinate::unshield_event_hardcoded().as_u32(),
            GLOBAL_UTXO_POSITION_UNSHIELD_EVENT_HARDCODED_VALUE
        );
        assert_eq!(
            UtxoLeafCoordinate::pre_transaction_poi_proof_hardcoded().as_u32(),
            GLOBAL_UTXO_POSITION_PRE_TRANSACTION_POI_PROOF_HARDCODED_VALUE
        );
    }

    #[test]
    fn raw_coordinate_parsing_accepts_only_canonical_values() {
        assert_eq!(
            UtxoTreeCoordinate::from_raw(7)
                .unwrap_or_else(|error| panic!("in-tree tree coordinate should parse: {error}")),
            UtxoTreeCoordinate::InTree(7)
        );
        assert_eq!(
            UtxoLeafCoordinate::from_raw(99_999).unwrap_or_else(|error| {
                panic!("unshield hardcoded leaf coordinate should parse: {error}")
            }),
            UtxoLeafCoordinate::UnshieldEventHardcoded
        );

        let Err(error) = UtxoTreeCoordinate::from_raw(70_000) else {
            panic!("non-canonical tree coordinate should fail");
        };
        assert_eq!(
            error,
            ParseDomainError::new(
                "utxo tree coordinate must be in-tree or one of the canonical hardcoded sentinels"
            )
        );
    }
}
