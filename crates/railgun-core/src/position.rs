use core::fmt;

use railgun_types::{
    CommitmentLeafPosition, GLOBAL_UTXO_POSITION_PRE_TRANSACTION_POI_PROOF_HARDCODED_VALUE,
    GLOBAL_UTXO_POSITION_UNSHIELD_EVENT_HARDCODED_VALUE,
    GLOBAL_UTXO_TREE_PRE_TRANSACTION_POI_PROOF_HARDCODED_VALUE, GlobalTreePosition, TREE_MAX_ITEMS,
    UtxoLeafCoordinate, UtxoTreeCoordinate,
};

/// Error returned when canonical position math exceeds supported integer ranges.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PositionError {
    /// `start_position + batch_index` overflowed `u32`.
    LeafPositionOverflow,
    /// Commitment leaf position math requires a canonical in-tree start position.
    SentinelCoordinateUnsupportedForCommitmentLeafPosition,
    /// `tree * TREE_MAX_ITEMS + index` overflowed `u64`.
    GlobalTreePositionOverflow,
}

impl fmt::Display for PositionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LeafPositionOverflow => {
                formatter.write_str("commitment leaf position overflowed u32")
            }
            Self::SentinelCoordinateUnsupportedForCommitmentLeafPosition => {
                formatter.write_str("commitment leaf position requires an in-tree start position")
            }
            Self::GlobalTreePositionOverflow => {
                formatter.write_str("global tree position overflowed u64")
            }
        }
    }
}

impl std::error::Error for PositionError {}

/// Computes the canonical commitment leaf position within one UTXO tree.
///
/// The position is `start_position + batch_index`, matching upstream event and
/// txid indexing behavior exactly.
///
/// # Errors
///
/// Returns an error if `start_position` is a sentinel coordinate or if the sum
/// exceeds `u32`.
pub fn commitment_leaf_position(
    start_position: UtxoLeafCoordinate,
    batch_index: u16,
) -> Result<CommitmentLeafPosition, PositionError> {
    let UtxoLeafCoordinate::InTree(start_position) = start_position else {
        return Err(PositionError::SentinelCoordinateUnsupportedForCommitmentLeafPosition);
    };

    u32::from(start_position)
        .checked_add(u32::from(batch_index))
        .map(CommitmentLeafPosition::new)
        .ok_or(PositionError::LeafPositionOverflow)
}

/// Computes the canonical global UTXO forest position.
///
/// The formula is `tree * TREE_MAX_ITEMS + index`. This helper intentionally
/// uses typed coordinates rather than raw integers so callers can only provide
/// canonical in-tree values or one of the protocol-defined sentinels.
///
/// # Errors
///
/// Returns an error if the computation exceeds `u64`.
pub fn global_tree_position(
    tree: UtxoTreeCoordinate,
    index: UtxoLeafCoordinate,
) -> Result<GlobalTreePosition, PositionError> {
    u64::from(tree.as_u32())
        .checked_mul(u64::from(TREE_MAX_ITEMS))
        .and_then(|value| value.checked_add(u64::from(index.as_u32())))
        .map(GlobalTreePosition::new)
        .ok_or(PositionError::GlobalTreePositionOverflow)
}

/// Returns the hardcoded unshield-only transaction tree value.
#[must_use]
pub const fn unshield_event_hardcoded_tree() -> UtxoTreeCoordinate {
    UtxoTreeCoordinate::unshield_event_hardcoded()
}

/// Returns the hardcoded unshield-only transaction leaf position.
#[must_use]
pub const fn unshield_event_hardcoded_leaf_position() -> CommitmentLeafPosition {
    CommitmentLeafPosition::new(GLOBAL_UTXO_POSITION_UNSHIELD_EVENT_HARDCODED_VALUE)
}

/// Returns the hardcoded pre-transaction POI proof tree value.
#[must_use]
pub const fn pre_transaction_poi_proof_hardcoded_tree() -> UtxoTreeCoordinate {
    UtxoTreeCoordinate::pre_transaction_poi_proof_hardcoded()
}

/// Returns the hardcoded pre-transaction POI proof leaf position.
#[must_use]
pub const fn pre_transaction_poi_proof_hardcoded_leaf_position() -> CommitmentLeafPosition {
    CommitmentLeafPosition::new(GLOBAL_UTXO_POSITION_PRE_TRANSACTION_POI_PROOF_HARDCODED_VALUE)
}

/// Returns the canonical pre-transaction POI proof global position.
#[must_use]
pub fn global_tree_position_pre_transaction_poi_proof() -> GlobalTreePosition {
    // These constants are part of the protocol surface and must not be inlined
    // elsewhere, so this helper derives the global position from the shared
    // canonical sentinel coordinates instead of duplicating the final value.
    GlobalTreePosition::new(
        u64::from(GLOBAL_UTXO_TREE_PRE_TRANSACTION_POI_PROOF_HARDCODED_VALUE)
            * u64::from(TREE_MAX_ITEMS)
            + u64::from(GLOBAL_UTXO_POSITION_PRE_TRANSACTION_POI_PROOF_HARDCODED_VALUE),
    )
}

#[cfg(test)]
mod tests {
    use railgun_types::{
        GLOBAL_UTXO_POSITION_PRE_TRANSACTION_POI_PROOF_HARDCODED_VALUE,
        GLOBAL_UTXO_POSITION_UNSHIELD_EVENT_HARDCODED_VALUE,
        GLOBAL_UTXO_TREE_PRE_TRANSACTION_POI_PROOF_HARDCODED_VALUE,
        GLOBAL_UTXO_TREE_UNSHIELD_EVENT_HARDCODED_VALUE, UtxoLeafCoordinate, UtxoTreeCoordinate,
    };

    use super::{
        PositionError, commitment_leaf_position, global_tree_position,
        global_tree_position_pre_transaction_poi_proof,
        pre_transaction_poi_proof_hardcoded_leaf_position,
        pre_transaction_poi_proof_hardcoded_tree, unshield_event_hardcoded_leaf_position,
        unshield_event_hardcoded_tree,
    };

    #[test]
    fn commitment_leaf_position_matches_start_plus_batch_index() {
        let position = commitment_leaf_position(UtxoLeafCoordinate::in_tree(40), 2)
            .unwrap_or_else(|error| panic!("leaf position should compute: {error}"));

        assert_eq!(position.get(), 42);
    }

    #[test]
    fn commitment_leaf_position_rejects_sentinel_start_position() {
        let Err(error) =
            commitment_leaf_position(UtxoLeafCoordinate::unshield_event_hardcoded(), 0)
        else {
            panic!("sentinel start position should be rejected");
        };

        assert_eq!(error, PositionError::SentinelCoordinateUnsupportedForCommitmentLeafPosition);
    }

    #[test]
    fn commitment_leaf_position_reaches_upper_in_tree_bound() {
        let position = commitment_leaf_position(UtxoLeafCoordinate::in_tree(u16::MAX), 0)
            .unwrap_or_else(|error| {
                panic!("maximum in-tree start position should compute: {error}")
            });

        assert_eq!(position.get(), u32::from(u16::MAX));
    }

    #[test]
    fn global_tree_position_matches_canonical_formula() {
        let zero =
            global_tree_position(UtxoTreeCoordinate::in_tree(0), UtxoLeafCoordinate::in_tree(0))
                .unwrap_or_else(|error| panic!("zero position should compute: {error}"));
        let one_tree =
            global_tree_position(UtxoTreeCoordinate::in_tree(1), UtxoLeafCoordinate::in_tree(0))
                .unwrap_or_else(|error| panic!("tree boundary position should compute: {error}"));
        let sentinel = global_tree_position(
            UtxoTreeCoordinate::unshield_event_hardcoded(),
            UtxoLeafCoordinate::unshield_event_hardcoded(),
        )
        .unwrap_or_else(|error| panic!("sentinel position should compute: {error}"));

        assert_eq!(zero.get(), 0);
        assert_eq!(one_tree.get(), 65_536);
        assert_eq!(sentinel.get(), 6_553_634_463);
    }

    #[test]
    fn pre_transaction_poi_global_tree_position_matches_canonical_vector() {
        let position = global_tree_position_pre_transaction_poi_proof();

        assert_eq!(position.get(), 13_107_334_463);
    }

    #[test]
    fn unshield_hardcoded_values_match_issue_constants() {
        assert_eq!(
            unshield_event_hardcoded_tree().as_u32(),
            GLOBAL_UTXO_TREE_UNSHIELD_EVENT_HARDCODED_VALUE
        );
        assert_eq!(
            unshield_event_hardcoded_leaf_position().get(),
            GLOBAL_UTXO_POSITION_UNSHIELD_EVENT_HARDCODED_VALUE
        );
    }

    #[test]
    fn pre_transaction_poi_hardcoded_values_match_issue_constants() {
        assert_eq!(
            pre_transaction_poi_proof_hardcoded_tree().as_u32(),
            GLOBAL_UTXO_TREE_PRE_TRANSACTION_POI_PROOF_HARDCODED_VALUE
        );
        assert_eq!(
            pre_transaction_poi_proof_hardcoded_leaf_position().get(),
            GLOBAL_UTXO_POSITION_PRE_TRANSACTION_POI_PROOF_HARDCODED_VALUE
        );
    }

    #[test]
    fn pre_transaction_poi_helper_matches_standard_formula() {
        let direct = global_tree_position(
            UtxoTreeCoordinate::pre_transaction_poi_proof_hardcoded(),
            UtxoLeafCoordinate::pre_transaction_poi_proof_hardcoded(),
        )
        .unwrap_or_else(|error| panic!("pre-transaction position should compute: {error}"));

        assert_eq!(global_tree_position_pre_transaction_poi_proof(), direct);
    }
}
