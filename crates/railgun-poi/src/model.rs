//! Typed POI models and list metadata helpers.

use std::{collections::HashMap, str::FromStr};

use num_bigint::BigUint;
use railgun_core::parse_canonical_field_bytes;
use railgun_types::{Groth16Proof, MerkleNodeHash, MerkleRoot, RailgunTxid};

use crate::PoiError;

/// Canonical default required POI list key.
///
/// Source basis:
/// - <https://github.com/Railgun-Community/shared-models/blob/dc3af7873305938f9f0771a24ad91f807f1b88e0/src/models/proof-of-innocence.ts#L205-L213>
pub const DEFAULT_REQUIRED_POI_LIST_KEY: &str =
    "efc6ddb59c098a13fb2b618fdae94c1c3a807abc8fb1837c93620c9143ee9e88";

/// Canonical default required POI list name.
pub const DEFAULT_REQUIRED_POI_LIST_NAME: &str = "Chainalysis OFAC Sanctions API";

/// Canonical default required POI list description.
pub const DEFAULT_REQUIRED_POI_LIST_DESCRIPTION: &str = "API which is used to restrict bad actors designated by the US Department of the Treasury. See: https://www.chainalysis.com/free-cryptocurrency-sanctions-screening-tools.";

/// Typed POI list key used by proofs and broadcaster policy.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PoiListKey([u8; 32]);

impl PoiListKey {
    /// Creates a POI list key from raw bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Parses a POI list key from canonical lowercase hex.
    ///
    /// # Errors
    ///
    /// Returns an error when `value` is not exactly 32 bytes of hex.
    pub fn parse(value: &str) -> Result<Self, PoiError> {
        Ok(Self(decode_hex_32(value, "POI list key must be exactly 32 bytes of hex")?))
    }

    /// Returns the raw POI list-key bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl core::fmt::Display for PoiListKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for PoiListKey {
    type Err = PoiError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

/// Typed txid leaf hash used as the nested POI proof lookup key.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TxidLeafHash(MerkleNodeHash);

impl TxidLeafHash {
    /// Creates a txid leaf hash from an existing Merkle node hash.
    #[must_use]
    pub const fn new(hash: MerkleNodeHash) -> Self {
        Self(hash)
    }

    /// Parses a txid leaf hash from canonical 32-byte hex.
    ///
    /// # Errors
    ///
    /// Returns an error when `value` is not exactly 32 bytes of hex.
    pub fn parse(value: &str) -> Result<Self, PoiError> {
        Ok(Self(MerkleNodeHash::new(decode_hex_32(
            value,
            "txid leaf hash must be exactly 32 bytes of hex",
        )?)))
    }

    /// Returns the wrapped Merkle node hash.
    #[must_use]
    pub const fn hash(&self) -> &MerkleNodeHash {
        &self.0
    }
}

impl FromStr for TxidLeafHash {
    type Err = PoiError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

/// Typed blinded commitment field element used in POI proof payloads.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct BlindedCommitment(BigUint);

impl BlindedCommitment {
    /// Creates a blinded commitment from a field-element integer value.
    ///
    /// # Errors
    ///
    /// Returns an error when `value` is not a canonical BN254 scalar field
    /// element.
    pub fn new(value: BigUint) -> Result<Self, PoiError> {
        validate_field_value(&value, "blinded commitment must fit within the BN254 scalar field")?;
        Ok(Self(value))
    }

    /// Parses a blinded commitment from canonical 32-byte hex.
    ///
    /// # Errors
    ///
    /// Returns an error when `value` is not exactly 32 bytes of hex or is not a
    /// canonical BN254 scalar field element.
    pub fn parse(value: &str) -> Result<Self, PoiError> {
        let bytes = decode_hex_32(value, "blinded commitment must be exactly 32 bytes of hex")?;
        parse_canonical_field_bytes(&bytes).map(Self).map_err(|_| {
            PoiError::InvalidFieldEncoding("blinded commitment must be canonical BN254 field bytes")
        })
    }

    /// Returns the underlying field-element integer value.
    #[must_use]
    pub const fn value(&self) -> &BigUint {
        &self.0
    }
}

impl FromStr for BlindedCommitment {
    type Err = PoiError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

/// Typed txid merkle-root index bound into POI proofs.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TxidMerklerootIndex(u64);

impl TxidMerklerootIndex {
    /// Creates a txid merkle-root index from an explicit integer value.
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

/// Validation status for one POI item.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PoiStatus {
    /// The POI has been validated in the list event set.
    Valid,
    /// The originating shield was blocked.
    ShieldBlocked,
    /// A proof was submitted but not yet validated.
    ProofSubmitted,
    /// A required proof or shield status is missing.
    Missing,
}

impl FromStr for PoiStatus {
    type Err = PoiError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "Valid" => Ok(Self::Valid),
            "ShieldBlocked" => Ok(Self::ShieldBlocked),
            "ProofSubmitted" => Ok(Self::ProofSubmitted),
            "Missing" => Ok(Self::Missing),
            _ => Err(PoiError::UnknownPoiStatus(value.to_owned())),
        }
    }
}

/// Canonical POI list type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PoiListType {
    /// The list is enforced by policy.
    Active,
    /// The list is collected but not enforced.
    Gather,
}

impl FromStr for PoiListType {
    type Err = PoiError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "Active" => Ok(Self::Active),
            "Gather" => Ok(Self::Gather),
            _ => Err(PoiError::UnknownPoiListType(value.to_owned())),
        }
    }
}

/// Canonical POI event type used in list-sync status.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PoiEventType {
    /// Shield event list.
    Shield,
    /// Current transact event list.
    Transact,
    /// Unshield event list.
    Unshield,
    /// Legacy transact event list.
    LegacyTransact,
}

impl FromStr for PoiEventType {
    type Err = PoiError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "Shield" => Ok(Self::Shield),
            "Transact" => Ok(Self::Transact),
            "Unshield" => Ok(Self::Unshield),
            "LegacyTransact" => Ok(Self::LegacyTransact),
            _ => Err(PoiError::UnknownPoiEventType(value.to_owned())),
        }
    }
}

/// Event counts for one POI list status snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PoiEventLengths {
    shield: u64,
    transact: u64,
    unshield: u64,
    legacy_transact: u64,
}

impl PoiEventLengths {
    /// Creates POI event counts from explicit typed fields.
    #[must_use]
    pub const fn new(shield: u64, transact: u64, unshield: u64, legacy_transact: u64) -> Self {
        Self { shield, transact, unshield, legacy_transact }
    }

    /// Returns the shield event count.
    #[must_use]
    pub const fn shield(self) -> u64 {
        self.shield
    }

    /// Returns the transact event count.
    #[must_use]
    pub const fn transact(self) -> u64 {
        self.transact
    }

    /// Returns the unshield event count.
    #[must_use]
    pub const fn unshield(self) -> u64 {
        self.unshield
    }

    /// Returns the legacy transact event count.
    #[must_use]
    pub const fn legacy_transact(self) -> u64 {
        self.legacy_transact
    }
}

/// Typed POI proof payload captured before transaction broadcast.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreTransactionPoi {
    snark_proof: Groth16Proof,
    txid_merkleroot: MerkleRoot,
    poi_merkleroots: Vec<MerkleRoot>,
    blinded_commitments_out: Vec<BlindedCommitment>,
    railgun_txid_if_has_unshield: RailgunTxid,
}

impl PreTransactionPoi {
    /// Creates a pre-transaction POI payload.
    ///
    /// # Errors
    ///
    /// Returns an error when required lists or blinded commitments are empty.
    pub fn new(
        snark_proof: Groth16Proof,
        txid_merkleroot: MerkleRoot,
        poi_merkleroots: Vec<MerkleRoot>,
        blinded_commitments_out: Vec<BlindedCommitment>,
        railgun_txid_if_has_unshield: RailgunTxid,
    ) -> Result<Self, PoiError> {
        if poi_merkleroots.is_empty() {
            return Err(PoiError::InvalidPoiPayload(
                "POI proof payload must include at least one POI merkleroot",
            ));
        }
        if blinded_commitments_out.is_empty() {
            return Err(PoiError::InvalidPoiPayload(
                "POI proof payload must include at least one blinded commitment",
            ));
        }

        Ok(Self {
            snark_proof,
            txid_merkleroot,
            poi_merkleroots,
            blinded_commitments_out,
            railgun_txid_if_has_unshield,
        })
    }

    /// Returns the Groth16 proof payload.
    #[must_use]
    pub const fn snark_proof(&self) -> &Groth16Proof {
        &self.snark_proof
    }

    /// Returns the txid merkle root.
    #[must_use]
    pub const fn txid_merkleroot(&self) -> &MerkleRoot {
        &self.txid_merkleroot
    }

    /// Returns the ordered POI merkle roots.
    #[must_use]
    pub fn poi_merkleroots(&self) -> &[MerkleRoot] {
        &self.poi_merkleroots
    }

    /// Returns the ordered blinded commitments out.
    #[must_use]
    pub fn blinded_commitments_out(&self) -> &[BlindedCommitment] {
        &self.blinded_commitments_out
    }

    /// Returns the unshield-linked Railgun txid.
    #[must_use]
    pub const fn railgun_txid_if_has_unshield(&self) -> &RailgunTxid {
        &self.railgun_txid_if_has_unshield
    }
}

/// Nested POI proof map keyed by list and txid leaf hash.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PreTransactionPoisPerTxidLeafPerList(
    HashMap<PoiListKey, HashMap<TxidLeafHash, PreTransactionPoi>>,
);

impl PreTransactionPoisPerTxidLeafPerList {
    /// Creates the nested POI proof map from an existing typed structure.
    #[must_use]
    pub fn new(proofs: HashMap<PoiListKey, HashMap<TxidLeafHash, PreTransactionPoi>>) -> Self {
        Self(proofs)
    }

    /// Inserts one proof for the specified list and txid leaf hash.
    pub fn insert(
        &mut self,
        list_key: PoiListKey,
        txid_leaf_hash: TxidLeafHash,
        proof: PreTransactionPoi,
    ) {
        self.0.entry(list_key).or_default().insert(txid_leaf_hash, proof);
    }

    /// Returns the nested POI proof map.
    #[must_use]
    pub fn as_map(&self) -> &HashMap<PoiListKey, HashMap<TxidLeafHash, PreTransactionPoi>> {
        &self.0
    }
}

/// Typed POI proof payload submitted for one transact proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransactProofData {
    snark_proof: Groth16Proof,
    poi_merkleroots: Vec<MerkleRoot>,
    txid_merkleroot: MerkleRoot,
    txid_merkleroot_index: TxidMerklerootIndex,
    blinded_commitments_out: Vec<BlindedCommitment>,
    railgun_txid_if_has_unshield: RailgunTxid,
}

impl TransactProofData {
    /// Creates a transact proof-data payload.
    ///
    /// # Errors
    ///
    /// Returns an error when required lists or blinded commitments are empty.
    pub fn new(
        snark_proof: Groth16Proof,
        poi_merkleroots: Vec<MerkleRoot>,
        txid_merkleroot: MerkleRoot,
        txid_merkleroot_index: TxidMerklerootIndex,
        blinded_commitments_out: Vec<BlindedCommitment>,
        railgun_txid_if_has_unshield: RailgunTxid,
    ) -> Result<Self, PoiError> {
        if poi_merkleroots.is_empty() {
            return Err(PoiError::InvalidPoiPayload(
                "transact proof data must include at least one POI merkleroot",
            ));
        }
        if blinded_commitments_out.is_empty() {
            return Err(PoiError::InvalidPoiPayload(
                "transact proof data must include at least one blinded commitment",
            ));
        }

        Ok(Self {
            snark_proof,
            poi_merkleroots,
            txid_merkleroot,
            txid_merkleroot_index,
            blinded_commitments_out,
            railgun_txid_if_has_unshield,
        })
    }

    /// Returns the Groth16 proof payload.
    #[must_use]
    pub const fn snark_proof(&self) -> &Groth16Proof {
        &self.snark_proof
    }

    /// Returns the ordered POI merkle roots.
    #[must_use]
    pub fn poi_merkleroots(&self) -> &[MerkleRoot] {
        &self.poi_merkleroots
    }

    /// Returns the txid merkle root.
    #[must_use]
    pub const fn txid_merkleroot(&self) -> &MerkleRoot {
        &self.txid_merkleroot
    }

    /// Returns the txid merkle-root index.
    #[must_use]
    pub const fn txid_merkleroot_index(&self) -> TxidMerklerootIndex {
        self.txid_merkleroot_index
    }

    /// Returns the ordered blinded commitments out.
    #[must_use]
    pub fn blinded_commitments_out(&self) -> &[BlindedCommitment] {
        &self.blinded_commitments_out
    }

    /// Returns the unshield-linked Railgun txid.
    #[must_use]
    pub const fn railgun_txid_if_has_unshield(&self) -> &RailgunTxid {
        &self.railgun_txid_if_has_unshield
    }
}

/// Human-readable POI list metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PoiList {
    key: PoiListKey,
    list_type: PoiListType,
    name: String,
    description: String,
}

impl PoiList {
    /// Creates POI list metadata from explicit typed fields.
    ///
    /// # Errors
    ///
    /// Returns an error when the name or description is empty.
    pub fn new(
        key: PoiListKey,
        list_type: PoiListType,
        name: String,
        description: String,
    ) -> Result<Self, PoiError> {
        if name.trim().is_empty() {
            return Err(PoiError::InvalidPoiListMetadata("POI list name must not be empty"));
        }
        if description.trim().is_empty() {
            return Err(PoiError::InvalidPoiListMetadata("POI list description must not be empty"));
        }

        Ok(Self { key, list_type, name, description })
    }

    /// Returns the typed list key.
    #[must_use]
    pub const fn key(&self) -> &PoiListKey {
        &self.key
    }

    /// Returns the list type.
    #[must_use]
    pub const fn list_type(&self) -> PoiListType {
        self.list_type
    }

    /// Returns the human-readable list name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the human-readable list description.
    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }
}

/// Sync and queue status for one POI list.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PoiListStatus {
    poi_event_lengths: PoiEventLengths,
    list_provider_poi_event_queue_length: Option<u64>,
    pending_transact_proofs: u64,
    blocked_shields: u64,
    historical_merkleroots_length: u64,
    latest_historical_merkleroot: MerkleRoot,
}

impl PoiListStatus {
    /// Creates a typed POI list status snapshot.
    #[must_use]
    pub const fn new(
        poi_event_lengths: PoiEventLengths,
        list_provider_poi_event_queue_length: Option<u64>,
        pending_transact_proofs: u64,
        blocked_shields: u64,
        historical_merkleroots_length: u64,
        latest_historical_merkleroot: MerkleRoot,
    ) -> Self {
        Self {
            poi_event_lengths,
            list_provider_poi_event_queue_length,
            pending_transact_proofs,
            blocked_shields,
            historical_merkleroots_length,
            latest_historical_merkleroot,
        }
    }

    /// Returns the per-event sync counts.
    #[must_use]
    pub const fn poi_event_lengths(&self) -> PoiEventLengths {
        self.poi_event_lengths
    }

    /// Returns the optional provider queue length.
    #[must_use]
    pub const fn list_provider_poi_event_queue_length(&self) -> Option<u64> {
        self.list_provider_poi_event_queue_length
    }

    /// Returns the pending transact-proof count.
    #[must_use]
    pub const fn pending_transact_proofs(&self) -> u64 {
        self.pending_transact_proofs
    }

    /// Returns the blocked shield count.
    #[must_use]
    pub const fn blocked_shields(&self) -> u64 {
        self.blocked_shields
    }

    /// Returns the length of historical POI merkle roots.
    #[must_use]
    pub const fn historical_merkleroots_length(&self) -> u64 {
        self.historical_merkleroots_length
    }

    /// Returns the latest historical POI merkle root.
    #[must_use]
    pub const fn latest_historical_merkleroot(&self) -> &MerkleRoot {
        &self.latest_historical_merkleroot
    }
}

/// Returns the canonical default required POI list key.
///
/// # Panics
///
/// Panics only if the built-in canonical required list key literal stops being a
/// valid 32-byte hex value.
#[must_use]
pub fn default_required_poi_list_key() -> PoiListKey {
    PoiListKey::parse(DEFAULT_REQUIRED_POI_LIST_KEY)
        .unwrap_or_else(|_| panic!("default required POI list key should be canonical"))
}

/// Returns the canonical default required POI list metadata.
///
/// # Panics
///
/// Panics only if the built-in required POI list metadata literals stop being
/// internally consistent.
#[must_use]
pub fn default_required_poi_list() -> PoiList {
    PoiList::new(
        default_required_poi_list_key(),
        PoiListType::Active,
        DEFAULT_REQUIRED_POI_LIST_NAME.to_owned(),
        DEFAULT_REQUIRED_POI_LIST_DESCRIPTION.to_owned(),
    )
    .unwrap_or_else(|_| panic!("default required POI list metadata should be valid"))
}

/// Returns the canonical required POI lists.
#[must_use]
pub fn required_poi_lists() -> Vec<PoiList> {
    vec![default_required_poi_list()]
}

/// Returns whether `key` is one of the canonical required POI list keys.
#[must_use]
pub fn is_required_poi_list_key(key: &PoiListKey) -> bool {
    *key == default_required_poi_list_key()
}

fn validate_field_value(value: &BigUint, message: &'static str) -> Result<(), PoiError> {
    let bytes = value.to_bytes_be();
    if bytes.len() > 32 {
        return Err(PoiError::InvalidFieldEncoding(message));
    }

    let mut padded = [0_u8; 32];
    let start = 32 - bytes.len();
    padded[start..].copy_from_slice(&bytes);
    let roundtrip = parse_canonical_field_bytes(&padded)
        .map_err(|_| PoiError::InvalidFieldEncoding(message))?;

    if roundtrip == *value { Ok(()) } else { Err(PoiError::InvalidFieldEncoding(message)) }
}

fn decode_hex_32(value: &str, message: &'static str) -> Result<[u8; 32], PoiError> {
    let trimmed = value.strip_prefix("0x").unwrap_or(value);
    if trimmed.len() != 64 {
        return Err(PoiError::InvalidHexEncoding(message));
    }

    let mut bytes = [0_u8; 32];
    for (index, chunk) in trimmed.as_bytes().chunks_exact(2).enumerate() {
        let high = (chunk[0] as char).to_digit(16).ok_or(PoiError::InvalidHexEncoding(message))?;
        let low = (chunk[1] as char).to_digit(16).ok_or(PoiError::InvalidHexEncoding(message))?;
        bytes[index] =
            u8::try_from((high << 4) | low).map_err(|_| PoiError::InvalidHexEncoding(message))?;
    }

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use std::fmt::Write;

    use num_bigint::BigUint;
    use railgun_types::{BN254_SCALAR_FIELD_MODULUS_BYTES, Groth16Proof};

    use super::{
        BlindedCommitment, DEFAULT_REQUIRED_POI_LIST_KEY, DEFAULT_REQUIRED_POI_LIST_NAME, PoiError,
        PoiEventLengths, PoiEventType, PoiList, PoiListType, PoiStatus, PreTransactionPoi,
        PreTransactionPoisPerTxidLeafPerList, TransactProofData, TxidLeafHash, TxidMerklerootIndex,
        default_required_poi_list, default_required_poi_list_key, is_required_poi_list_key,
        required_poi_lists,
    };
    use crate::model::PoiListKey;

    fn proof() -> Groth16Proof {
        Groth16Proof::new(
            ["a0".to_owned(), "a1".to_owned()],
            [["b00".to_owned(), "b01".to_owned()], ["b10".to_owned(), "b11".to_owned()]],
            ["c0".to_owned(), "c1".to_owned()],
        )
    }

    fn root(byte: u8) -> railgun_types::MerkleRoot {
        railgun_types::MerkleRoot::new([byte; 32])
    }

    fn txid(byte: u8) -> railgun_types::RailgunTxid {
        railgun_types::RailgunTxid::new(BigUint::from(byte))
            .unwrap_or_else(|error| panic!("test txid should validate: {error}"))
    }

    fn blinded(byte: u8) -> BlindedCommitment {
        BlindedCommitment::new(BigUint::from(byte))
            .unwrap_or_else(|error| panic!("test blinded commitment should validate: {error}"))
    }

    fn encode_hex(bytes: &[u8]) -> String {
        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(&mut encoded, "{byte:02x}")
                .unwrap_or_else(|_| panic!("writing to a string should not fail"));
        }
        encoded
    }

    #[test]
    fn poi_status_accepts_only_canonical_values() {
        assert_eq!("Valid".parse::<PoiStatus>(), Ok(PoiStatus::Valid));
        assert_eq!("ShieldBlocked".parse::<PoiStatus>(), Ok(PoiStatus::ShieldBlocked));
        assert_eq!("ProofSubmitted".parse::<PoiStatus>(), Ok(PoiStatus::ProofSubmitted));
        assert_eq!("Missing".parse::<PoiStatus>(), Ok(PoiStatus::Missing));

        assert_eq!("Nope".parse::<PoiStatus>(), Err(PoiError::UnknownPoiStatus("Nope".to_owned())));
    }

    #[test]
    fn poi_list_type_accepts_only_canonical_values() {
        assert_eq!("Active".parse::<PoiListType>(), Ok(PoiListType::Active));
        assert_eq!("Gather".parse::<PoiListType>(), Ok(PoiListType::Gather));
        assert_eq!(
            "Passive".parse::<PoiListType>(),
            Err(PoiError::UnknownPoiListType("Passive".to_owned()))
        );
    }

    #[test]
    fn poi_event_type_accepts_only_canonical_values() {
        assert_eq!("Shield".parse::<PoiEventType>(), Ok(PoiEventType::Shield));
        assert_eq!("Transact".parse::<PoiEventType>(), Ok(PoiEventType::Transact));
        assert_eq!("Unshield".parse::<PoiEventType>(), Ok(PoiEventType::Unshield));
        assert_eq!("LegacyTransact".parse::<PoiEventType>(), Ok(PoiEventType::LegacyTransact));
        assert_eq!(
            "Legacy".parse::<PoiEventType>(),
            Err(PoiError::UnknownPoiEventType("Legacy".to_owned()))
        );
    }

    #[test]
    fn exposes_default_required_poi_list_metadata() {
        let key = default_required_poi_list_key();
        let list = default_required_poi_list();

        assert_eq!(key.to_string(), DEFAULT_REQUIRED_POI_LIST_KEY);
        assert_eq!(list.key().to_string(), DEFAULT_REQUIRED_POI_LIST_KEY);
        assert_eq!(list.name(), DEFAULT_REQUIRED_POI_LIST_NAME);
        assert_eq!(list.list_type(), PoiListType::Active);
        assert!(is_required_poi_list_key(&key));
        assert_eq!(required_poi_lists(), vec![list]);
    }

    #[test]
    fn rejects_invalid_list_metadata_shape() {
        let key = default_required_poi_list_key();
        let error = PoiList::new(key, PoiListType::Active, " ".to_owned(), "desc".to_owned());
        let Err(error) = error else {
            panic!("expected empty POI list name to fail");
        };

        assert_eq!(error, PoiError::InvalidPoiListMetadata("POI list name must not be empty"));
    }

    #[test]
    fn rejects_invalid_list_key_hex() {
        assert_eq!(
            "abcd".parse::<PoiListKey>(),
            Err(PoiError::InvalidHexEncoding("POI list key must be exactly 32 bytes of hex"))
        );
    }

    #[test]
    fn rejects_non_canonical_blinded_commitment_values() {
        let error = BlindedCommitment::parse(&encode_hex(&BN254_SCALAR_FIELD_MODULUS_BYTES));
        let Err(error) = error else {
            panic!("expected field modulus bytes to be rejected");
        };

        assert_eq!(
            error,
            PoiError::InvalidFieldEncoding(
                "blinded commitment must be canonical BN254 field bytes"
            )
        );
    }

    #[test]
    fn rejects_pre_transaction_poi_without_required_vectors() {
        let error = PreTransactionPoi::new(proof(), root(1), Vec::new(), vec![blinded(3)], txid(7));
        let Err(error) = error else {
            panic!("expected empty POI merkleroots to fail");
        };

        assert_eq!(
            error,
            PoiError::InvalidPoiPayload(
                "POI proof payload must include at least one POI merkleroot"
            )
        );
    }

    #[test]
    fn transact_proof_data_preserves_required_fields() {
        let proof_data = TransactProofData::new(
            proof(),
            vec![root(2), root(3)],
            root(4),
            TxidMerklerootIndex::new(9),
            vec![blinded(7)],
            txid(11),
        )
        .unwrap_or_else(|error| panic!("expected transact proof data to construct: {error}"));

        assert_eq!(proof_data.poi_merkleroots().len(), 2);
        assert_eq!(proof_data.txid_merkleroot_index().get(), 9);
        assert_eq!(proof_data.blinded_commitments_out()[0].value(), &BigUint::from(7_u8));
        assert_eq!(proof_data.railgun_txid_if_has_unshield().value(), &BigUint::from(11_u8));
    }

    #[test]
    fn preserves_nested_poi_map_shape() {
        let list_key = default_required_poi_list_key();
        let txid_leaf_hash =
            TxidLeafHash::parse("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
                .unwrap_or_else(|error| panic!("expected txid leaf hash to parse: {error}"));
        let proof =
            PreTransactionPoi::new(proof(), root(1), vec![root(2)], vec![blinded(3)], txid(4))
                .unwrap_or_else(|error| {
                    panic!("expected pre-transaction POI to construct: {error}")
                });

        let mut pois = PreTransactionPoisPerTxidLeafPerList::default();
        pois.insert(list_key, txid_leaf_hash, proof.clone());

        let by_list = pois
            .as_map()
            .get(&list_key)
            .unwrap_or_else(|| panic!("expected POI proofs for required list"));
        assert_eq!(by_list.get(&txid_leaf_hash), Some(&proof));
    }

    #[test]
    fn poi_list_status_exposes_typed_event_lengths() {
        let status =
            super::PoiListStatus::new(PoiEventLengths::new(1, 2, 3, 4), Some(5), 6, 7, 8, root(9));

        assert_eq!(status.poi_event_lengths().legacy_transact(), 4);
        assert_eq!(status.list_provider_poi_event_queue_length(), Some(5));
        assert_eq!(status.latest_historical_merkleroot(), &root(9));
    }
}
