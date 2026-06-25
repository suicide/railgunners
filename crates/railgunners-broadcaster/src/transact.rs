use std::collections::{BTreeMap, HashMap};

use railgunners_poi::{
    BlindedCommitment, PoiListKey, PreTransactionPoi, PreTransactionPoisPerTxidLeafPerList,
    TxidLeafHash,
};
use railgunners_types::{
    Address, ChainId, ChainType, Groth16Proof, MerkleRoot, RailgunTxid, TxidVersion,
    ViewingPublicKey,
};
use serde::{Deserialize, Serialize};

use crate::BroadcasterError;

/// Canonical broadcaster transact request type supported by this crate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BroadcasterTransactRequestType {
    /// Canonical COMMON transact payload.
    Common,
}

impl BroadcasterTransactRequestType {
    fn as_wire(self) -> &'static str {
        match self {
            Self::Common => "COMMON",
        }
    }

    fn parse(value: &str) -> Result<Self, BroadcasterError> {
        match value {
            "COMMON" => Ok(Self::Common),
            unsupported => Err(BroadcasterError::UnsupportedTransactType(unsupported.to_owned())),
        }
    }
}

/// Typed broadcaster compatibility version bounds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BroadcasterVersionRange {
    min_version: String,
    max_version: String,
}

impl BroadcasterVersionRange {
    /// Creates validated broadcaster compatibility version bounds.
    ///
    /// # Errors
    ///
    /// Returns an error if either version string is empty.
    pub fn new(min_version: String, max_version: String) -> Result<Self, BroadcasterError> {
        if min_version.is_empty() {
            return Err(BroadcasterError::InvalidTransactPayload(
                "minVersion must not be empty".into(),
            ));
        }
        if max_version.is_empty() {
            return Err(BroadcasterError::InvalidTransactPayload(
                "maxVersion must not be empty".into(),
            ));
        }

        Ok(Self { min_version, max_version })
    }

    /// Returns the minimum compatible broadcaster version.
    #[must_use]
    pub fn min_version(&self) -> &str {
        &self.min_version
    }

    /// Returns the maximum compatible broadcaster version.
    #[must_use]
    pub fn max_version(&self) -> &str {
        &self.max_version
    }
}

/// Typed shared chain and compatibility params for broadcaster requests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BroadcasterRequestSharedParams {
    txid_version: TxidVersion,
    chain_id: ChainId,
    chain_type: ChainType,
    fees_id: String,
    broadcaster_viewing_key: String,
    dev_log: bool,
    version_range: BroadcasterVersionRange,
}

impl BroadcasterRequestSharedParams {
    /// Creates validated shared broadcaster request params.
    ///
    /// # Errors
    ///
    /// Returns an error if required string fields are empty or the broadcaster
    /// viewing key is not valid canonical 32-byte hex.
    pub fn new(
        txid_version: TxidVersion,
        chain_id: ChainId,
        chain_type: ChainType,
        fees_id: String,
        broadcaster_viewing_key: String,
        dev_log: bool,
        version_range: BroadcasterVersionRange,
    ) -> Result<Self, BroadcasterError> {
        if fees_id.is_empty() {
            return Err(BroadcasterError::InvalidTransactPayload(
                "feesID must not be empty".into(),
            ));
        }
        validate_viewing_key_hex(&broadcaster_viewing_key)?;

        Ok(Self {
            txid_version,
            chain_id,
            chain_type,
            fees_id,
            broadcaster_viewing_key,
            dev_log,
            version_range,
        })
    }

    /// Returns the txid version.
    #[must_use]
    pub const fn txid_version(&self) -> TxidVersion {
        self.txid_version
    }

    /// Returns the chain id.
    #[must_use]
    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    /// Returns the chain type.
    #[must_use]
    pub const fn chain_type(&self) -> ChainType {
        self.chain_type
    }

    /// Returns the fees id.
    #[must_use]
    pub fn fees_id(&self) -> &str {
        &self.fees_id
    }

    /// Returns the raw broadcaster viewing key string.
    #[must_use]
    pub fn broadcaster_viewing_key(&self) -> &str {
        &self.broadcaster_viewing_key
    }

    /// Returns whether development logging is enabled.
    #[must_use]
    pub const fn dev_log(&self) -> bool {
        self.dev_log
    }

    /// Returns the minimum compatible broadcaster version.
    #[must_use]
    pub fn min_version(&self) -> &str {
        self.version_range.min_version()
    }

    /// Returns the maximum compatible broadcaster version.
    #[must_use]
    pub fn max_version(&self) -> &str {
        self.version_range.max_version()
    }
}

/// Typed COMMON broadcaster transact payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BroadcasterRawParamsTransactCommon {
    shared: BroadcasterRequestSharedParams,
    to: String,
    data: String,
    use_relay_adapt: bool,
    min_gas_price: String,
    pre_transaction_pois_per_txid_leaf_per_list: PreTransactionPoisPerTxidLeafPerList,
}

impl BroadcasterRawParamsTransactCommon {
    /// Creates a validated COMMON broadcaster transact payload.
    ///
    /// # Errors
    ///
    /// Returns an error if required fields are empty or malformed.
    pub fn new(
        shared: BroadcasterRequestSharedParams,
        to: String,
        data: String,
        use_relay_adapt: bool,
        min_gas_price: String,
        pre_transaction_pois_per_txid_leaf_per_list: PreTransactionPoisPerTxidLeafPerList,
    ) -> Result<Self, BroadcasterError> {
        if min_gas_price.is_empty() {
            return Err(BroadcasterError::InvalidTransactPayload(
                "minGasPrice must not be empty".into(),
            ));
        }
        validate_address_hex(&to)?;
        validate_hex_bytes(&data).map_err(|_| BroadcasterError::InvalidTransactCalldata)?;

        Ok(Self {
            shared,
            to,
            data,
            use_relay_adapt,
            min_gas_price,
            pre_transaction_pois_per_txid_leaf_per_list,
        })
    }

    /// Returns the canonical COMMON transact type.
    #[must_use]
    pub const fn transact_type(&self) -> BroadcasterTransactRequestType {
        BroadcasterTransactRequestType::Common
    }

    /// Returns the shared broadcaster request params.
    #[must_use]
    pub const fn shared(&self) -> &BroadcasterRequestSharedParams {
        &self.shared
    }

    /// Returns the destination address string.
    #[must_use]
    pub fn to(&self) -> &str {
        &self.to
    }

    /// Returns the calldata string.
    #[must_use]
    pub fn data(&self) -> &str {
        &self.data
    }

    /// Returns whether relay-adapt is requested.
    #[must_use]
    pub const fn use_relay_adapt(&self) -> bool {
        self.use_relay_adapt
    }

    /// Returns the minimum gas price string.
    #[must_use]
    pub fn min_gas_price(&self) -> &str {
        &self.min_gas_price
    }

    /// Returns the nested POI proof bundle.
    #[must_use]
    pub const fn pre_transaction_pois_per_txid_leaf_per_list(
        &self,
    ) -> &PreTransactionPoisPerTxidLeafPerList {
        &self.pre_transaction_pois_per_txid_leaf_per_list
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct BroadcasterRawParamsTransactCommonWire {
    #[serde(rename = "transactType")]
    transact_type: String,
    #[serde(rename = "txidVersion")]
    txid_version: String,
    #[serde(rename = "chainID")]
    chain_id: u64,
    #[serde(rename = "chainType")]
    chain_type: u64,
    #[serde(rename = "feesID")]
    fees_id: String,
    #[serde(rename = "broadcasterViewingKey")]
    broadcaster_viewing_key: String,
    #[serde(rename = "devLog")]
    dev_log: bool,
    #[serde(rename = "minVersion")]
    min_version: String,
    #[serde(rename = "maxVersion")]
    max_version: String,
    to: String,
    data: String,
    #[serde(rename = "useRelayAdapt")]
    use_relay_adapt: bool,
    #[serde(rename = "minGasPrice")]
    min_gas_price: String,
    #[serde(rename = "preTransactionPOIsPerTxidLeafPerList")]
    pre_transaction_pois_per_txid_leaf_per_list:
        BTreeMap<String, BTreeMap<String, PreTransactionPoiWire>>,
}

#[allow(clippy::struct_field_names)]
#[derive(Clone, Debug, Deserialize, Serialize)]
struct Groth16ProofWire {
    pi_a: [String; 2],
    pi_b: [[String; 2]; 2],
    pi_c: [String; 2],
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PreTransactionPoiWire {
    #[serde(rename = "snarkProof")]
    snark_proof: Groth16ProofWire,
    #[serde(rename = "txidMerkleroot")]
    txid_merkleroot: String,
    #[serde(rename = "poiMerkleroots")]
    poi_merkleroots: Vec<String>,
    #[serde(rename = "blindedCommitmentsOut")]
    blinded_commitments_out: Vec<String>,
    #[serde(rename = "railgunTxidIfHasUnshield")]
    railgun_txid_if_has_unshield: String,
}

fn validate_hex_bytes(value: &str) -> Result<Vec<u8>, BroadcasterError> {
    let trimmed = value.strip_prefix("0x").unwrap_or(value);
    hex::decode(trimmed).map_err(|_| BroadcasterError::InvalidTransactCalldata)
}

fn decode_hex_exact<const N: usize>(value: &str) -> Result<[u8; N], BroadcasterError> {
    let trimmed = value.strip_prefix("0x").unwrap_or(value);
    let bytes = hex::decode(trimmed).map_err(|_| {
        BroadcasterError::InvalidTransactPoiBundle("expected canonical hex encoding".into())
    })?;
    bytes.try_into().map_err(|_| {
        BroadcasterError::InvalidTransactPoiBundle(
            "expected canonical fixed-width hex encoding".into(),
        )
    })
}

fn validate_viewing_key_hex(value: &str) -> Result<(), BroadcasterError> {
    let bytes = decode_hex_with_error(value, BroadcasterError::InvalidBroadcasterViewingKey)?;
    ViewingPublicKey::from_slice(&bytes)
        .map_err(|_| BroadcasterError::InvalidBroadcasterViewingKey)?;
    Ok(())
}

fn validate_address_hex(value: &str) -> Result<(), BroadcasterError> {
    let bytes = decode_hex_with_error(value, BroadcasterError::InvalidTransactToAddress)?;
    Address::from_slice(&bytes).map_err(|_| BroadcasterError::InvalidTransactToAddress)?;
    Ok(())
}

fn decode_hex_with_error(
    value: &str,
    error: BroadcasterError,
) -> Result<Vec<u8>, BroadcasterError> {
    let trimmed = value.strip_prefix("0x").unwrap_or(value);
    hex::decode(trimmed).map_err(|_| error)
}

fn parse_txid_version(value: &str) -> Result<TxidVersion, BroadcasterError> {
    match value {
        "V2_PoseidonMerkle" => Ok(TxidVersion::V2PoseidonMerkle),
        "V3_PoseidonMerkle" => Ok(TxidVersion::V3PoseidonMerkle),
        unsupported => Err(BroadcasterError::UnsupportedTxidVersion(unsupported.to_owned())),
    }
}

fn serialize_txid_version(value: TxidVersion) -> &'static str {
    match value {
        TxidVersion::V2PoseidonMerkle => "V2_PoseidonMerkle",
        TxidVersion::V3PoseidonMerkle => "V3_PoseidonMerkle",
    }
}

fn parse_chain_type(value: u64) -> Result<ChainType, BroadcasterError> {
    let chain_type =
        u8::try_from(value).map_err(|_| BroadcasterError::UnsupportedChainType(value))?;
    if chain_type != 0 {
        return Err(BroadcasterError::UnsupportedChainType(value));
    }
    Ok(ChainType::new(chain_type))
}

fn parse_shared_params(
    wire: &BroadcasterRawParamsTransactCommonWire,
) -> Result<BroadcasterRequestSharedParams, BroadcasterError> {
    let txid_version = parse_txid_version(&wire.txid_version)?;
    let chain_id = ChainId::new(wire.chain_id).map_err(|_| BroadcasterError::InvalidChainId)?;
    let chain_type = parse_chain_type(wire.chain_type)?;

    BroadcasterRequestSharedParams::new(
        txid_version,
        chain_id,
        chain_type,
        wire.fees_id.clone(),
        wire.broadcaster_viewing_key.clone(),
        wire.dev_log,
        BroadcasterVersionRange::new(wire.min_version.clone(), wire.max_version.clone())?,
    )
}

fn parse_merkle_root(value: &str) -> Result<MerkleRoot, BroadcasterError> {
    MerkleRoot::from_slice(&decode_hex_exact::<32>(value)?).map_err(|_| {
        BroadcasterError::InvalidTransactPoiBundle(
            "POI merkleroots must be 32-byte hex values".into(),
        )
    })
}

fn parse_railgun_txid(value: &str) -> Result<RailgunTxid, BroadcasterError> {
    let trimmed = value.strip_prefix("0x").unwrap_or(value);
    let bytes = hex::decode(trimmed).map_err(|_| {
        BroadcasterError::InvalidTransactPoiBundle(
            "railgunTxidIfHasUnshield must be canonical hex".into(),
        )
    })?;
    if bytes.len() > 32 {
        return Err(BroadcasterError::InvalidTransactPoiBundle(
            "railgunTxidIfHasUnshield must be at most 32 bytes".into(),
        ));
    }
    let mut padded = [0_u8; 32];
    padded[32 - bytes.len()..].copy_from_slice(&bytes);
    RailgunTxid::new(num_bigint::BigUint::from_bytes_be(&padded)).map_err(|_| {
        BroadcasterError::InvalidTransactPoiBundle(
            "railgunTxidIfHasUnshield must be canonical BN254 field bytes".into(),
        )
    })
}

fn parse_pre_transaction_poi(
    wire: PreTransactionPoiWire,
) -> Result<PreTransactionPoi, BroadcasterError> {
    let poi_merkleroots = wire
        .poi_merkleroots
        .iter()
        .map(|value| parse_merkle_root(value))
        .collect::<Result<Vec<_>, _>>()?;
    let blinded_commitments_out = wire
        .blinded_commitments_out
        .iter()
        .map(|value| {
            BlindedCommitment::parse(value).map_err(|_| {
                BroadcasterError::InvalidTransactPoiBundle(
                    "blindedCommitmentsOut must contain canonical 32-byte BN254 field hex".into(),
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    PreTransactionPoi::new(
        Groth16Proof::new(wire.snark_proof.pi_a, wire.snark_proof.pi_b, wire.snark_proof.pi_c),
        parse_merkle_root(&wire.txid_merkleroot).map_err(|_| {
            BroadcasterError::InvalidTransactPoiBundle(
                "txidMerkleroot must be a 32-byte hex value".into(),
            )
        })?,
        poi_merkleroots,
        blinded_commitments_out,
        parse_railgun_txid(&wire.railgun_txid_if_has_unshield)?,
    )
    .map_err(|error| {
        BroadcasterError::InvalidTransactPoiBundle(match error {
            railgunners_poi::PoiError::InvalidPoiPayload(message) => message.into(),
            _ => "preTransactionPOIsPerTxidLeafPerList contained an invalid proof payload".into(),
        })
    })
}

fn parse_pre_transaction_poi_bundle(
    wire: BTreeMap<String, BTreeMap<String, PreTransactionPoiWire>>,
) -> Result<PreTransactionPoisPerTxidLeafPerList, BroadcasterError> {
    let mut proofs = HashMap::new();

    for (list_key, txid_map) in wire {
        let typed_list_key = PoiListKey::parse(&list_key).map_err(|_| {
            BroadcasterError::InvalidTransactPoiBundle(
                "preTransactionPOIsPerTxidLeafPerList keys must be canonical 32-byte hex list keys"
                    .into(),
            )
        })?;
        let mut typed_txid_map = HashMap::new();
        for (txid_leaf_hash, proof) in txid_map {
            let typed_txid_leaf_hash = TxidLeafHash::parse(&txid_leaf_hash).map_err(|_| {
                BroadcasterError::InvalidTransactPoiBundle(
                    "preTransactionPOIsPerTxidLeafPerList txid keys must be canonical 32-byte hex txid leaf hashes"
                        .into(),
                )
            })?;
            typed_txid_map.insert(typed_txid_leaf_hash, parse_pre_transaction_poi(proof)?);
        }
        proofs.insert(typed_list_key, typed_txid_map);
    }

    Ok(PreTransactionPoisPerTxidLeafPerList::new(proofs))
}

fn encode_merkle_root(root: &MerkleRoot) -> String {
    hex::encode(root.as_bytes())
}

fn encode_railgun_txid(txid: &RailgunTxid) -> String {
    let bytes = txid.value().to_bytes_be();
    let mut padded = [0_u8; 32];
    let start = 32 - bytes.len();
    padded[start..].copy_from_slice(&bytes);
    hex::encode(padded)
}

fn encode_txid_leaf_hash(txid_leaf_hash: &TxidLeafHash) -> String {
    hex::encode(txid_leaf_hash.hash().as_bytes())
}

fn encode_blinded_commitment(commitment: &BlindedCommitment) -> String {
    let bytes = commitment.value().to_bytes_be();
    let mut padded = [0_u8; 32];
    let start = 32 - bytes.len();
    padded[start..].copy_from_slice(&bytes);
    hex::encode(padded)
}

fn encode_pre_transaction_poi(proof: &PreTransactionPoi) -> PreTransactionPoiWire {
    PreTransactionPoiWire {
        snark_proof: Groth16ProofWire {
            pi_a: proof.snark_proof().pi_a().clone(),
            pi_b: proof.snark_proof().pi_b().clone(),
            pi_c: proof.snark_proof().pi_c().clone(),
        },
        txid_merkleroot: encode_merkle_root(proof.txid_merkleroot()),
        poi_merkleroots: proof.poi_merkleroots().iter().map(encode_merkle_root).collect(),
        blinded_commitments_out: proof
            .blinded_commitments_out()
            .iter()
            .map(encode_blinded_commitment)
            .collect(),
        railgun_txid_if_has_unshield: encode_railgun_txid(proof.railgun_txid_if_has_unshield()),
    }
}

fn encode_pre_transaction_poi_bundle(
    bundle: &PreTransactionPoisPerTxidLeafPerList,
) -> BTreeMap<String, BTreeMap<String, PreTransactionPoiWire>> {
    let mut outer = BTreeMap::new();

    for (list_key, txid_map) in bundle.as_map() {
        let mut inner = BTreeMap::new();
        for (txid_leaf_hash, proof) in txid_map {
            inner.insert(encode_txid_leaf_hash(txid_leaf_hash), encode_pre_transaction_poi(proof));
        }
        outer.insert(list_key.to_string(), inner);
    }

    outer
}

impl TryFrom<BroadcasterRawParamsTransactCommonWire> for BroadcasterRawParamsTransactCommon {
    type Error = BroadcasterError;

    fn try_from(value: BroadcasterRawParamsTransactCommonWire) -> Result<Self, Self::Error> {
        BroadcasterTransactRequestType::parse(&value.transact_type)?;
        let shared = parse_shared_params(&value)?;
        let pre_transaction_pois_per_txid_leaf_per_list =
            parse_pre_transaction_poi_bundle(value.pre_transaction_pois_per_txid_leaf_per_list)?;

        Self::new(
            shared,
            value.to,
            value.data,
            value.use_relay_adapt,
            value.min_gas_price,
            pre_transaction_pois_per_txid_leaf_per_list,
        )
    }
}

impl From<&BroadcasterRawParamsTransactCommon> for BroadcasterRawParamsTransactCommonWire {
    fn from(value: &BroadcasterRawParamsTransactCommon) -> Self {
        Self {
            transact_type: value.transact_type().as_wire().to_owned(),
            txid_version: serialize_txid_version(value.shared().txid_version()).to_owned(),
            chain_id: value.shared().chain_id().get(),
            chain_type: u64::from(value.shared().chain_type().get()),
            fees_id: value.shared().fees_id().to_owned(),
            broadcaster_viewing_key: value.shared().broadcaster_viewing_key().to_owned(),
            dev_log: value.shared().dev_log(),
            min_version: value.shared().min_version().to_owned(),
            max_version: value.shared().max_version().to_owned(),
            to: value.to().to_owned(),
            data: value.data().to_owned(),
            use_relay_adapt: value.use_relay_adapt(),
            min_gas_price: value.min_gas_price().to_owned(),
            pre_transaction_pois_per_txid_leaf_per_list: encode_pre_transaction_poi_bundle(
                value.pre_transaction_pois_per_txid_leaf_per_list(),
            ),
        }
    }
}

/// Parses a canonical COMMON broadcaster transact payload.
///
/// # Errors
///
/// Returns an error if the payload shape or any validated field is malformed.
pub fn parse_transact_common_payload(
    payload: &str,
) -> Result<BroadcasterRawParamsTransactCommon, BroadcasterError> {
    let wire: BroadcasterRawParamsTransactCommonWire =
        serde_json::from_str(payload).map_err(|_| BroadcasterError::InvalidTransactPayloadJson)?;
    wire.try_into()
}

/// Serializes a COMMON broadcaster transact payload into canonical JSON.
///
/// # Errors
///
/// Returns an error if serialization fails unexpectedly.
pub fn serialize_transact_common_payload(
    payload: &BroadcasterRawParamsTransactCommon,
) -> Result<String, BroadcasterError> {
    serde_json::to_string(&BroadcasterRawParamsTransactCommonWire::from(payload))
        .map_err(|_| BroadcasterError::InvalidTransactPayloadJson)
}

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;
    use railgunners_poi::{
        PoiListKey, PreTransactionPoi, PreTransactionPoisPerTxidLeafPerList, TxidLeafHash,
    };
    use railgunners_types::{
        ChainId, ChainType, Groth16Proof, MerkleNodeHash, MerkleRoot, RailgunTxid, TxidVersion,
    };

    use super::{
        BroadcasterError, BroadcasterRawParamsTransactCommon, BroadcasterRequestSharedParams,
        BroadcasterVersionRange, parse_transact_common_payload, serialize_transact_common_payload,
    };

    fn sample_poi_bundle() -> PreTransactionPoisPerTxidLeafPerList {
        let mut bundle = PreTransactionPoisPerTxidLeafPerList::default();
        bundle.insert(
            PoiListKey::parse("efc6ddb59c098a13fb2b618fdae94c1c3a807abc8fb1837c93620c9143ee9e88")
                .unwrap_or_else(|error| panic!("test list key should parse: {error}")),
            TxidLeafHash::new(MerkleNodeHash::new([3_u8; 32])),
            PreTransactionPoi::new(
                Groth16Proof::new(
                    ["1".to_owned(), "2".to_owned()],
                    [["3".to_owned(), "4".to_owned()], ["5".to_owned(), "6".to_owned()]],
                    ["7".to_owned(), "8".to_owned()],
                ),
                MerkleRoot::new([9_u8; 32]),
                vec![MerkleRoot::new([10_u8; 32])],
                vec![railgunners_poi::BlindedCommitment::new(BigUint::from(11_u8)).unwrap_or_else(
                    |error| panic!("test blinded commitment should parse: {error}"),
                )],
                RailgunTxid::new(BigUint::from(12_u8))
                    .unwrap_or_else(|error| panic!("test txid should parse: {error}")),
            )
            .unwrap_or_else(|error| panic!("test POI should construct: {error}")),
        );
        bundle
    }

    fn sample_payload() -> BroadcasterRawParamsTransactCommon {
        BroadcasterRawParamsTransactCommon::new(
            BroadcasterRequestSharedParams::new(
                TxidVersion::V2PoseidonMerkle,
                ChainId::new(1)
                    .unwrap_or_else(|error| panic!("test chain id should validate: {error}")),
                ChainType::new(0),
                "fees-cache-id".to_owned(),
                "0x0707070707070707070707070707070707070707070707070707070707070707".to_owned(),
                true,
                BroadcasterVersionRange::new("1.0.0".to_owned(), "1.1.0".to_owned())
                    .unwrap_or_else(|error| panic!("test version range should construct: {error}")),
            )
            .unwrap_or_else(|error| panic!("test shared params should construct: {error}")),
            "0x1111111111111111111111111111111111111111".to_owned(),
            "0x1234".to_owned(),
            false,
            "4096".to_owned(),
            sample_poi_bundle(),
        )
        .unwrap_or_else(|error| panic!("test payload should construct: {error}"))
    }

    #[test]
    fn transact_common_round_trips() {
        let payload = sample_payload();
        let serialized = serialize_transact_common_payload(&payload)
            .unwrap_or_else(|error| panic!("payload should serialize: {error}"));
        let reparsed = parse_transact_common_payload(&serialized)
            .unwrap_or_else(|error| panic!("payload should parse: {error}"));

        assert_eq!(reparsed.transact_type(), payload.transact_type());
        assert_eq!(reparsed.shared(), payload.shared());
        assert_eq!(reparsed.to(), payload.to());
        assert_eq!(reparsed.data(), payload.data());
        assert_eq!(reparsed.use_relay_adapt(), payload.use_relay_adapt());
        assert_eq!(reparsed.min_gas_price(), payload.min_gas_price());
        assert_eq!(
            reparsed.pre_transaction_pois_per_txid_leaf_per_list(),
            payload.pre_transaction_pois_per_txid_leaf_per_list()
        );
    }

    #[test]
    fn parses_canonical_field_names() {
        let payload = sample_payload();
        let serialized = serialize_transact_common_payload(&payload)
            .unwrap_or_else(|error| panic!("payload should serialize: {error}"));
        let json: serde_json::Value = serde_json::from_str(&serialized)
            .unwrap_or_else(|error| panic!("serialized payload should parse as json: {error}"));

        assert_eq!(json["transactType"], "COMMON");
        assert_eq!(json["txidVersion"], "V2_PoseidonMerkle");
        assert_eq!(json["chainID"], 1);
        assert_eq!(json["chainType"], 0);
        assert_eq!(json["feesID"], "fees-cache-id");
        assert_eq!(
            json["broadcasterViewingKey"],
            "0x0707070707070707070707070707070707070707070707070707070707070707"
        );
        assert_eq!(json["devLog"], true);
        assert_eq!(json["minVersion"], "1.0.0");
        assert_eq!(json["maxVersion"], "1.1.0");
        assert_eq!(json["to"], "0x1111111111111111111111111111111111111111");
        assert_eq!(json["data"], "0x1234");
        assert_eq!(json["useRelayAdapt"], false);
        assert_eq!(json["minGasPrice"], "4096");
        assert!(json.get("preTransactionPOIsPerTxidLeafPerList").is_some());
    }

    #[test]
    fn rejects_unsupported_transact_type() {
        let mut value: serde_json::Value = serde_json::from_str(
            &serialize_transact_common_payload(&sample_payload())
                .unwrap_or_else(|error| panic!("payload should serialize: {error}")),
        )
        .unwrap_or_else(|error| panic!("payload should parse: {error}"));
        value["transactType"] = serde_json::Value::String("TX7702".to_owned());

        let Err(error) = parse_transact_common_payload(&value.to_string()) else {
            panic!("unsupported transact type should fail");
        };
        assert_eq!(error, BroadcasterError::UnsupportedTransactType("TX7702".to_owned()));
    }

    #[test]
    fn rejects_invalid_broadcaster_viewing_key() {
        let mut value: serde_json::Value = serde_json::from_str(
            &serialize_transact_common_payload(&sample_payload())
                .unwrap_or_else(|error| panic!("payload should serialize: {error}")),
        )
        .unwrap_or_else(|error| panic!("payload should parse: {error}"));
        value["broadcasterViewingKey"] = serde_json::Value::String("0x1234".to_owned());

        let Err(error) = parse_transact_common_payload(&value.to_string()) else {
            panic!("invalid broadcaster viewing key should fail");
        };
        assert_eq!(error, BroadcasterError::InvalidBroadcasterViewingKey);
    }

    #[test]
    fn rejects_invalid_poi_bundle_key() {
        let mut payload = serde_json::from_str::<serde_json::Value>(
            &serialize_transact_common_payload(&sample_payload())
                .unwrap_or_else(|error| panic!("payload should serialize: {error}")),
        )
        .unwrap_or_else(|error| panic!("payload should parse: {error}"));

        payload["preTransactionPOIsPerTxidLeafPerList"] = serde_json::json!({
            "not-a-list-key": {}
        });

        let Err(error) = parse_transact_common_payload(&payload.to_string()) else {
            panic!("invalid POI list key should fail");
        };
        assert_eq!(
            error,
            BroadcasterError::InvalidTransactPoiBundle(
                "preTransactionPOIsPerTxidLeafPerList keys must be canonical 32-byte hex list keys"
                    .into(),
            )
        );
    }

    #[test]
    fn rejects_missing_required_field() {
        let mut value: serde_json::Value = serde_json::from_str(
            &serialize_transact_common_payload(&sample_payload())
                .unwrap_or_else(|error| panic!("payload should serialize: {error}")),
        )
        .unwrap_or_else(|error| panic!("payload should parse: {error}"));
        let Some(object) = value.as_object_mut() else {
            panic!("payload should be a JSON object");
        };
        object.remove("feesID");

        let Err(error) = parse_transact_common_payload(&value.to_string()) else {
            panic!("missing required field should fail");
        };
        assert_eq!(error, BroadcasterError::InvalidTransactPayloadJson);
    }
}
