use std::collections::{BTreeMap, HashMap};

use aes_gcm::{
    AesGcm,
    aead::{AeadInPlace, KeyInit, OsRng, generic_array::GenericArray, rand_core::RngCore},
    aes::Aes256,
};
use curve25519_dalek::{edwards::CompressedEdwardsY, scalar::Scalar};
use ed25519_dalek::SigningKey;
use railgunners_core::derive_viewing_public_key;
use railgunners_poi::{
    BlindedCommitment, PoiListKey, PreTransactionPoi, PreTransactionPoisPerTxidLeafPerList,
    TxidLeafHash,
};
use railgunners_types::{
    Address, ChainId, ChainType, Groth16Proof, MerkleRoot, RailgunTxid, TxidVersion,
    ViewingPrivateKey, ViewingPublicKey,
};
use serde::{Deserialize, Serialize};

use super::BroadcasterTransactRequestType;
use crate::{BroadcasterEncryptedData, BroadcasterError, BroadcasterTransactEnvelope};

type Aes256Gcm16 = AesGcm<Aes256, aes_gcm::aead::consts::U16>;

const IV_LENGTH: usize = 16;
const TAG_LENGTH: usize = 16;
const IV_TAG_LENGTH: usize = IV_LENGTH + TAG_LENGTH;

struct DecodedEncryptedData {
    iv: [u8; IV_LENGTH],
    tag: [u8; TAG_LENGTH],
    ciphertext: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Typed transact payload types
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Wire types (private)
// ---------------------------------------------------------------------------

fn default_transact_type() -> String {
    "COMMON".to_owned()
}

fn default_version() -> String {
    "0.0.0".to_owned()
}

#[derive(Debug, Deserialize, Serialize)]
struct BroadcasterRawParamsTransactCommonWire {
    #[serde(rename = "transactType", default = "default_transact_type")]
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
    #[serde(rename = "devLog", default)]
    dev_log: bool,
    #[serde(rename = "minVersion", default = "default_version")]
    min_version: String,
    #[serde(rename = "maxVersion", default = "default_version")]
    max_version: String,
    to: String,
    data: String,
    #[serde(rename = "useRelayAdapt", default)]
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

// ---------------------------------------------------------------------------
// Private validation and parsing helpers
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Public parse / serialize
// ---------------------------------------------------------------------------

/// Parses a canonical COMMON broadcaster transact payload.
///
/// # Errors
///
/// Returns an error if the payload shape or any validated field is malformed.
pub fn parse(payload: &str) -> Result<BroadcasterRawParamsTransactCommon, BroadcasterError> {
    let wire: BroadcasterRawParamsTransactCommonWire =
        serde_json::from_str(payload).map_err(|_| BroadcasterError::InvalidTransactPayloadJson)?;
    wire.try_into()
}

/// Serializes a COMMON broadcaster transact payload into canonical JSON.
///
/// # Errors
///
/// Returns an error if serialization fails unexpectedly.
pub fn serialize(payload: &BroadcasterRawParamsTransactCommon) -> Result<String, BroadcasterError> {
    serde_json::to_string(&BroadcasterRawParamsTransactCommonWire::from(payload))
        .map_err(|_| BroadcasterError::InvalidTransactPayloadJson)
}

// ---------------------------------------------------------------------------
// Decrypted result types
// ---------------------------------------------------------------------------

/// Decrypted broadcaster transact payload and parsed COMMON request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BroadcasterDecryptedTransactCommon {
    plaintext: String,
    payload: BroadcasterRawParamsTransactCommon,
}

impl BroadcasterDecryptedTransactCommon {
    /// Creates a decrypted broadcaster transact payload result.
    #[must_use]
    pub fn new(plaintext: String, payload: BroadcasterRawParamsTransactCommon) -> Self {
        Self { plaintext, payload }
    }

    /// Returns the decrypted canonical transact JSON payload.
    #[must_use]
    pub fn plaintext(&self) -> &str {
        &self.plaintext
    }

    /// Returns the parsed typed transact payload.
    #[must_use]
    pub const fn payload(&self) -> &BroadcasterRawParamsTransactCommon {
        &self.payload
    }
}

/// Decrypted transact plaintext with the retained ECDH shared key.
///
/// Use [`Self::shared_key`] with [`encrypt_data`] to encrypt a reply over
/// the same channel without re-deriving the key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BroadcasterDecryptedTransactPlaintext {
    plaintext: String,
    shared_key: [u8; 32],
}

impl BroadcasterDecryptedTransactPlaintext {
    /// Creates a decrypted transact payload result with the retained shared key.
    #[must_use]
    pub fn new(plaintext: String, shared_key: [u8; 32]) -> Self {
        Self { plaintext, shared_key }
    }

    /// Returns the decrypted plaintext.
    #[must_use]
    pub fn plaintext(&self) -> &str {
        &self.plaintext
    }

    /// Returns the ECDH shared key retained from decryption.
    #[must_use]
    pub const fn shared_key(&self) -> &[u8; 32] {
        &self.shared_key
    }
}

// ---------------------------------------------------------------------------
// Private crypto helpers
// ---------------------------------------------------------------------------

fn ed25519_private_scalar(viewing_private_key: &ViewingPrivateKey) -> Scalar {
    SigningKey::from_bytes(viewing_private_key.as_bytes()).to_scalar()
}

fn decode_edwards_point(
    public_key: &ViewingPublicKey,
    error: BroadcasterError,
) -> Result<curve25519_dalek::edwards::EdwardsPoint, BroadcasterError> {
    CompressedEdwardsY(*public_key.as_bytes()).decompress().ok_or(error)
}

fn derive_transact_shared_key_from_point(
    private_key: &ViewingPrivateKey,
    point: &curve25519_dalek::edwards::EdwardsPoint,
) -> [u8; 32] {
    (point * ed25519_private_scalar(private_key)).to_montgomery().to_bytes()
}

fn ecdh_shared_key(
    private_key: &ViewingPrivateKey,
    public_key: &ViewingPublicKey,
    error: BroadcasterError,
) -> Result<[u8; 32], BroadcasterError> {
    let point = decode_edwards_point(public_key, error)?;
    Ok(derive_transact_shared_key_from_point(private_key, &point))
}

fn decode_encrypted_data(
    encrypted_data: &BroadcasterEncryptedData,
) -> Result<DecodedEncryptedData, BroadcasterError> {
    let parts = encrypted_data.parts();
    let iv_tag = parts[0].strip_prefix("0x").unwrap_or(&parts[0]);
    let ciphertext = parts[1].strip_prefix("0x").unwrap_or(&parts[1]);

    let iv_tag_bytes = hex::decode(iv_tag).map_err(|_| {
        BroadcasterError::InvalidTransactEnvelopeEncryptedData(
            "broadcaster transact encryptedData[0] must be valid hex".into(),
        )
    })?;
    if iv_tag_bytes.len() != IV_TAG_LENGTH {
        return Err(BroadcasterError::InvalidTransactEnvelopeEncryptedData(
            "broadcaster transact encryptedData[0] must contain 16-byte iv and 16-byte tag".into(),
        ));
    }

    let ciphertext_bytes = hex::decode(ciphertext).map_err(|_| {
        BroadcasterError::InvalidTransactEnvelopeEncryptedData(
            "broadcaster transact encryptedData[1] must be valid hex".into(),
        )
    })?;

    let mut iv = [0_u8; IV_LENGTH];
    iv.copy_from_slice(&iv_tag_bytes[..IV_LENGTH]);
    let mut tag = [0_u8; TAG_LENGTH];
    tag.copy_from_slice(&iv_tag_bytes[IV_LENGTH..]);

    Ok(DecodedEncryptedData { iv, tag, ciphertext: ciphertext_bytes })
}

fn decrypt_payload(
    encrypted_data: &BroadcasterEncryptedData,
    shared_key: &[u8; 32],
) -> Result<String, BroadcasterError> {
    let DecodedEncryptedData { iv, tag, mut ciphertext } = decode_encrypted_data(encrypted_data)?;
    let cipher = Aes256Gcm16::new_from_slice(shared_key)
        .map_err(|_| BroadcasterError::TransactDecryptionFailed)?;
    cipher
        .decrypt_in_place_detached(
            GenericArray::from_slice(&iv),
            b"",
            &mut ciphertext,
            &GenericArray::clone_from_slice(&tag),
        )
        .map_err(|_| BroadcasterError::TransactDecryptionFailed)?;

    String::from_utf8(ciphertext).map_err(|_| BroadcasterError::InvalidTransactPayloadUtf8)
}

fn encrypt_with_iv(
    broadcaster_viewing_key: &ViewingPublicKey,
    payload: &BroadcasterRawParamsTransactCommon,
    ephemeral_private_key: &ViewingPrivateKey,
    iv: [u8; IV_LENGTH],
) -> Result<BroadcasterTransactEnvelope, BroadcasterError> {
    let serialized = serialize(payload)?;
    let shared_key = ecdh_shared_key(
        ephemeral_private_key,
        broadcaster_viewing_key,
        BroadcasterError::InvalidBroadcasterEncryptionKey,
    )?;
    let pubkey = derive_viewing_public_key(ephemeral_private_key);
    let encrypted_data = encrypt_data(serialized.as_bytes(), &shared_key, iv)?;

    Ok(BroadcasterTransactEnvelope::new(pubkey, encrypted_data))
}

// ---------------------------------------------------------------------------
// Public encrypt / decrypt functions
// ---------------------------------------------------------------------------

/// Encrypts a typed COMMON transact payload into a canonical broadcaster envelope
/// with a freshly generated ephemeral key.
///
/// # Errors
///
/// Returns an error if the payload cannot be serialized, the broadcaster viewing
/// key is not a valid ed25519 point, or encryption fails unexpectedly.
pub fn encrypt(
    broadcaster_viewing_key: &ViewingPublicKey,
    payload: &BroadcasterRawParamsTransactCommon,
) -> Result<BroadcasterTransactEnvelope, BroadcasterError> {
    let mut ephemeral_private_key = [0_u8; ViewingPrivateKey::LENGTH];
    OsRng.fill_bytes(&mut ephemeral_private_key);
    encrypt_with_key(
        broadcaster_viewing_key,
        payload,
        &ViewingPrivateKey::new(ephemeral_private_key),
    )
}

/// Encrypts a typed COMMON transact payload into a canonical broadcaster envelope
/// using a caller-supplied ephemeral viewing private key.
///
/// # Errors
///
/// Returns an error if the payload cannot be serialized, the broadcaster viewing
/// key is not a valid ed25519 point, or encryption fails unexpectedly.
pub fn encrypt_with_key(
    broadcaster_viewing_key: &ViewingPublicKey,
    payload: &BroadcasterRawParamsTransactCommon,
    ephemeral_private_key: &ViewingPrivateKey,
) -> Result<BroadcasterTransactEnvelope, BroadcasterError> {
    let mut iv = [0_u8; IV_LENGTH];
    OsRng.fill_bytes(&mut iv);
    encrypt_with_iv(broadcaster_viewing_key, payload, ephemeral_private_key, iv)
}

/// Encrypts arbitrary bytes with a pre-derived ECDH shared key and explicit IV,
/// producing a [`BroadcasterEncryptedData`] tuple suitable for a transact
/// response.
///
/// # Errors
///
/// Returns an error if the cipher cannot be initialised or encryption fails
/// unexpectedly.
pub fn encrypt_data(
    data: &[u8],
    shared_key: &[u8; 32],
    iv: [u8; IV_LENGTH],
) -> Result<BroadcasterEncryptedData, BroadcasterError> {
    let cipher = Aes256Gcm16::new_from_slice(shared_key)
        .map_err(|_| BroadcasterError::TransactEncryptionFailed)?;
    let mut encrypted = data.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(GenericArray::from_slice(&iv), b"", &mut encrypted)
        .map_err(|_| BroadcasterError::TransactEncryptionFailed)?;

    Ok(BroadcasterEncryptedData::new([
        format!("0x{}{}", hex::encode(iv), hex::encode(tag.as_slice())),
        format!("0x{}", hex::encode(encrypted)),
    ]))
}

/// Decrypts a canonical broadcaster transact envelope into its plaintext JSON and
/// retains the ECDH shared key. Use this when you need to encrypt a response on
/// the same channel (see [`encrypt_data`]).
///
/// # Errors
///
/// Returns an error if the envelope public key or encrypted tuple is malformed,
/// shared-key derivation fails, decryption fails, or the decrypted plaintext is
/// not valid UTF-8.
pub fn decrypt_with_key(
    broadcaster_viewing_private_key: &ViewingPrivateKey,
    envelope: &BroadcasterTransactEnvelope,
) -> Result<BroadcasterDecryptedTransactPlaintext, BroadcasterError> {
    let shared_key = ecdh_shared_key(
        broadcaster_viewing_private_key,
        envelope.pubkey(),
        BroadcasterError::InvalidTransactEnvelopePubkey,
    )?;
    let plaintext = decrypt_payload(envelope.encrypted_data(), &shared_key)?;
    Ok(BroadcasterDecryptedTransactPlaintext::new(plaintext, shared_key))
}

/// Decrypts a canonical broadcaster transact envelope into its plaintext JSON.
///
/// # Errors
///
/// Returns an error if the envelope public key or encrypted tuple is malformed,
/// shared-key derivation fails, decryption fails, or the decrypted plaintext is
/// not valid UTF-8.
pub fn decrypt_plaintext(
    broadcaster_viewing_private_key: &ViewingPrivateKey,
    envelope: &BroadcasterTransactEnvelope,
) -> Result<String, BroadcasterError> {
    decrypt_with_key(broadcaster_viewing_private_key, envelope).map(|result| result.plaintext)
}

/// Decrypts a canonical broadcaster transact envelope into its plaintext JSON and
/// typed COMMON transact payload.
///
/// # Errors
///
/// Returns an error if the envelope public key or encrypted tuple is malformed,
/// shared-key derivation fails, decryption fails, or the decrypted JSON does not
/// match the canonical COMMON transact payload schema.
pub fn decrypt_envelope(
    broadcaster_viewing_private_key: &ViewingPrivateKey,
    envelope: &BroadcasterTransactEnvelope,
) -> Result<BroadcasterDecryptedTransactCommon, BroadcasterError> {
    let decrypted = decrypt_with_key(broadcaster_viewing_private_key, envelope)?;
    let payload = parse(&decrypted.plaintext)?;

    Ok(BroadcasterDecryptedTransactCommon::new(decrypted.plaintext, payload))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use aes_gcm::{
        AesGcm,
        aead::{AeadInPlace, KeyInit, generic_array::GenericArray},
        aes::Aes256,
    };
    use curve25519_dalek::edwards::CompressedEdwardsY;
    use num_bigint::BigUint;
    use railgunners_core::derive_viewing_public_key;
    use railgunners_poi::{
        PoiListKey, PreTransactionPoi, PreTransactionPoisPerTxidLeafPerList, TxidLeafHash,
    };
    use railgunners_types::{
        ChainId, ChainType, Groth16Proof, MerkleNodeHash, MerkleRoot, RailgunTxid, TxidVersion,
        ViewingPrivateKey, ViewingPublicKey,
    };

    use super::{
        BroadcasterError, BroadcasterRawParamsTransactCommon, BroadcasterRequestSharedParams,
        BroadcasterVersionRange, IV_LENGTH, TAG_LENGTH, decrypt_envelope, decrypt_plaintext,
        decrypt_with_key, ecdh_shared_key, ed25519_private_scalar, encrypt, encrypt_data,
        encrypt_with_iv, encrypt_with_key, parse, serialize,
    };
    use crate::{BroadcasterEncryptedData, BroadcasterTransactEnvelope};

    type Aes256Gcm16 = AesGcm<Aes256, aes_gcm::aead::consts::U16>;

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

    fn decrypt_payload_manual(
        broadcaster_viewing_private_key: &ViewingPrivateKey,
        encrypted_data: &BroadcasterEncryptedData,
        client_pubkey: &ViewingPublicKey,
    ) -> String {
        let shared_key = ecdh_shared_key(
            broadcaster_viewing_private_key,
            client_pubkey,
            BroadcasterError::InvalidTransactEnvelopePubkey,
        )
        .unwrap_or_else(|error| panic!("shared key should derive: {error}"));
        let parts = encrypted_data.parts();
        let iv_tag = parts[0].strip_prefix("0x").unwrap_or(&parts[0]);
        let ciphertext = parts[1].strip_prefix("0x").unwrap_or(&parts[1]);

        let iv = hex::decode(&iv_tag[..IV_LENGTH * 2])
            .unwrap_or_else(|error| panic!("iv should decode: {error}"));
        let tag = hex::decode(&iv_tag[IV_LENGTH * 2..])
            .unwrap_or_else(|error| panic!("tag should decode: {error}"));
        let mut encrypted = hex::decode(ciphertext)
            .unwrap_or_else(|error| panic!("ciphertext should decode: {error}"));

        let cipher = Aes256Gcm16::new_from_slice(&shared_key)
            .unwrap_or_else(|_| panic!("cipher should initialize"));
        cipher
            .decrypt_in_place_detached(
                GenericArray::from_slice(&iv),
                b"",
                &mut encrypted,
                &GenericArray::clone_from_slice(&tag),
            )
            .unwrap_or_else(|_| panic!("ciphertext should decrypt"));

        String::from_utf8(encrypted)
            .unwrap_or_else(|error| panic!("decrypted payload should be utf8: {error}"))
    }

    fn invalid_viewing_public_key_bytes() -> [u8; 32] {
        for first in u8::MIN..=u8::MAX {
            for second in u8::MIN..=u8::MAX {
                let mut candidate = [0_u8; 32];
                candidate[0] = first;
                candidate[1] = second;

                if CompressedEdwardsY(candidate).decompress().is_none() {
                    return candidate;
                }
            }
        }

        panic!("expected at least one invalid compressed ed25519 point encoding");
    }

    // -- Transact payload parse/serialize tests --

    #[test]
    fn transact_common_round_trips() {
        let payload = sample_payload();
        let serialized =
            serialize(&payload).unwrap_or_else(|error| panic!("payload should serialize: {error}"));
        let reparsed =
            parse(&serialized).unwrap_or_else(|error| panic!("payload should parse: {error}"));

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
        let serialized =
            serialize(&payload).unwrap_or_else(|error| panic!("payload should serialize: {error}"));
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
            &serialize(&sample_payload())
                .unwrap_or_else(|error| panic!("payload should serialize: {error}")),
        )
        .unwrap_or_else(|error| panic!("payload should parse: {error}"));
        value["transactType"] = serde_json::Value::String("TX7702".to_owned());

        let Err(error) = parse(&value.to_string()) else {
            panic!("unsupported transact type should fail");
        };
        assert_eq!(error, BroadcasterError::UnsupportedTransactType("TX7702".to_owned()));
    }

    #[test]
    fn rejects_invalid_broadcaster_viewing_key() {
        let mut value: serde_json::Value = serde_json::from_str(
            &serialize(&sample_payload())
                .unwrap_or_else(|error| panic!("payload should serialize: {error}")),
        )
        .unwrap_or_else(|error| panic!("payload should parse: {error}"));
        value["broadcasterViewingKey"] = serde_json::Value::String("0x1234".to_owned());

        let Err(error) = parse(&value.to_string()) else {
            panic!("invalid broadcaster viewing key should fail");
        };
        assert_eq!(error, BroadcasterError::InvalidBroadcasterViewingKey);
    }

    #[test]
    fn rejects_invalid_poi_bundle_key() {
        let mut payload = serde_json::from_str::<serde_json::Value>(
            &serialize(&sample_payload())
                .unwrap_or_else(|error| panic!("payload should serialize: {error}")),
        )
        .unwrap_or_else(|error| panic!("payload should parse: {error}"));

        payload["preTransactionPOIsPerTxidLeafPerList"] = serde_json::json!({
            "not-a-list-key": {}
        });

        let Err(error) = parse(&payload.to_string()) else {
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
            &serialize(&sample_payload())
                .unwrap_or_else(|error| panic!("payload should serialize: {error}")),
        )
        .unwrap_or_else(|error| panic!("payload should parse: {error}"));
        let Some(object) = value.as_object_mut() else {
            panic!("payload should be a JSON object");
        };
        object.remove("feesID");

        let Err(error) = parse(&value.to_string()) else {
            panic!("missing required field should fail");
        };
        assert_eq!(error, BroadcasterError::InvalidTransactPayloadJson);
    }

    // -- Crypto tests --

    #[test]
    fn shared_key_matches_bidirectionally_for_viewing_keys() {
        let sender = ViewingPrivateKey::new([
            0x67, 0xd7, 0xd1, 0x9d, 0x00, 0xe6, 0xe3, 0xb3, 0x51, 0x7f, 0xe6, 0x8a, 0xc4, 0x65,
            0x05, 0xdd, 0x20, 0x7d, 0xf6, 0xe8, 0xfe, 0x3a, 0xa0, 0x6b, 0xa3, 0xfa, 0xce, 0x35,
            0x2e, 0x75, 0x99, 0xef,
        ]);
        let receiver = ViewingPrivateKey::new([
            0x34, 0x28, 0xcf, 0xc9, 0x39, 0x32, 0x03, 0x28, 0x50, 0x11, 0x74, 0xa4, 0xe7, 0x6e,
            0x86, 0x91, 0x97, 0xff, 0xc8, 0x94, 0xb5, 0x8d, 0xbf, 0x4d, 0x0e, 0x95, 0x3c, 0x48,
            0x4d, 0x66, 0xcb, 0x5e,
        ]);
        let sender_shared = ecdh_shared_key(
            &sender,
            &derive_viewing_public_key(&receiver),
            BroadcasterError::InvalidTransactEnvelopePubkey,
        )
        .unwrap_or_else(|error| panic!("sender shared key should derive: {error}"));
        let receiver_shared = ecdh_shared_key(
            &receiver,
            &derive_viewing_public_key(&sender),
            BroadcasterError::InvalidTransactEnvelopePubkey,
        )
        .unwrap_or_else(|error| panic!("receiver shared key should derive: {error}"));

        assert_eq!(sender_shared, receiver_shared);
    }

    #[test]
    fn deterministic_helper_builds_decryptable_envelope() {
        let broadcaster_private_key = ViewingPrivateKey::new([7_u8; 32]);
        let broadcaster_public_key = derive_viewing_public_key(&broadcaster_private_key);
        let ephemeral_private_key = ViewingPrivateKey::new([9_u8; 32]);
        let iv = [11_u8; IV_LENGTH];

        let envelope =
            encrypt_with_iv(&broadcaster_public_key, &sample_payload(), &ephemeral_private_key, iv)
                .unwrap_or_else(|error| panic!("payload should encrypt: {error}"));
        let decrypted = decrypt_payload_manual(
            &broadcaster_private_key,
            envelope.encrypted_data(),
            envelope.pubkey(),
        );
        let reparsed = parse(&decrypted)
            .unwrap_or_else(|error| panic!("decrypted payload should parse: {error}"));

        assert_eq!(envelope.pubkey(), &derive_viewing_public_key(&ephemeral_private_key));
        assert_eq!(reparsed, sample_payload());
    }

    #[test]
    fn public_ephemeral_helper_uses_caller_key() {
        let broadcaster_public_key = derive_viewing_public_key(&ViewingPrivateKey::new([7_u8; 32]));
        let ephemeral_private_key = ViewingPrivateKey::new([9_u8; 32]);

        let envelope =
            encrypt_with_key(&broadcaster_public_key, &sample_payload(), &ephemeral_private_key)
                .unwrap_or_else(|error| panic!("payload should encrypt: {error}"));

        assert_eq!(envelope.pubkey(), &derive_viewing_public_key(&ephemeral_private_key));
    }

    #[test]
    fn random_helper_builds_envelope_with_prefixed_tuple() {
        let broadcaster_public_key = derive_viewing_public_key(&ViewingPrivateKey::new([7_u8; 32]));

        let envelope = encrypt(&broadcaster_public_key, &sample_payload())
            .unwrap_or_else(|error| panic!("payload should encrypt: {error}"));

        assert!(envelope.encrypted_data().parts()[0].starts_with("0x"));
        assert!(envelope.encrypted_data().parts()[1].starts_with("0x"));
    }

    #[test]
    fn rejects_invalid_broadcaster_viewing_key_point() {
        let invalid_public_key = ViewingPublicKey::new(invalid_viewing_public_key_bytes());

        let Err(error) = encrypt_with_iv(
            &invalid_public_key,
            &sample_payload(),
            &ViewingPrivateKey::new([9_u8; 32]),
            [11_u8; IV_LENGTH],
        ) else {
            panic!("invalid broadcaster viewing key should fail");
        };

        assert_eq!(error, BroadcasterError::InvalidBroadcasterEncryptionKey);
    }

    #[test]
    fn shared_key_matches_raw_point_multiplication() {
        let private_key = ViewingPrivateKey::new([9_u8; 32]);
        let public_key = derive_viewing_public_key(&ViewingPrivateKey::new([7_u8; 32]));
        let point = CompressedEdwardsY(*public_key.as_bytes())
            .decompress()
            .unwrap_or_else(|| panic!("public key should decompress"));
        let expected = (point * ed25519_private_scalar(&private_key)).to_montgomery().to_bytes();

        let actual = ecdh_shared_key(
            &private_key,
            &public_key,
            BroadcasterError::InvalidTransactEnvelopePubkey,
        )
        .unwrap_or_else(|error| panic!("shared key should derive: {error}"));

        assert_eq!(actual, expected);
    }

    #[test]
    fn encrypted_payload_layout_matches_canonical_tuple_shape() {
        let encrypted = encrypt_data(b"{}", &[5_u8; 32], [7_u8; IV_LENGTH])
            .unwrap_or_else(|error| panic!("payload should encrypt: {error}"));

        assert_eq!(encrypted.parts()[0].len(), 2 + 32 + 32);
        assert!(encrypted.parts()[1].starts_with("0x"));
    }

    #[test]
    fn decrypt_helper_round_trips_encrypted_common_payload() {
        let broadcaster_private_key = ViewingPrivateKey::new([7_u8; 32]);
        let broadcaster_public_key = derive_viewing_public_key(&broadcaster_private_key);
        let payload = sample_payload();
        let serialized =
            serialize(&payload).unwrap_or_else(|error| panic!("payload should serialize: {error}"));
        let envelope = encrypt_with_iv(
            &broadcaster_public_key,
            &payload,
            &ViewingPrivateKey::new([9_u8; 32]),
            [11_u8; IV_LENGTH],
        )
        .unwrap_or_else(|error| panic!("payload should encrypt: {error}"));

        let decrypted = decrypt_envelope(&broadcaster_private_key, &envelope)
            .unwrap_or_else(|error| panic!("envelope should decrypt: {error}"));

        assert_eq!(decrypted.plaintext(), serialized);
        assert_eq!(decrypted.payload(), &payload);
    }

    #[test]
    fn decrypt_helper_rejects_invalid_envelope_pubkey() {
        let envelope = BroadcasterTransactEnvelope::new(
            ViewingPublicKey::new(invalid_viewing_public_key_bytes()),
            BroadcasterEncryptedData::new([
                format!("0x{}{}", hex::encode([1_u8; IV_LENGTH]), hex::encode([2_u8; TAG_LENGTH])),
                "0x00".to_owned(),
            ]),
        );

        let Err(error) = decrypt_envelope(&ViewingPrivateKey::new([7_u8; 32]), &envelope) else {
            panic!("invalid envelope pubkey should fail");
        };

        assert_eq!(error, BroadcasterError::InvalidTransactEnvelopePubkey);
    }

    #[test]
    fn decrypt_helper_rejects_invalid_encrypted_tuple_shape() {
        let envelope = BroadcasterTransactEnvelope::new(
            derive_viewing_public_key(&ViewingPrivateKey::new([9_u8; 32])),
            BroadcasterEncryptedData::new(["0x1234".to_owned(), "0x00".to_owned()]),
        );

        let Err(error) = decrypt_envelope(&ViewingPrivateKey::new([7_u8; 32]), &envelope) else {
            panic!("invalid encrypted tuple should fail");
        };

        assert_eq!(
            error,
            BroadcasterError::InvalidTransactEnvelopeEncryptedData(
                "broadcaster transact encryptedData[0] must contain 16-byte iv and 16-byte tag"
                    .into(),
            )
        );
    }

    #[test]
    fn decrypt_helper_rejects_wrong_private_key() {
        let broadcaster_private_key = ViewingPrivateKey::new([7_u8; 32]);
        let broadcaster_public_key = derive_viewing_public_key(&broadcaster_private_key);
        let envelope = encrypt_with_iv(
            &broadcaster_public_key,
            &sample_payload(),
            &ViewingPrivateKey::new([9_u8; 32]),
            [11_u8; IV_LENGTH],
        )
        .unwrap_or_else(|error| panic!("payload should encrypt: {error}"));

        let Err(error) = decrypt_envelope(&ViewingPrivateKey::new([8_u8; 32]), &envelope) else {
            panic!("wrong private key should fail");
        };

        assert_eq!(error, BroadcasterError::TransactDecryptionFailed);
    }

    #[test]
    fn decrypt_helper_rejects_invalid_typed_payload_after_successful_decryption() {
        let broadcaster_private_key = ViewingPrivateKey::new([7_u8; 32]);
        let broadcaster_public_key = derive_viewing_public_key(&broadcaster_private_key);
        let envelope = encrypt_with_iv(
            &broadcaster_public_key,
            &sample_payload(),
            &ViewingPrivateKey::new([9_u8; 32]),
            [11_u8; IV_LENGTH],
        )
        .unwrap_or_else(|error| panic!("payload should encrypt: {error}"));
        let malformed_plaintext = r#"{"transactType":"COMMON"}"#;
        let shared_key = ecdh_shared_key(
            &broadcaster_private_key,
            &ViewingPublicKey::new(*envelope.pubkey().as_bytes()),
            BroadcasterError::InvalidTransactEnvelopePubkey,
        )
        .unwrap_or_else(|error| panic!("shared key should derive: {error}"));
        let encrypted_data =
            encrypt_data(malformed_plaintext.as_bytes(), &shared_key, [12_u8; IV_LENGTH])
                .unwrap_or_else(|error| panic!("malformed payload should encrypt: {error}"));
        let malformed_envelope = BroadcasterTransactEnvelope::new(
            ViewingPublicKey::new(*envelope.pubkey().as_bytes()),
            encrypted_data,
        );

        let Err(error) = decrypt_envelope(&broadcaster_private_key, &malformed_envelope) else {
            panic!("invalid typed payload should fail");
        };

        assert_eq!(error, BroadcasterError::InvalidTransactPayloadJson);
    }

    #[test]
    fn decrypt_plaintext_round_trips_encrypted_common_payload() {
        let broadcaster_private_key = ViewingPrivateKey::new([7_u8; 32]);
        let broadcaster_public_key = derive_viewing_public_key(&broadcaster_private_key);
        let payload = sample_payload();
        let serialized =
            serialize(&payload).unwrap_or_else(|error| panic!("payload should serialize: {error}"));
        let envelope = encrypt_with_iv(
            &broadcaster_public_key,
            &payload,
            &ViewingPrivateKey::new([9_u8; 32]),
            [11_u8; IV_LENGTH],
        )
        .unwrap_or_else(|error| panic!("payload should encrypt: {error}"));

        let plaintext = decrypt_plaintext(&broadcaster_private_key, &envelope)
            .unwrap_or_else(|error| panic!("should decrypt: {error}"));

        assert_eq!(plaintext, serialized);
    }

    #[test]
    fn decrypt_plaintext_rejects_wrong_private_key() {
        let broadcaster_private_key = ViewingPrivateKey::new([7_u8; 32]);
        let broadcaster_public_key = derive_viewing_public_key(&broadcaster_private_key);
        let envelope = encrypt_with_iv(
            &broadcaster_public_key,
            &sample_payload(),
            &ViewingPrivateKey::new([9_u8; 32]),
            [11_u8; IV_LENGTH],
        )
        .unwrap_or_else(|error| panic!("payload should encrypt: {error}"));

        let Err(error) = decrypt_plaintext(&ViewingPrivateKey::new([8_u8; 32]), &envelope) else {
            panic!("wrong private key should fail");
        };

        assert_eq!(error, BroadcasterError::TransactDecryptionFailed);
    }

    #[test]
    fn decrypt_plaintext_rejects_malformed_encrypted_tuple() {
        let envelope = BroadcasterTransactEnvelope::new(
            derive_viewing_public_key(&ViewingPrivateKey::new([9_u8; 32])),
            BroadcasterEncryptedData::new(["0x1234".to_owned(), "0x00".to_owned()]),
        );

        let Err(error) = decrypt_plaintext(&ViewingPrivateKey::new([7_u8; 32]), &envelope) else {
            panic!("malformed encrypted tuple should fail");
        };

        assert_eq!(
            error,
            BroadcasterError::InvalidTransactEnvelopeEncryptedData(
                "broadcaster transact encryptedData[0] must contain 16-byte iv and 16-byte tag"
                    .into(),
            )
        );
    }

    #[test]
    fn decrypt_plaintext_rejects_invalid_utf8_plaintext() {
        let broadcaster_private_key = ViewingPrivateKey::new([7_u8; 32]);
        let ephemeral_private_key = ViewingPrivateKey::new([9_u8; 32]);
        let ephemeral_public_key = derive_viewing_public_key(&ephemeral_private_key);
        let shared_key = ecdh_shared_key(
            &broadcaster_private_key,
            &ephemeral_public_key,
            BroadcasterError::InvalidTransactEnvelopePubkey,
        )
        .unwrap_or_else(|error| panic!("shared key should derive: {error}"));

        // Encrypt arbitrary bytes that are not valid UTF-8.
        let encrypted_data = encrypt_data(&[0xFF, 0xFE], &shared_key, [11_u8; IV_LENGTH])
            .unwrap_or_else(|error| panic!("should encrypt: {error}"));
        let envelope = BroadcasterTransactEnvelope::new(ephemeral_public_key, encrypted_data);

        let Err(error) = decrypt_plaintext(&broadcaster_private_key, &envelope) else {
            panic!("invalid UTF-8 should fail");
        };

        assert_eq!(error, BroadcasterError::InvalidTransactPayloadUtf8);
    }

    #[test]
    fn decrypt_with_key_retains_shared_key() {
        let broadcaster_private_key = ViewingPrivateKey::new([7_u8; 32]);
        let broadcaster_public_key = derive_viewing_public_key(&broadcaster_private_key);
        let payload = sample_payload();
        let serialized =
            serialize(&payload).unwrap_or_else(|error| panic!("payload should serialize: {error}"));
        let envelope = encrypt_with_iv(
            &broadcaster_public_key,
            &payload,
            &ViewingPrivateKey::new([9_u8; 32]),
            [11_u8; IV_LENGTH],
        )
        .unwrap_or_else(|error| panic!("payload should encrypt: {error}"));

        let decrypted = decrypt_with_key(&broadcaster_private_key, &envelope)
            .unwrap_or_else(|error| panic!("should decrypt with key: {error}"));

        assert_eq!(decrypted.plaintext(), serialized);
        assert_eq!(decrypted.shared_key().len(), 32);

        // Verify the retained key can re-encrypt data successfully.
        let response_data = b"response payload";
        let iv = [22_u8; IV_LENGTH];
        let encrypted_response = encrypt_data(response_data, decrypted.shared_key(), iv)
            .unwrap_or_else(|error| panic!("should re-encrypt with retained key: {error}"));
        let response_plaintext = decrypt_payload_manual(
            &broadcaster_private_key,
            &encrypted_response,
            envelope.pubkey(),
        );

        assert_eq!(response_plaintext.as_bytes(), response_data);
    }

    #[test]
    fn decrypt_plaintext_and_decrypt_with_key_produce_same_plaintext() {
        let broadcaster_private_key = ViewingPrivateKey::new([7_u8; 32]);
        let broadcaster_public_key = derive_viewing_public_key(&broadcaster_private_key);
        let envelope = encrypt_with_iv(
            &broadcaster_public_key,
            &sample_payload(),
            &ViewingPrivateKey::new([9_u8; 32]),
            [11_u8; IV_LENGTH],
        )
        .unwrap_or_else(|error| panic!("payload should encrypt: {error}"));

        let plaintext = decrypt_plaintext(&broadcaster_private_key, &envelope)
            .unwrap_or_else(|error| panic!("should decrypt plaintext: {error}"));
        let with_key = decrypt_with_key(&broadcaster_private_key, &envelope)
            .unwrap_or_else(|error| panic!("should decrypt with key: {error}"));

        assert_eq!(with_key.plaintext(), plaintext);
    }

    #[test]
    fn decrypt_with_key_rejects_wrong_private_key() {
        let broadcaster_private_key = ViewingPrivateKey::new([7_u8; 32]);
        let broadcaster_public_key = derive_viewing_public_key(&broadcaster_private_key);
        let envelope = encrypt_with_iv(
            &broadcaster_public_key,
            &sample_payload(),
            &ViewingPrivateKey::new([9_u8; 32]),
            [11_u8; IV_LENGTH],
        )
        .unwrap_or_else(|error| panic!("payload should encrypt: {error}"));

        let Err(error) = decrypt_with_key(&ViewingPrivateKey::new([8_u8; 32]), &envelope) else {
            panic!("wrong private key should fail");
        };

        assert_eq!(error, BroadcasterError::TransactDecryptionFailed);
    }

    #[test]
    fn decrypt_with_key_rejects_invalid_envelope_pubkey() {
        let envelope = BroadcasterTransactEnvelope::new(
            ViewingPublicKey::new(invalid_viewing_public_key_bytes()),
            BroadcasterEncryptedData::new([
                format!("0x{}{}", hex::encode([1_u8; IV_LENGTH]), hex::encode([2_u8; TAG_LENGTH])),
                "0x00".to_owned(),
            ]),
        );

        let Err(error) = decrypt_with_key(&ViewingPrivateKey::new([7_u8; 32]), &envelope) else {
            panic!("invalid envelope pubkey should fail");
        };

        assert_eq!(error, BroadcasterError::InvalidTransactEnvelopePubkey);
    }
}
