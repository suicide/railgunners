use std::collections::BTreeMap;

use railgunners_poi::PreTransactionPoisPerTxidLeafPerList;
use railgunners_types::Address;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use super::BroadcasterTransactRequestType;
use super::common::{
    BroadcasterRequestSharedParams, PreTransactionPoiWire, SharedWireFields, default_version,
    encode_pre_transaction_poi_bundle, parse_pre_transaction_poi_bundle,
    parse_shared_params_fields, serialize_txid_version, validate_hex_bytes,
};
use crate::BroadcasterError;

/// Typed EIP-7702 authorization attached to a `TX7702` request.
///
/// Both client wire shapes normalize into this type. The `v` value of the nested
/// shape maps to `y_parity` (`27` to `0`, `28` to `1`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Tx7702Authorization {
    address: Address,
    nonce: u64,
    chain_id: u128,
    y_parity: u8,
    r: [u8; 32],
    s: [u8; 32],
}

impl Tx7702Authorization {
    /// Creates a typed EIP-7702 authorization.
    ///
    /// # Errors
    ///
    /// Returns an error if `y_parity` is not `0` or `1`.
    pub fn new(
        address: Address,
        nonce: u64,
        chain_id: u128,
        y_parity: u8,
        r: [u8; 32],
        s: [u8; 32],
    ) -> Result<Self, BroadcasterError> {
        if y_parity > 1 {
            return Err(invalid("authorization yParity must be 0 or 1"));
        }

        Ok(Self { address, nonce, chain_id, y_parity, r, s })
    }

    /// Returns the delegate address.
    #[must_use]
    pub const fn address(&self) -> Address {
        self.address
    }

    /// Returns the authorization nonce.
    #[must_use]
    pub const fn nonce(&self) -> u64 {
        self.nonce
    }

    /// Returns the authorization chain id. `0` means valid on any chain.
    #[must_use]
    pub const fn chain_id(&self) -> u128 {
        self.chain_id
    }

    /// Returns the signature parity (`0` or `1`).
    #[must_use]
    pub const fn y_parity(&self) -> u8 {
        self.y_parity
    }

    /// Returns the signature `r` scalar bytes.
    #[must_use]
    pub const fn r(&self) -> &[u8; 32] {
        &self.r
    }

    /// Returns the signature `s` scalar bytes.
    #[must_use]
    pub const fn s(&self) -> &[u8; 32] {
        &self.s
    }
}

/// Typed `TX7702` broadcaster transact payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BroadcasterRawParamsTransactTx7702 {
    shared: BroadcasterRequestSharedParams,
    to: Address,
    data: String,
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
    authorization: Tx7702Authorization,
    gas_limit: Option<String>,
    pre_transaction_pois_per_txid_leaf_per_list: PreTransactionPoisPerTxidLeafPerList,
}

impl BroadcasterRawParamsTransactTx7702 {
    /// Creates a validated `TX7702` broadcaster transact payload.
    ///
    /// # Errors
    ///
    /// Returns an error if the calldata is not hex.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        shared: BroadcasterRequestSharedParams,
        to: Address,
        data: String,
        max_fee_per_gas: u128,
        max_priority_fee_per_gas: u128,
        authorization: Tx7702Authorization,
        gas_limit: Option<String>,
        pre_transaction_pois_per_txid_leaf_per_list: PreTransactionPoisPerTxidLeafPerList,
    ) -> Result<Self, BroadcasterError> {
        validate_hex_bytes(&data)?;

        Ok(Self {
            shared,
            to,
            data,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            authorization,
            gas_limit,
            pre_transaction_pois_per_txid_leaf_per_list,
        })
    }

    /// Returns the canonical `TX7702` transact type.
    #[must_use]
    pub const fn transact_type(&self) -> BroadcasterTransactRequestType {
        BroadcasterTransactRequestType::Tx7702
    }

    /// Returns the shared broadcaster request params.
    #[must_use]
    pub const fn shared(&self) -> &BroadcasterRequestSharedParams {
        &self.shared
    }

    /// Returns the ephemeral EOA that authorizes the delegation.
    #[must_use]
    pub const fn to(&self) -> Address {
        self.to
    }

    /// Returns the calldata string.
    #[must_use]
    pub fn data(&self) -> &str {
        &self.data
    }

    /// Returns the client EIP-1559 maximum fee per gas.
    #[must_use]
    pub const fn max_fee_per_gas(&self) -> u128 {
        self.max_fee_per_gas
    }

    /// Returns the client EIP-1559 maximum priority fee per gas.
    #[must_use]
    pub const fn max_priority_fee_per_gas(&self) -> u128 {
        self.max_priority_fee_per_gas
    }

    /// Returns the typed EIP-7702 authorization.
    #[must_use]
    pub const fn authorization(&self) -> &Tx7702Authorization {
        &self.authorization
    }

    /// Returns the optional client gas limit, parsed and never submitted.
    #[must_use]
    pub fn gas_limit(&self) -> Option<&str> {
        self.gas_limit.as_deref()
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

#[derive(Debug, Deserialize)]
struct Tx7702Wire {
    #[serde(rename = "transactType", default)]
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
    #[serde(rename = "maxFeePerGas")]
    max_fee_per_gas: Box<RawValue>,
    #[serde(rename = "maxPriorityFeePerGas")]
    max_priority_fee_per_gas: Box<RawValue>,
    authorization: Tx7702AuthorizationWire,
    #[serde(rename = "gasLimit", default)]
    gas_limit: Option<Box<RawValue>>,
    #[serde(rename = "preTransactionPOIsPerTxidLeafPerList")]
    pre_transaction_pois_per_txid_leaf_per_list:
        BTreeMap<String, BTreeMap<String, PreTransactionPoiWire>>,
}

/// Authorization wire shape. Both client shapes are accepted; a nested
/// `signature` object wins over flat `r`/`s`/`yParity` fields.
#[derive(Debug, Deserialize)]
struct Tx7702AuthorizationWire {
    address: String,
    nonce: Box<RawValue>,
    #[serde(rename = "chainId")]
    chain_id: Box<RawValue>,
    signature: Option<Tx7702SignatureWire>,
    r: Option<Box<RawValue>>,
    s: Option<Box<RawValue>>,
    #[serde(rename = "yParity")]
    y_parity: Option<Box<RawValue>>,
}

#[derive(Debug, Deserialize)]
struct Tx7702SignatureWire {
    v: Box<RawValue>,
    r: Box<RawValue>,
    s: Box<RawValue>,
}

#[derive(Serialize)]
struct Tx7702OutWire {
    #[serde(rename = "transactType")]
    transact_type: &'static str,
    #[serde(rename = "txidVersion")]
    txid_version: &'static str,
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
    #[serde(rename = "maxFeePerGas")]
    max_fee_per_gas: String,
    #[serde(rename = "maxPriorityFeePerGas")]
    max_priority_fee_per_gas: String,
    authorization: Tx7702AuthorizationOut,
    #[serde(rename = "gasLimit", skip_serializing_if = "Option::is_none")]
    gas_limit: Option<String>,
    #[serde(rename = "preTransactionPOIsPerTxidLeafPerList")]
    pre_transaction_pois_per_txid_leaf_per_list:
        BTreeMap<String, BTreeMap<String, PreTransactionPoiWire>>,
}

#[derive(Serialize)]
struct Tx7702AuthorizationOut {
    address: String,
    nonce: String,
    #[serde(rename = "chainId")]
    chain_id: String,
    signature: Tx7702SignatureOut,
}

#[derive(Serialize)]
struct Tx7702SignatureOut {
    r: String,
    s: String,
    v: u8,
}

impl TryFrom<Tx7702Wire> for BroadcasterRawParamsTransactTx7702 {
    type Error = BroadcasterError;

    fn try_from(value: Tx7702Wire) -> Result<Self, Self::Error> {
        match BroadcasterTransactRequestType::parse(&value.transact_type)? {
            BroadcasterTransactRequestType::Tx7702 => {}
            BroadcasterTransactRequestType::Common => {
                return Err(BroadcasterError::UnsupportedTransactType(value.transact_type));
            }
        }

        let shared = parse_shared_params_fields(&SharedWireFields {
            txid_version: &value.txid_version,
            chain_id: value.chain_id,
            chain_type: value.chain_type,
            fees_id: &value.fees_id,
            broadcaster_viewing_key: &value.broadcaster_viewing_key,
            dev_log: value.dev_log,
            min_version: &value.min_version,
            max_version: &value.max_version,
        })?;
        let to =
            Address::parse(&value.to).map_err(|_| BroadcasterError::InvalidTransactToAddress)?;
        let max_fee_per_gas = parse_uint(&value.max_fee_per_gas, u128::MAX, "maxFeePerGas")?;
        let max_priority_fee_per_gas =
            parse_uint(&value.max_priority_fee_per_gas, u128::MAX, "maxPriorityFeePerGas")?;
        let authorization = parse_authorization(&value.authorization)?;
        let gas_limit = value.gas_limit.as_deref().map(parse_gas_limit).transpose()?;
        let pre_transaction_pois_per_txid_leaf_per_list =
            parse_pre_transaction_poi_bundle(value.pre_transaction_pois_per_txid_leaf_per_list)?;

        Self::new(
            shared,
            to,
            value.data,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            authorization,
            gas_limit,
            pre_transaction_pois_per_txid_leaf_per_list,
        )
    }
}

impl From<&BroadcasterRawParamsTransactTx7702> for Tx7702OutWire {
    fn from(value: &BroadcasterRawParamsTransactTx7702) -> Self {
        Self {
            transact_type: value.transact_type().as_wire(),
            txid_version: serialize_txid_version(value.shared().txid_version()),
            chain_id: value.shared().chain_id().get(),
            chain_type: u64::from(value.shared().chain_type().get()),
            fees_id: value.shared().fees_id().to_owned(),
            broadcaster_viewing_key: value.shared().broadcaster_viewing_key().to_owned(),
            dev_log: value.shared().dev_log(),
            min_version: value.shared().min_version().to_owned(),
            max_version: value.shared().max_version().to_owned(),
            to: value.to().to_string(),
            data: value.data().to_owned(),
            max_fee_per_gas: value.max_fee_per_gas().to_string(),
            max_priority_fee_per_gas: value.max_priority_fee_per_gas().to_string(),
            authorization: Tx7702AuthorizationOut {
                address: value.authorization().address().to_string(),
                nonce: value.authorization().nonce().to_string(),
                chain_id: value.authorization().chain_id().to_string(),
                signature: Tx7702SignatureOut {
                    r: format!("0x{}", hex::encode(value.authorization().r())),
                    s: format!("0x{}", hex::encode(value.authorization().s())),
                    v: value.authorization().y_parity() + 27,
                },
            },
            gas_limit: value.gas_limit().map(ToOwned::to_owned),
            pre_transaction_pois_per_txid_leaf_per_list: encode_pre_transaction_poi_bundle(
                value.pre_transaction_pois_per_txid_leaf_per_list(),
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Authorization parsing
// ---------------------------------------------------------------------------

fn parse_authorization(
    wire: &Tx7702AuthorizationWire,
) -> Result<Tx7702Authorization, BroadcasterError> {
    let address = Address::parse(&wire.address)
        .map_err(|_| invalid("authorization address is not a valid address"))?;
    let nonce =
        parse_uint(&wire.nonce, u128::from(u64::MAX), "authorization nonce").and_then(|value| {
            u64::try_from(value).map_err(|_| invalid("authorization nonce is too large"))
        })?;
    let chain_id = parse_uint(&wire.chain_id, u128::MAX, "authorization chainId")?;

    let (y_parity, r, s) = if let Some(signature) = &wire.signature {
        let v = parse_uint(&signature.v, u128::from(u8::MAX), "authorization signature v")?;
        let y_parity = match v {
            27 => 0_u8,
            28 => 1_u8,
            _ => return Err(invalid("authorization signature v must be 27 or 28")),
        };
        let r = parse_word(&signature.r, "authorization signature r")?;
        let s = parse_word(&signature.s, "authorization signature s")?;
        (y_parity, r, s)
    } else {
        let y_parity = wire
            .y_parity
            .as_deref()
            .ok_or_else(|| invalid("authorization yParity is missing"))
            .and_then(|value| parse_uint(value, 1, "authorization yParity"))?;
        let y_parity =
            u8::try_from(y_parity).map_err(|_| invalid("authorization yParity must be 0 or 1"))?;
        let r = parse_word(
            wire.r.as_deref().ok_or_else(|| invalid("authorization r is missing"))?,
            "authorization r",
        )?;
        let s = parse_word(
            wire.s.as_deref().ok_or_else(|| invalid("authorization s is missing"))?,
            "authorization s",
        )?;
        (y_parity, r, s)
    };

    Tx7702Authorization::new(address, nonce, chain_id, y_parity, r, s)
}

fn parse_word(value: &RawValue, field: &'static str) -> Result<[u8; 32], BroadcasterError> {
    let text: String = serde_json::from_str(value.get())
        .map_err(|_| invalid(format!("{field} must be 32-byte hex").as_str()))?;
    let trimmed = text.strip_prefix("0x").unwrap_or(&text);
    let bytes = hex::decode(trimmed)
        .map_err(|_| invalid(format!("{field} must be 32-byte hex").as_str()))?;

    bytes.try_into().map_err(|_| invalid(format!("{field} must be 32-byte hex").as_str()))
}

// ---------------------------------------------------------------------------
// Scalar parsing
// ---------------------------------------------------------------------------

enum ParsedUint {
    Value(u128),
    Overflow,
    Invalid,
}

fn parse_uint(value: &RawValue, max: u128, field: &'static str) -> Result<u128, BroadcasterError> {
    match parse_uint_raw(value) {
        ParsedUint::Value(number) if number <= max => Ok(number),
        ParsedUint::Value(_) | ParsedUint::Overflow => {
            Err(invalid(format!("{field} is too large").as_str()))
        }
        ParsedUint::Invalid => {
            Err(invalid(format!("{field} must be a non-negative integer").as_str()))
        }
    }
}

/// Parses a raw JSON token, so integers above `u64::MAX` keep full precision
/// instead of being rejected by `serde_json`'s number representation.
fn parse_uint_raw(value: &RawValue) -> ParsedUint {
    let token = value.get().trim();

    if token.starts_with('"') {
        return serde_json::from_str::<String>(token)
            .map_or(ParsedUint::Invalid, |text| parse_uint_text(&text));
    }

    if token.is_empty() {
        return ParsedUint::Invalid;
    }
    if token.bytes().all(|byte| byte.is_ascii_digit()) {
        return token.parse::<u128>().map_or(ParsedUint::Overflow, ParsedUint::Value);
    }

    parse_decimal_token(token)
}

/// Parses an exponent or fractional JSON number exactly, without going through
/// `f64`, so a large or long token cannot silently change value.
fn parse_decimal_token(token: &str) -> ParsedUint {
    let Some(unsigned) = token.strip_prefix('-') else {
        return parse_unsigned_decimal_token(token);
    };

    // Only a negative zero is acceptable; a negative value is not a
    // non-negative integer.
    match parse_unsigned_decimal_token(unsigned) {
        ParsedUint::Value(0) => ParsedUint::Value(0),
        _ => ParsedUint::Invalid,
    }
}

fn parse_unsigned_decimal_token(unsigned: &str) -> ParsedUint {
    if unsigned.starts_with('-') || unsigned.is_empty() {
        return ParsedUint::Invalid;
    }

    let (mantissa, exponent) = unsigned
        .split_once(['e', 'E'])
        .map_or((unsigned, None), |(mantissa, exponent)| (mantissa, Some(exponent)));

    let (integer, fraction) =
        mantissa.split_once('.').map_or((mantissa, ""), |(integer, fraction)| (integer, fraction));
    if integer.is_empty() && fraction.is_empty() {
        return ParsedUint::Invalid;
    }
    if !integer.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return ParsedUint::Invalid;
    }

    let digits = format!("{integer}{fraction}");
    let digits = digits.trim_start_matches('0');
    if digits.is_empty() {
        return ParsedUint::Value(0);
    }

    let exponent = match exponent {
        None => 0,
        Some(exponent) => match exponent.parse::<i64>() {
            Ok(exponent) => exponent,
            Err(_) if exponent.starts_with('-') => return ParsedUint::Invalid,
            Err(_) => return ParsedUint::Overflow,
        },
    };
    let Ok(fraction_len) = i64::try_from(fraction.len()) else {
        return ParsedUint::Invalid;
    };
    let Some(adjust) = exponent.checked_sub(fraction_len) else {
        return ParsedUint::Invalid;
    };

    if adjust >= 0 {
        let Some(total_len) =
            usize::try_from(adjust).ok().and_then(|adjust| digits.len().checked_add(adjust))
        else {
            return ParsedUint::Overflow;
        };
        // A `u128` has at most 39 decimal digits.
        if total_len > 39 {
            return ParsedUint::Overflow;
        }

        let mut scaled = String::with_capacity(total_len);
        scaled.push_str(digits);
        scaled.extend(std::iter::repeat_n('0', total_len - digits.len()));
        return scaled.parse::<u128>().map_or(ParsedUint::Overflow, ParsedUint::Value);
    }

    let Ok(divisor) = usize::try_from(adjust.unsigned_abs()) else {
        return ParsedUint::Invalid;
    };
    if divisor >= digits.len() {
        return ParsedUint::Invalid;
    }
    let (whole, dropped) = digits.split_at(digits.len() - divisor);
    if !dropped.bytes().all(|byte| byte == b'0') {
        return ParsedUint::Invalid;
    }

    whole.parse::<u128>().map_or(ParsedUint::Overflow, ParsedUint::Value)
}

fn parse_uint_text(text: &str) -> ParsedUint {
    let trimmed = text.trim();

    if let Some(hex) = trimmed.strip_prefix("0x") {
        if hex.is_empty() || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return ParsedUint::Invalid;
        }
        return u128::from_str_radix(hex, 16).map_or(ParsedUint::Overflow, ParsedUint::Value);
    }

    if trimmed.is_empty() || !trimmed.bytes().all(|byte| byte.is_ascii_digit()) {
        return ParsedUint::Invalid;
    }
    trimmed.parse::<u128>().map_or(ParsedUint::Overflow, ParsedUint::Value)
}

fn parse_gas_limit(value: &RawValue) -> Result<String, BroadcasterError> {
    let token = value.get().trim();

    if token.starts_with('"') {
        let text: String = serde_json::from_str(token)
            .map_err(|_| invalid("gasLimit must be a non-negative integer"))?;
        if text.is_empty() {
            return Err(invalid("gasLimit must be a non-negative integer"));
        }
        return Ok(text);
    }

    match parse_uint_raw(value) {
        ParsedUint::Value(number) => Ok(number.to_string()),
        ParsedUint::Overflow | ParsedUint::Invalid => {
            Err(invalid("gasLimit must be a non-negative integer"))
        }
    }
}

fn invalid(message: &str) -> BroadcasterError {
    BroadcasterError::InvalidTransactPayload(message.to_owned().into())
}

// ---------------------------------------------------------------------------
// Public parse / serialize
// ---------------------------------------------------------------------------

/// Parses a `TX7702` broadcaster transact payload.
///
/// # Errors
///
/// Returns an error if the payload shape, the authorization, or any validated
/// field is malformed.
pub fn parse(payload: &str) -> Result<BroadcasterRawParamsTransactTx7702, BroadcasterError> {
    let wire: Tx7702Wire =
        serde_json::from_str(payload).map_err(|_| BroadcasterError::InvalidTransactPayloadJson)?;
    wire.try_into()
}

/// Serializes a `TX7702` broadcaster transact payload into canonical JSON.
///
/// # Errors
///
/// Returns an error if serialization fails unexpectedly.
pub fn serialize(payload: &BroadcasterRawParamsTransactTx7702) -> Result<String, BroadcasterError> {
    serde_json::to_string(&Tx7702OutWire::from(payload))
        .map_err(|_| BroadcasterError::InvalidTransactPayloadJson)
}

#[cfg(test)]
mod tests {
    use super::{BroadcasterRawParamsTransactTx7702, Tx7702Authorization, parse, serialize};
    use crate::BroadcasterError;

    const VIEWING_KEY: &str = "0x0707070707070707070707070707070707070707070707070707070707070707";
    const DELEGATE: &str = "0x1F74b4339990Db761bC0168F20D294A3a141497e";
    const TO: &str = "0x1111111111111111111111111111111111111111";
    const R: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";
    const S: &str = "0x2222222222222222222222222222222222222222222222222222222222222222";

    fn base_payload() -> serde_json::Value {
        serde_json::json!({
            "transactType": "TX7702",
            "txidVersion": "V2_PoseidonMerkle",
            "chainID": 1,
            "chainType": 0,
            "feesID": "fees-cache-id",
            "broadcasterViewingKey": VIEWING_KEY,
            "devLog": true,
            "minVersion": "1.0.0",
            "maxVersion": "1.1.0",
            "to": TO,
            "data": "0x1234",
            "maxFeePerGas": "2000000000",
            "maxPriorityFeePerGas": "1",
            "authorization": {
                "address": DELEGATE,
                "nonce": "1",
                "chainId": "1",
                "signature": { "r": R, "s": S, "v": 27 },
            },
            "preTransactionPOIsPerTxidLeafPerList": {},
        })
    }

    fn parse_value(value: &serde_json::Value) -> BroadcasterRawParamsTransactTx7702 {
        parse(&value.to_string()).unwrap_or_else(|error| panic!("payload should parse: {error}"))
    }

    fn parse_error(value: &serde_json::Value) -> BroadcasterError {
        let Err(error) = parse(&value.to_string()) else {
            panic!("payload should fail to parse");
        };

        error
    }

    #[test]
    fn parses_nested_authorization() {
        let payload = parse_value(&base_payload());

        assert_eq!(payload.authorization().nonce(), 1);
        assert_eq!(payload.authorization().chain_id(), 1);
        assert_eq!(payload.authorization().y_parity(), 0);
        assert_eq!(payload.authorization().r(), &[0x11; 32]);
        assert_eq!(payload.authorization().s(), &[0x22; 32]);
        assert_eq!(payload.gas_limit(), None);
    }

    #[test]
    fn parses_flat_authorization() {
        let mut value = base_payload();
        value["authorization"] = serde_json::json!({
            "address": DELEGATE,
            "nonce": "0x2",
            "chainId": 1,
            "r": R,
            "s": S,
            "yParity": 1,
        });

        let payload = parse_value(&value);

        assert_eq!(payload.authorization().nonce(), 2);
        assert_eq!(payload.authorization().y_parity(), 1);
    }

    #[test]
    fn parses_hex_and_numeric_scalars() {
        let mut value = base_payload();
        value["maxFeePerGas"] = serde_json::json!(0x05f5_e100);
        value["maxPriorityFeePerGas"] = serde_json::json!("0x10");
        value["authorization"]["chainId"] = serde_json::json!("0x0");
        value["authorization"]["nonce"] = serde_json::json!(7);

        let payload = parse_value(&value);

        assert_eq!(payload.max_fee_per_gas(), 100_000_000);
        assert_eq!(payload.max_priority_fee_per_gas(), 16);
        assert_eq!(payload.authorization().chain_id(), 0);
        assert_eq!(payload.authorization().nonce(), 7);
    }

    #[test]
    fn prefers_nested_signature_over_flat_fields() {
        let mut value = base_payload();
        value["authorization"]["r"] = serde_json::Value::String("0x33".repeat(32));
        value["authorization"]["s"] = serde_json::Value::String("0x44".repeat(32));
        value["authorization"]["yParity"] = serde_json::json!(1);

        let payload = parse_value(&value);

        assert_eq!(payload.authorization().y_parity(), 0);
        assert_eq!(payload.authorization().r(), &[0x11; 32]);
    }

    #[test]
    fn gas_limit_round_trips() {
        let mut value = base_payload();
        value["gasLimit"] = serde_json::json!("250000");

        let payload = parse_value(&value);
        assert_eq!(payload.gas_limit(), Some("250000"));

        let serialized =
            serialize(&payload).unwrap_or_else(|error| panic!("payload should serialize: {error}"));
        let json: serde_json::Value = serde_json::from_str(&serialized)
            .unwrap_or_else(|error| panic!("serialized payload should parse: {error}"));
        assert_eq!(json["gasLimit"], "250000");
        assert_eq!(json["transactType"], "TX7702");
        assert_eq!(json["authorization"]["signature"]["v"], 27);
    }

    #[test]
    fn gas_limit_is_omitted_when_absent() {
        let payload = parse_value(&base_payload());
        let serialized =
            serialize(&payload).unwrap_or_else(|error| panic!("payload should serialize: {error}"));
        let json: serde_json::Value = serde_json::from_str(&serialized)
            .unwrap_or_else(|error| panic!("serialized payload should parse: {error}"));

        assert!(json.get("gasLimit").is_none());
    }

    #[test]
    fn rejects_missing_authorization() {
        let mut value = base_payload();
        let object =
            value.as_object_mut().unwrap_or_else(|| panic!("payload should be a JSON object"));
        object.remove("authorization");

        assert_eq!(parse_error(&value), BroadcasterError::InvalidTransactPayloadJson);
    }

    #[test]
    fn rejects_missing_fee() {
        let mut value = base_payload();
        let object =
            value.as_object_mut().unwrap_or_else(|| panic!("payload should be a JSON object"));
        object.remove("maxFeePerGas");

        assert_eq!(parse_error(&value), BroadcasterError::InvalidTransactPayloadJson);
    }

    #[test]
    fn rejects_v_outside_27_and_28() {
        let mut value = base_payload();
        value["authorization"]["signature"]["v"] = serde_json::json!(29);

        assert_eq!(
            parse_error(&value),
            BroadcasterError::InvalidTransactPayload(
                "authorization signature v must be 27 or 28".into()
            )
        );
    }

    #[test]
    fn rejects_y_parity_outside_0_and_1() {
        let mut value = base_payload();
        value["authorization"] = serde_json::json!({
            "address": DELEGATE,
            "nonce": "1",
            "chainId": "1",
            "r": R,
            "s": S,
            "yParity": 2,
        });

        assert_eq!(
            parse_error(&value),
            BroadcasterError::InvalidTransactPayload("authorization yParity is too large".into())
        );
    }

    #[test]
    fn rejects_negative_tokens() {
        for token in ["-1", "-1.5", "-1e3"] {
            let Err(error) = parse_with_raw_fee(token) else {
                panic!("negative fee token {token} should fail");
            };
            assert_eq!(
                error,
                BroadcasterError::InvalidTransactPayload(
                    "maxFeePerGas must be a non-negative integer".into()
                )
            );
        }
    }

    #[test]
    fn accepts_negative_zero() {
        assert_eq!(parse_fee("-0"), 0);
    }

    #[test]
    fn rejects_extreme_exponents_without_panicking() {
        let Err(error) = parse_with_raw_fee("1e-9223372036854775808") else {
            panic!("extreme negative exponent should fail");
        };
        assert_eq!(
            error,
            BroadcasterError::InvalidTransactPayload(
                "maxFeePerGas must be a non-negative integer".into()
            )
        );

        let Err(error) = parse_with_raw_fee("1e9223372036854775808") else {
            panic!("extreme positive exponent should fail");
        };
        assert_eq!(
            error,
            BroadcasterError::InvalidTransactPayload("maxFeePerGas is too large".into())
        );
    }

    #[test]
    fn rejects_nonce_above_u64() {
        let mut value = base_payload();
        value["authorization"]["nonce"] = serde_json::json!("18446744073709551616");

        assert_eq!(
            parse_error(&value),
            BroadcasterError::InvalidTransactPayload("authorization nonce is too large".into())
        );
    }

    #[test]
    fn accepts_numeric_values_above_u64() {
        // `serde_json::Value` cannot hold integers above `u64::MAX`, so build the
        // numeric tokens as raw JSON text. This is the exact case a JavaScript
        // client serializes for a large numeric fee or chain id.
        let mut value = base_payload();
        value["authorization"]["chainId"] = serde_json::json!("__CHAIN_ID__");
        value["maxFeePerGas"] = serde_json::json!("__MAX_FEE__");
        let text = value
            .to_string()
            .replace("\"__CHAIN_ID__\"", "18446744073709551616")
            .replace("\"__MAX_FEE__\"", "18446744073709551616");

        let payload = parse(&text).unwrap_or_else(|error| panic!("payload should parse: {error}"));

        assert_eq!(payload.authorization().chain_id(), 18_446_744_073_709_551_616);
        assert_eq!(payload.max_fee_per_gas(), 18_446_744_073_709_551_616);
    }

    fn parse_with_raw_fee(
        token: &str,
    ) -> Result<BroadcasterRawParamsTransactTx7702, BroadcasterError> {
        let mut value = base_payload();
        value["maxFeePerGas"] = serde_json::json!("__FEE__");
        let text = value.to_string().replace("\"__FEE__\"", token);
        parse(&text)
    }

    fn parse_fee(token: &str) -> u128 {
        parse_with_raw_fee(token)
            .unwrap_or_else(|error| panic!("fee token should parse: {error}"))
            .max_fee_per_gas()
    }

    #[test]
    fn accepts_exponent_and_fractional_forms() {
        assert_eq!(parse_fee("1e3"), 1_000);
        assert_eq!(parse_fee("1.5e1"), 15);
        assert_eq!(parse_fee("100.0"), 100);
        assert_eq!(parse_fee("0e999"), 0);
    }

    #[test]
    fn preserves_precision_for_fractional_token() {
        assert_eq!(parse_fee("9007199254740993.0"), 9_007_199_254_740_993);
    }

    #[test]
    fn rejects_non_integral_fractional_token() {
        let Err(error) = parse_with_raw_fee("1e-400") else {
            panic!("underflowing fraction should fail");
        };

        assert_eq!(
            error,
            BroadcasterError::InvalidTransactPayload(
                "maxFeePerGas must be a non-negative integer".into()
            )
        );
    }

    #[test]
    fn rejects_exponent_above_u128() {
        let Err(error) = parse_with_raw_fee("4e38") else {
            panic!("fee above u128 should fail");
        };

        assert_eq!(
            error,
            BroadcasterError::InvalidTransactPayload("maxFeePerGas is too large".into())
        );
    }

    #[test]
    fn accepts_exponent_near_u128_boundary() {
        assert_eq!(parse_fee("3.4e38"), 340_000_000_000_000_000_000_000_000_000_000_000_000);
    }

    #[test]
    fn accepts_u128_max_as_string() {
        let mut value = base_payload();
        value["maxFeePerGas"] = serde_json::json!(u128::MAX.to_string());

        let payload = parse_value(&value);

        assert_eq!(payload.max_fee_per_gas(), u128::MAX);
    }

    #[test]
    fn rejects_fee_above_u128() {
        let mut value = base_payload();
        value["maxFeePerGas"] = serde_json::json!("340282366920938463463374607431768211456");

        assert_eq!(
            parse_error(&value),
            BroadcasterError::InvalidTransactPayload("maxFeePerGas is too large".into())
        );
    }

    #[test]
    fn rejects_fractional_numeric_fee() {
        let mut value = base_payload();
        value["maxFeePerGas"] = serde_json::json!(1.5);

        assert_eq!(
            parse_error(&value),
            BroadcasterError::InvalidTransactPayload(
                "maxFeePerGas must be a non-negative integer".into()
            )
        );
    }

    #[test]
    fn rejects_non_numeric_fee() {
        let mut value = base_payload();
        value["maxPriorityFeePerGas"] = serde_json::json!("not-a-number");

        assert_eq!(
            parse_error(&value),
            BroadcasterError::InvalidTransactPayload(
                "maxPriorityFeePerGas must be a non-negative integer".into()
            )
        );
    }

    #[test]
    fn rejects_common_transact_type() {
        let mut value = base_payload();
        value["transactType"] = serde_json::json!("COMMON");

        assert_eq!(
            parse_error(&value),
            BroadcasterError::UnsupportedTransactType("COMMON".to_owned())
        );
    }

    #[test]
    fn authorization_construction_rejects_invalid_parity() {
        let address = railgunners_types::Address::parse(DELEGATE)
            .unwrap_or_else(|error| panic!("address should parse: {error}"));

        let Err(error) = Tx7702Authorization::new(address, 1, 1, 2, [0x11; 32], [0x22; 32]) else {
            panic!("invalid parity should fail");
        };

        assert_eq!(
            error,
            BroadcasterError::InvalidTransactPayload("authorization yParity must be 0 or 1".into())
        );
    }
}
