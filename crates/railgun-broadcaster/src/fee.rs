use std::collections::BTreeMap;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use railgun_core::decode_railgun_address;
use railgun_poi::PoiListKey;
use railgun_types::{RailgunAddress, ViewingPrivateKey};
use serde::{Deserialize, Serialize};

use crate::BroadcasterError;

#[derive(Debug, Deserialize, Serialize)]
struct BroadcasterFeeMessageWire {
    data: String,
    signature: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct BroadcasterFeeMessageDataWire {
    fees: BTreeMap<String, String>,
    #[serde(rename = "feeExpiration")]
    fee_expiration: u64,
    #[serde(rename = "feesID")]
    fees_id: String,
    #[serde(rename = "railgunAddress")]
    railgun_address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    identifier: Option<String>,
    #[serde(rename = "availableWallets")]
    available_wallets: u64,
    version: String,
    #[serde(rename = "relayAdapt")]
    relay_adapt: String,
    #[serde(rename = "requiredPOIListKeys")]
    required_poi_list_keys: Vec<String>,
    reliability: f64,
}

/// Typed broadcaster fee quote data.
#[derive(Clone, Debug, PartialEq)]
pub struct BroadcasterFeeMessageData {
    fees: BTreeMap<String, String>,
    fee_expiration: u64,
    fees_id: String,
    railgun_address: RailgunAddress,
    identifier: Option<String>,
    available_wallets: u64,
    version: String,
    relay_adapt: String,
    required_poi_list_keys: Vec<PoiListKey>,
    reliability: f64,
}

/// Inputs for validated broadcaster fee quote construction.
#[derive(Clone, Debug, PartialEq)]
pub struct BroadcasterFeeMessageDataFields {
    /// Canonical token-fee mapping.
    pub fees: BTreeMap<String, String>,
    /// Fee-expiration timestamp in milliseconds.
    pub fee_expiration: u64,
    /// Broadcaster-generated fee quote identifier.
    pub fees_id: String,
    /// Broadcaster Railgun address.
    pub railgun_address: RailgunAddress,
    /// Optional broadcaster identifier.
    pub identifier: Option<String>,
    /// Current available-wallet count.
    pub available_wallets: u64,
    /// Broadcaster version string.
    pub version: String,
    /// Relay-adapt contract address string.
    pub relay_adapt: String,
    /// Required POI list keys.
    pub required_poi_list_keys: Vec<PoiListKey>,
    /// Broadcaster reliability score.
    pub reliability: f64,
}

impl BroadcasterFeeMessageData {
    /// Creates validated broadcaster fee quote data.
    ///
    /// # Errors
    ///
    /// Returns an error if any required canonical field is empty.
    pub fn new(fields: BroadcasterFeeMessageDataFields) -> Result<Self, BroadcasterError> {
        validate_fee_message_data_fields(
            &fields.fees_id,
            &fields.railgun_address,
            &fields.version,
            &fields.relay_adapt,
        )?;

        Ok(Self {
            fees: fields.fees,
            fee_expiration: fields.fee_expiration,
            fees_id: fields.fees_id,
            railgun_address: fields.railgun_address,
            identifier: fields.identifier,
            available_wallets: fields.available_wallets,
            version: fields.version,
            relay_adapt: fields.relay_adapt,
            required_poi_list_keys: fields.required_poi_list_keys,
            reliability: fields.reliability,
        })
    }

    /// Returns the canonical token-fee mapping.
    #[must_use]
    pub fn fees(&self) -> &BTreeMap<String, String> {
        &self.fees
    }

    /// Returns the fee-expiration timestamp in milliseconds.
    #[must_use]
    pub const fn fee_expiration(&self) -> u64 {
        self.fee_expiration
    }

    /// Returns the broadcaster-generated fee quote identifier.
    #[must_use]
    pub fn fees_id(&self) -> &str {
        &self.fees_id
    }

    /// Returns the broadcaster Railgun address.
    #[must_use]
    pub const fn railgun_address(&self) -> &RailgunAddress {
        &self.railgun_address
    }

    /// Returns the optional broadcaster identifier.
    #[must_use]
    pub fn identifier(&self) -> Option<&str> {
        self.identifier.as_deref()
    }

    /// Returns the current available-wallet count.
    #[must_use]
    pub const fn available_wallets(&self) -> u64 {
        self.available_wallets
    }

    /// Returns the broadcaster version string.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Returns the relay-adapt contract address string.
    #[must_use]
    pub fn relay_adapt(&self) -> &str {
        &self.relay_adapt
    }

    /// Returns the required POI list keys.
    #[must_use]
    pub fn required_poi_list_keys(&self) -> &[PoiListKey] {
        &self.required_poi_list_keys
    }

    /// Returns the broadcaster reliability score.
    #[must_use]
    pub const fn reliability(&self) -> f64 {
        self.reliability
    }
}

/// Parsed broadcaster fee-message envelope.
#[derive(Clone, Debug, PartialEq)]
pub struct BroadcasterFeeMessage {
    data: BroadcasterFeeMessageData,
    encoded_data: String,
    signature: String,
}

impl BroadcasterFeeMessage {
    /// Creates a parsed broadcaster fee-message envelope.
    #[must_use]
    pub fn new(data: BroadcasterFeeMessageData, encoded_data: String, signature: String) -> Self {
        Self { data, encoded_data, signature }
    }

    /// Returns the parsed fee-message data.
    #[must_use]
    pub const fn data(&self) -> &BroadcasterFeeMessageData {
        &self.data
    }

    /// Returns the exact canonical hex-encoded fee-message data string.
    #[must_use]
    pub fn encoded_data(&self) -> &str {
        &self.encoded_data
    }

    /// Returns the exact canonical signature hex string.
    #[must_use]
    pub fn signature(&self) -> &str {
        &self.signature
    }
}

fn validate_fee_message_data_fields(
    fees_id: &str,
    railgun_address: &RailgunAddress,
    version: &str,
    relay_adapt: &str,
) -> Result<(), BroadcasterError> {
    if fees_id.is_empty() {
        return Err(BroadcasterError::InvalidFeeMessageField("feesID must not be empty"));
    }
    if railgun_address.as_str().is_empty() {
        return Err(BroadcasterError::InvalidFeeMessageField("railgunAddress must not be empty"));
    }
    if version.is_empty() {
        return Err(BroadcasterError::InvalidFeeMessageField("version must not be empty"));
    }
    if relay_adapt.is_empty() {
        return Err(BroadcasterError::InvalidFeeMessageField("relayAdapt must not be empty"));
    }

    Ok(())
}

impl TryFrom<BroadcasterFeeMessageDataWire> for BroadcasterFeeMessageData {
    type Error = BroadcasterError;

    fn try_from(value: BroadcasterFeeMessageDataWire) -> Result<Self, Self::Error> {
        let railgun_address = RailgunAddress::parse(&value.railgun_address)
            .map_err(|_| BroadcasterError::InvalidFeeMessageField("railgunAddress is invalid"))?;
        validate_fee_message_data_fields(
            &value.fees_id,
            &railgun_address,
            &value.version,
            &value.relay_adapt,
        )?;
        let required_poi_list_keys = value
            .required_poi_list_keys
            .iter()
            .map(|list_key| {
                PoiListKey::parse(list_key).map_err(|_| {
                    BroadcasterError::InvalidFeeMessageField(
                        "requiredPOIListKeys must contain canonical 32-byte hex keys",
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Self::new(BroadcasterFeeMessageDataFields {
            fees: value.fees,
            fee_expiration: value.fee_expiration,
            fees_id: value.fees_id,
            railgun_address,
            identifier: value.identifier,
            available_wallets: value.available_wallets,
            version: value.version,
            relay_adapt: value.relay_adapt,
            required_poi_list_keys,
            reliability: value.reliability,
        })
    }
}

impl From<&BroadcasterFeeMessageData> for BroadcasterFeeMessageDataWire {
    fn from(value: &BroadcasterFeeMessageData) -> Self {
        Self {
            fees: value.fees().clone(),
            fee_expiration: value.fee_expiration(),
            fees_id: value.fees_id().to_owned(),
            railgun_address: value.railgun_address().as_str().to_owned(),
            identifier: value.identifier().map(ToOwned::to_owned),
            available_wallets: value.available_wallets(),
            version: value.version().to_owned(),
            relay_adapt: value.relay_adapt().to_owned(),
            required_poi_list_keys: value
                .required_poi_list_keys()
                .iter()
                .map(ToString::to_string)
                .collect(),
            reliability: value.reliability(),
        }
    }
}

fn decode_hex(value: &str) -> Result<Vec<u8>, BroadcasterError> {
    let trimmed = value.strip_prefix("0x").unwrap_or(value);
    hex::decode(trimmed).map_err(|_| BroadcasterError::InvalidFeeMessageDataHex)
}

fn decode_signature(value: &str) -> Result<Signature, BroadcasterError> {
    let trimmed = value.strip_prefix("0x").unwrap_or(value);
    let bytes = hex::decode(trimmed).map_err(|_| BroadcasterError::InvalidFeeMessageSignature)?;
    let array: [u8; 64] =
        bytes.try_into().map_err(|_| BroadcasterError::InvalidFeeMessageSignature)?;
    Ok(Signature::from_bytes(&array))
}

/// Parses the outer broadcaster fee-message JSON envelope without validating the
/// inner data payload.
///
/// # Errors
///
/// Returns an error if the envelope JSON is malformed or missing required fields.
pub fn parse_fee_message_wire(payload: &str) -> Result<(String, String), BroadcasterError> {
    let wire: BroadcasterFeeMessageWire =
        serde_json::from_str(payload).map_err(|_| BroadcasterError::InvalidFeeMessagePayload)?;
    if wire.data.is_empty() {
        return Err(BroadcasterError::InvalidFeeMessage("data must not be empty"));
    }
    if wire.signature.is_empty() {
        return Err(BroadcasterError::InvalidFeeMessage("signature must not be empty"));
    }
    Ok((wire.data, wire.signature))
}

/// Parses canonical broadcaster fee-message data from a hex-encoded UTF-8 JSON string.
///
/// # Errors
///
/// Returns an error if the data hex cannot be decoded, is not valid UTF-8, or
/// does not match the canonical fee-message shape.
pub fn parse_fee_message_data(
    encoded_data: &str,
) -> Result<BroadcasterFeeMessageData, BroadcasterError> {
    let bytes = decode_hex(encoded_data)?;
    let utf8 = String::from_utf8(bytes).map_err(|_| BroadcasterError::InvalidFeeMessageDataUtf8)?;
    let wire: BroadcasterFeeMessageDataWire =
        serde_json::from_str(&utf8).map_err(|_| BroadcasterError::InvalidFeeMessageDataJson)?;
    wire.try_into()
}

/// Parses a canonical broadcaster fee-message payload into a typed envelope.
///
/// # Errors
///
/// Returns an error if the outer envelope or inner fee-message data is malformed.
pub fn parse_fee_message_payload(payload: &str) -> Result<BroadcasterFeeMessage, BroadcasterError> {
    let (encoded_data, signature) = parse_fee_message_wire(payload)?;
    let data = parse_fee_message_data(&encoded_data)?;
    Ok(BroadcasterFeeMessage::new(data, encoded_data, signature))
}

/// Serializes canonical broadcaster fee-message data into the exact hex-encoded
/// UTF-8 JSON string used as signing input.
///
/// # Errors
///
/// Returns an error if serialization fails unexpectedly.
pub fn serialize_fee_message_data(
    data: &BroadcasterFeeMessageData,
) -> Result<String, BroadcasterError> {
    let json = serde_json::to_string(&BroadcasterFeeMessageDataWire::from(data))
        .map_err(|_| BroadcasterError::InvalidFeeMessageDataJson)?;
    Ok(format!("0x{}", hex::encode(json.as_bytes())))
}

/// Signs canonical broadcaster fee-message data into a typed fee-message envelope.
///
/// # Errors
///
/// Returns an error if canonical fee-message data serialization fails.
pub fn sign_fee_message(
    data: &BroadcasterFeeMessageData,
    viewing_private_key: &ViewingPrivateKey,
) -> Result<BroadcasterFeeMessage, BroadcasterError> {
    let encoded_data = serialize_fee_message_data(data)?;
    let decoded_data = decode_hex(&encoded_data)?;
    let signature = SigningKey::from_bytes(viewing_private_key.as_bytes()).sign(&decoded_data);

    Ok(BroadcasterFeeMessage::new(
        data.clone(),
        encoded_data,
        format!("0x{}", hex::encode(signature.to_bytes())),
    ))
}

/// Verifies the broadcaster fee-message signature against the broadcaster identity.
///
/// The signed bytes are the decoded bytes represented by the canonical hex
/// `data` string carried by the envelope, matching upstream broadcaster
/// behavior.
///
/// # Errors
///
/// Returns an error if the broadcaster address, signature, or signature check is invalid.
pub fn verify_fee_message_signature(
    message: &BroadcasterFeeMessage,
) -> Result<(), BroadcasterError> {
    let decoded_address = decode_railgun_address(message.data.railgun_address().as_str())
        .map_err(|_| BroadcasterError::InvalidFeeMessageField("railgunAddress is invalid"))?;
    let verifying_key = VerifyingKey::from_bytes(decoded_address.viewing_public_key().as_bytes())
        .map_err(|_| {
        BroadcasterError::InvalidFeeMessageField("railgunAddress viewing key is invalid")
    })?;
    let signature = decode_signature(message.signature())?;
    let decoded_data = decode_hex(message.encoded_data())?;
    verifying_key
        .verify(&decoded_data, &signature)
        .map_err(|_| BroadcasterError::InvalidFeeMessageSignatureVerification)
}

/// Validates fee-quote freshness against an explicit validation time.
///
/// # Errors
///
/// Returns an error if the fee quote expired before `validation_time`.
pub fn validate_fee_message_at(
    data: &BroadcasterFeeMessageData,
    validation_time: u64,
) -> Result<(), BroadcasterError> {
    if data.fee_expiration() < validation_time {
        return Err(BroadcasterError::ExpiredFeeQuote {
            fee_expiration: data.fee_expiration(),
            validation_time,
        });
    }
    Ok(())
}

/// Verifies the broadcaster fee-message signature and expiry.
///
/// # Errors
///
/// Returns an error if signature verification fails or the quote is stale.
pub fn validate_fee_message(
    message: &BroadcasterFeeMessage,
    validation_time: u64,
) -> Result<(), BroadcasterError> {
    verify_fee_message_signature(message)?;
    validate_fee_message_at(message.data(), validation_time)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use ed25519_dalek::{Signer, SigningKey};
    use railgun_core::{derive_viewing_public_key, encode_railgun_address};
    use railgun_poi::PoiListKey;
    use railgun_types::{ChainScope, MasterPublicKey, ViewingPrivateKey};

    use super::{
        BroadcasterError, BroadcasterFeeMessageData, BroadcasterFeeMessageDataFields,
        BroadcasterFeeMessageDataWire, decode_hex, parse_fee_message_data,
        parse_fee_message_payload, serialize_fee_message_data, sign_fee_message,
        validate_fee_message, validate_fee_message_at, verify_fee_message_signature,
    };
    use crate::serialize_fee_message_payload;

    fn sample_fee_message_data() -> BroadcasterFeeMessageData {
        let viewing_private_key = ViewingPrivateKey::new([7_u8; 32]);
        let viewing_public_key = derive_viewing_public_key(&viewing_private_key);
        let railgun_address = encode_railgun_address(
            1,
            &MasterPublicKey::new(1_u8.into())
                .unwrap_or_else(|error| panic!("test master public key should validate: {error}")),
            ChainScope::AllChains,
            &viewing_public_key,
        )
        .unwrap_or_else(|error| panic!("test railgun address should encode: {error}"));

        let mut fees = BTreeMap::new();
        fees.insert("0x12345".to_owned(), "0x0de0b6b3a7640000".to_owned());

        BroadcasterFeeMessageData::new(BroadcasterFeeMessageDataFields {
            fees,
            fee_expiration: 1_800_000_000_000,
            fees_id: "fees-cache-id".to_owned(),
            railgun_address,
            identifier: Some("test-broadcaster".to_owned()),
            available_wallets: 4,
            version: "0.1.0".to_owned(),
            relay_adapt: "0x1111111111111111111111111111111111111111".to_owned(),
            required_poi_list_keys: vec![
                PoiListKey::parse(
                    "efc6ddb59c098a13fb2b618fdae94c1c3a807abc8fb1837c93620c9143ee9e88",
                )
                .unwrap_or_else(|error| panic!("test list key should parse: {error}")),
            ],
            reliability: 0.92,
        })
        .unwrap_or_else(|error| panic!("test fee data should construct: {error}"))
    }

    fn sample_fee_message_json() -> String {
        let viewing_private_key = ViewingPrivateKey::new([7_u8; 32]);
        let data = sample_fee_message_data();
        let encoded_data = serialize_fee_message_data(&data)
            .unwrap_or_else(|error| panic!("test fee data should serialize: {error}"));
        let decoded_data = decode_hex(&encoded_data)
            .unwrap_or_else(|error| panic!("data hex should decode: {error}"));
        let signature = SigningKey::from_bytes(viewing_private_key.as_bytes()).sign(&decoded_data);

        serde_json::json!({
            "data": encoded_data,
            "signature": format!("0x{}", hex::encode(signature.to_bytes())),
        })
        .to_string()
    }

    #[test]
    fn parses_fee_message_payload_and_preserves_fields() {
        let payload = sample_fee_message_json();
        let message = parse_fee_message_payload(&payload)
            .unwrap_or_else(|error| panic!("fee message should parse: {error}"));

        assert_eq!(message.data().fees().get("0x12345"), Some(&"0x0de0b6b3a7640000".to_owned()));
        assert_eq!(message.data().fee_expiration(), 1_800_000_000_000);
        assert_eq!(message.data().fees_id(), "fees-cache-id");
        assert_eq!(message.data().identifier(), Some("test-broadcaster"));
        assert_eq!(message.data().available_wallets(), 4);
        assert_eq!(message.data().version(), "0.1.0");
        assert_eq!(message.data().relay_adapt(), "0x1111111111111111111111111111111111111111");
        assert_eq!(message.data().required_poi_list_keys().len(), 1);
        assert!((message.data().reliability() - 0.92).abs() < f64::EPSILON);
    }

    #[test]
    fn verifies_fee_message_signature() {
        let payload = sample_fee_message_json();
        let message = parse_fee_message_payload(&payload)
            .unwrap_or_else(|error| panic!("fee message should parse: {error}"));

        verify_fee_message_signature(&message)
            .unwrap_or_else(|error| panic!("signature should verify: {error}"));
    }

    #[test]
    fn rejects_expired_fee_message() {
        let payload = sample_fee_message_json();
        let message = parse_fee_message_payload(&payload)
            .unwrap_or_else(|error| panic!("fee message should parse: {error}"));

        let Err(error) = validate_fee_message_at(message.data(), 1_800_000_000_001) else {
            panic!("expired fee message should fail");
        };
        assert_eq!(
            error,
            BroadcasterError::ExpiredFeeQuote {
                fee_expiration: 1_800_000_000_000,
                validation_time: 1_800_000_000_001,
            }
        );
    }

    #[test]
    fn rejects_invalid_signature() {
        let payload = sample_fee_message_json();
        let mut value: serde_json::Value = serde_json::from_str(&payload)
            .unwrap_or_else(|error| panic!("test payload should parse: {error}"));
        value["signature"] = serde_json::Value::String(format!("0x{}", "11".repeat(64)));

        let message = parse_fee_message_payload(&value.to_string())
            .unwrap_or_else(|error| panic!("mutated fee message should still parse: {error}"));
        let Err(error) = verify_fee_message_signature(&message) else {
            panic!("invalid signature should fail");
        };
        assert_eq!(error, BroadcasterError::InvalidFeeMessageSignatureVerification);
    }

    #[test]
    fn rejects_invalid_required_poi_list_key() {
        let mut data: BroadcasterFeeMessageDataWire = serde_json::from_str(
            &String::from_utf8(
                hex::decode(
                    serde_json::from_str::<serde_json::Value>(&sample_fee_message_json())
                        .unwrap_or_else(|error| panic!("payload should parse: {error}"))["data"]
                        .as_str()
                        .unwrap_or_else(|| panic!("data should be a string"))
                        .trim_start_matches("0x"),
                )
                .unwrap_or_else(|error| panic!("data hex should decode: {error}")),
            )
            .unwrap_or_else(|error| panic!("data bytes should be utf8: {error}")),
        )
        .unwrap_or_else(|error| panic!("data json should parse: {error}"));
        data.required_poi_list_keys = vec!["not-a-real-key".to_owned()];

        let encoded_data = format!(
            "0x{}",
            hex::encode(
                serde_json::to_string(&data)
                    .unwrap_or_else(|error| panic!("mutated data should serialize: {error}"))
            )
        );
        let Err(error) = parse_fee_message_data(&encoded_data) else {
            panic!("invalid required POI list key should fail");
        };
        assert_eq!(
            error,
            BroadcasterError::InvalidFeeMessageField(
                "requiredPOIListKeys must contain canonical 32-byte hex keys",
            )
        );
    }

    #[test]
    fn rejects_malformed_payload_json() {
        let Err(error) = parse_fee_message_payload("not-json") else {
            panic!("malformed payload should fail");
        };
        assert_eq!(error, BroadcasterError::InvalidFeeMessagePayload);
    }

    #[test]
    fn validates_signature_and_expiry_together() {
        let payload = sample_fee_message_json();
        let message = parse_fee_message_payload(&payload)
            .unwrap_or_else(|error| panic!("fee message should parse: {error}"));

        validate_fee_message(&message, 1_800_000_000_000)
            .unwrap_or_else(|error| panic!("fee message should validate: {error}"));
    }

    #[test]
    fn serializes_fee_message_data_deterministically() {
        let first = serialize_fee_message_data(&sample_fee_message_data())
            .unwrap_or_else(|error| panic!("first serialization should succeed: {error}"));
        let second = serialize_fee_message_data(&sample_fee_message_data())
            .unwrap_or_else(|error| panic!("second serialization should succeed: {error}"));

        assert_eq!(first, second);
    }

    #[test]
    fn omits_identifier_when_unset_during_serialization() {
        let sample = sample_fee_message_data();
        let data = BroadcasterFeeMessageData::new(BroadcasterFeeMessageDataFields {
            fees: sample.fees().clone(),
            fee_expiration: sample.fee_expiration(),
            fees_id: sample.fees_id().to_owned(),
            railgun_address: sample.railgun_address().clone(),
            identifier: None,
            available_wallets: sample.available_wallets(),
            version: sample.version().to_owned(),
            relay_adapt: sample.relay_adapt().to_owned(),
            required_poi_list_keys: sample.required_poi_list_keys().to_vec(),
            reliability: sample.reliability(),
        })
        .unwrap_or_else(|error| panic!("test fee data should construct: {error}"));

        let encoded_data = serialize_fee_message_data(&data)
            .unwrap_or_else(|error| panic!("fee data should serialize: {error}"));
        let decoded_data = String::from_utf8(
            decode_hex(&encoded_data)
                .unwrap_or_else(|error| panic!("data hex should decode: {error}")),
        )
        .unwrap_or_else(|error| panic!("decoded data should be utf8: {error}"));
        let value: serde_json::Value = serde_json::from_str(&decoded_data)
            .unwrap_or_else(|error| panic!("decoded data should be valid json: {error}"));

        assert!(value.get("identifier").is_none());
    }

    #[test]
    fn signed_fee_message_round_trips_and_verifies() {
        let viewing_private_key = ViewingPrivateKey::new([7_u8; 32]);
        let message = sign_fee_message(&sample_fee_message_data(), &viewing_private_key)
            .unwrap_or_else(|error| panic!("fee message should sign: {error}"));
        let payload = serialize_fee_message_payload(&message)
            .unwrap_or_else(|error| panic!("signed fee message should serialize: {error}"));
        let reparsed = parse_fee_message_payload(&payload)
            .unwrap_or_else(|error| panic!("signed fee message should parse: {error}"));

        verify_fee_message_signature(&reparsed)
            .unwrap_or_else(|error| panic!("signed fee message should verify: {error}"));
        assert_eq!(reparsed.data(), &sample_fee_message_data());
    }

    #[test]
    fn sign_fee_message_is_deterministic_for_identical_inputs() {
        let viewing_private_key = ViewingPrivateKey::new([7_u8; 32]);
        let first = sign_fee_message(&sample_fee_message_data(), &viewing_private_key)
            .unwrap_or_else(|error| panic!("first message should sign: {error}"));
        let second = sign_fee_message(&sample_fee_message_data(), &viewing_private_key)
            .unwrap_or_else(|error| panic!("second message should sign: {error}"));

        assert_eq!(first.encoded_data(), second.encoded_data());
        assert_eq!(first.signature(), second.signature());
    }

    #[test]
    fn sign_fee_message_matches_manual_decoded_byte_signing() {
        let viewing_private_key = ViewingPrivateKey::new([7_u8; 32]);
        let data = sample_fee_message_data();
        let encoded_data = serialize_fee_message_data(&data)
            .unwrap_or_else(|error| panic!("fee data should serialize: {error}"));
        let decoded_data = decode_hex(&encoded_data)
            .unwrap_or_else(|error| panic!("data hex should decode: {error}"));
        let expected_signature =
            SigningKey::from_bytes(viewing_private_key.as_bytes()).sign(&decoded_data);

        let message = sign_fee_message(&data, &viewing_private_key)
            .unwrap_or_else(|error| panic!("fee message should sign: {error}"));

        assert_eq!(message.encoded_data(), encoded_data);
        assert_eq!(
            message.signature(),
            format!("0x{}", hex::encode(expected_signature.to_bytes()))
        );
    }

    #[test]
    fn rejects_missing_required_field_during_construction() {
        let data = sample_fee_message_data();
        let Err(error) = BroadcasterFeeMessageData::new(BroadcasterFeeMessageDataFields {
            fees: data.fees().clone(),
            fee_expiration: data.fee_expiration(),
            fees_id: String::new(),
            railgun_address: data.railgun_address().clone(),
            identifier: data.identifier().map(ToOwned::to_owned),
            available_wallets: data.available_wallets(),
            version: data.version().to_owned(),
            relay_adapt: data.relay_adapt().to_owned(),
            required_poi_list_keys: data.required_poi_list_keys().to_vec(),
            reliability: data.reliability(),
        }) else {
            panic!("missing fees id should fail");
        };

        assert_eq!(error, BroadcasterError::InvalidFeeMessageField("feesID must not be empty"));
    }
}
