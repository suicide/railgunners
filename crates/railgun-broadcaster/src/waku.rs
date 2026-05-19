use railgun_types::{BlindedViewingPublicKey, TxHash};
use serde::{Deserialize, Serialize};

use crate::{BroadcasterError, BroadcasterFeeMessage};

/// Canonical encrypted broadcaster payload tuple.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BroadcasterEncryptedData([String; 2]);

impl BroadcasterEncryptedData {
    /// Creates a canonical encrypted broadcaster payload tuple.
    #[must_use]
    pub const fn new(parts: [String; 2]) -> Self {
        Self(parts)
    }

    /// Returns the encrypted payload tuple in canonical order.
    #[must_use]
    pub const fn parts(&self) -> &[String; 2] {
        &self.0
    }
}

/// Transport-neutral broadcaster transact envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BroadcasterTransactEnvelope {
    pubkey: BlindedViewingPublicKey,
    encrypted_data: BroadcasterEncryptedData,
}

impl BroadcasterTransactEnvelope {
    /// Creates a validated broadcaster transact envelope.
    #[must_use]
    pub const fn new(
        pubkey: BlindedViewingPublicKey,
        encrypted_data: BroadcasterEncryptedData,
    ) -> Self {
        Self { pubkey, encrypted_data }
    }

    /// Returns the blinded envelope public key.
    #[must_use]
    pub const fn pubkey(&self) -> &BlindedViewingPublicKey {
        &self.pubkey
    }

    /// Returns the encrypted payload tuple.
    #[must_use]
    pub const fn encrypted_data(&self) -> &BroadcasterEncryptedData {
        &self.encrypted_data
    }
}

/// Transport-neutral broadcaster transact response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BroadcasterTransactResponse {
    id: String,
    tx_hash: Option<TxHash>,
    error: Option<String>,
}

impl BroadcasterTransactResponse {
    /// Creates a validated broadcaster transact response.
    ///
    /// # Errors
    ///
    /// Returns an error if `id` is empty or if the response carries neither or
    /// both of `tx_hash` and `error`.
    pub fn new(
        id: String,
        tx_hash: Option<TxHash>,
        error: Option<String>,
    ) -> Result<Self, BroadcasterError> {
        if id.is_empty() {
            return Err(BroadcasterError::InvalidTransactResponsePayload(
                "broadcaster transact response id must not be empty",
            ));
        }
        if tx_hash.is_some() == error.is_some() {
            return Err(BroadcasterError::InvalidTransactResponsePayload(
                "broadcaster transact response must contain exactly one of txHash or error",
            ));
        }

        Ok(Self { id, tx_hash, error })
    }

    /// Returns the response identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the transaction hash when present.
    #[must_use]
    pub const fn tx_hash(&self) -> Option<&TxHash> {
        self.tx_hash.as_ref()
    }

    /// Returns the broadcaster error string when present.
    #[must_use]
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct BroadcasterFeeMessageWire {
    data: String,
    signature: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct BroadcasterTransactEnvelopeWire {
    method: String,
    params: BroadcasterTransactEnvelopeParamsWire,
}

#[derive(Debug, Deserialize, Serialize)]
struct BroadcasterTransactEnvelopeParamsWire {
    pubkey: String,
    #[serde(rename = "encryptedData")]
    encrypted_data: [String; 2],
}

#[derive(Debug, Deserialize, Serialize)]
struct BroadcasterTransactResponseWire {
    id: String,
    #[serde(rename = "txHash")]
    tx_hash: Option<String>,
    error: Option<String>,
}

fn decode_hex_exact<const N: usize>(value: &str) -> Result<[u8; N], BroadcasterError> {
    let trimmed = value.strip_prefix("0x").unwrap_or(value);
    let bytes = hex::decode(trimmed).map_err(|_| {
        BroadcasterError::InvalidTransactResponsePayload(
            "expected canonical fixed-width hex encoding",
        )
    })?;
    bytes.try_into().map_err(|_| {
        BroadcasterError::InvalidTransactResponsePayload(
            "expected canonical fixed-width hex encoding",
        )
    })
}

fn parse_blinded_pubkey(value: &str) -> Result<BlindedViewingPublicKey, BroadcasterError> {
    let trimmed = value.strip_prefix("0x").unwrap_or(value);
    let bytes =
        hex::decode(trimmed).map_err(|_| BroadcasterError::InvalidTransactEnvelopePubkey)?;
    BlindedViewingPublicKey::from_slice(&bytes)
        .map_err(|_| BroadcasterError::InvalidTransactEnvelopePubkey)
}

fn encode_blinded_pubkey(value: &BlindedViewingPublicKey) -> String {
    format!("0x{}", hex::encode(value.as_bytes()))
}

fn parse_tx_hash(value: &str) -> Result<TxHash, BroadcasterError> {
    Ok(TxHash::new(decode_hex_exact::<32>(value)?))
}

fn encode_tx_hash(value: &TxHash) -> String {
    format!("0x{}", hex::encode(value.as_bytes()))
}

impl From<&BroadcasterFeeMessage> for BroadcasterFeeMessageWire {
    fn from(value: &BroadcasterFeeMessage) -> Self {
        Self { data: value.encoded_data().to_owned(), signature: value.signature().to_owned() }
    }
}

impl TryFrom<BroadcasterTransactEnvelopeWire> for BroadcasterTransactEnvelope {
    type Error = BroadcasterError;

    fn try_from(value: BroadcasterTransactEnvelopeWire) -> Result<Self, Self::Error> {
        if value.method != "transact" {
            return Err(BroadcasterError::InvalidTransactEnvelopePayload(
                "broadcaster transact envelope method must be 'transact'",
            ));
        }

        Ok(Self::new(
            parse_blinded_pubkey(&value.params.pubkey)?,
            BroadcasterEncryptedData::new(value.params.encrypted_data),
        ))
    }
}

impl From<&BroadcasterTransactEnvelope> for BroadcasterTransactEnvelopeWire {
    fn from(value: &BroadcasterTransactEnvelope) -> Self {
        Self {
            method: "transact".to_owned(),
            params: BroadcasterTransactEnvelopeParamsWire {
                pubkey: encode_blinded_pubkey(value.pubkey()),
                encrypted_data: value.encrypted_data().parts().clone(),
            },
        }
    }
}

impl TryFrom<BroadcasterTransactResponseWire> for BroadcasterTransactResponse {
    type Error = BroadcasterError;

    fn try_from(value: BroadcasterTransactResponseWire) -> Result<Self, Self::Error> {
        let tx_hash = value.tx_hash.as_deref().map(parse_tx_hash).transpose()?;
        Self::new(value.id, tx_hash, value.error)
    }
}

impl From<&BroadcasterTransactResponse> for BroadcasterTransactResponseWire {
    fn from(value: &BroadcasterTransactResponse) -> Self {
        Self {
            id: value.id().to_owned(),
            tx_hash: value.tx_hash().map(encode_tx_hash),
            error: value.error().map(ToOwned::to_owned),
        }
    }
}

/// Serializes a broadcaster fee-message payload into canonical JSON.
///
/// # Errors
///
/// Returns an error if serialization fails unexpectedly.
pub fn serialize_fee_message_payload(
    payload: &BroadcasterFeeMessage,
) -> Result<String, BroadcasterError> {
    serde_json::to_string(&BroadcasterFeeMessageWire::from(payload))
        .map_err(|_| BroadcasterError::InvalidFeeMessagePayload)
}

/// Parses a broadcaster transact envelope payload.
///
/// # Errors
///
/// Returns an error if the envelope JSON or validated fields are malformed.
pub fn parse_transact_envelope_payload(
    payload: &str,
) -> Result<BroadcasterTransactEnvelope, BroadcasterError> {
    let wire: BroadcasterTransactEnvelopeWire = serde_json::from_str(payload)
        .map_err(|_| BroadcasterError::InvalidTransactEnvelopePayloadJson)?;
    wire.try_into()
}

/// Serializes a broadcaster transact envelope payload into canonical JSON.
///
/// # Errors
///
/// Returns an error if serialization fails unexpectedly.
pub fn serialize_transact_envelope_payload(
    payload: &BroadcasterTransactEnvelope,
) -> Result<String, BroadcasterError> {
    serde_json::to_string(&BroadcasterTransactEnvelopeWire::from(payload))
        .map_err(|_| BroadcasterError::InvalidTransactEnvelopePayloadJson)
}

/// Parses a broadcaster transact response payload.
///
/// # Errors
///
/// Returns an error if the response JSON or validated fields are malformed.
pub fn parse_transact_response_payload(
    payload: &str,
) -> Result<BroadcasterTransactResponse, BroadcasterError> {
    let wire: BroadcasterTransactResponseWire = serde_json::from_str(payload)
        .map_err(|_| BroadcasterError::InvalidTransactResponsePayloadJson)?;
    wire.try_into()
}

/// Serializes a broadcaster transact response payload into canonical JSON.
///
/// # Errors
///
/// Returns an error if serialization fails unexpectedly.
pub fn serialize_transact_response_payload(
    payload: &BroadcasterTransactResponse,
) -> Result<String, BroadcasterError> {
    serde_json::to_string(&BroadcasterTransactResponseWire::from(payload))
        .map_err(|_| BroadcasterError::InvalidTransactResponsePayloadJson)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use ed25519_dalek::{Signer, SigningKey};
    use railgun_core::{derive_viewing_public_key, encode_railgun_address};
    use railgun_types::{
        BlindedViewingPublicKey, ChainScope, MasterPublicKey, TxHash, ViewingPrivateKey,
    };
    use serde::{Deserialize, Serialize};

    use super::{
        BroadcasterEncryptedData, BroadcasterTransactEnvelope, BroadcasterTransactResponse,
        parse_transact_envelope_payload, parse_transact_response_payload,
        serialize_fee_message_payload, serialize_transact_envelope_payload,
        serialize_transact_response_payload,
    };
    use crate::{BroadcasterError, parse_fee_message_payload};

    #[derive(Debug, Deserialize, Serialize)]
    struct BroadcasterFeeMessageDataWire {
        fees: BTreeMap<String, String>,
        #[serde(rename = "feeExpiration")]
        fee_expiration: u64,
        #[serde(rename = "feesID")]
        fees_id: String,
        #[serde(rename = "railgunAddress")]
        railgun_address: String,
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

    fn sample_fee_message() -> crate::BroadcasterFeeMessage {
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

        let data = BroadcasterFeeMessageDataWire {
            fees,
            fee_expiration: 1_800_000_000_000,
            fees_id: "fees-cache-id".to_owned(),
            railgun_address: railgun_address.as_str().to_owned(),
            identifier: Some("test-broadcaster".to_owned()),
            available_wallets: 4,
            version: "0.1.0".to_owned(),
            relay_adapt: "0x1111111111111111111111111111111111111111".to_owned(),
            required_poi_list_keys: vec![
                "efc6ddb59c098a13fb2b618fdae94c1c3a807abc8fb1837c93620c9143ee9e88".to_owned(),
            ],
            reliability: 0.92,
        };
        let data_json = serde_json::to_string(&data)
            .unwrap_or_else(|error| panic!("test fee data should serialize: {error}"));
        let encoded_data = format!("0x{}", hex::encode(data_json.as_bytes()));
        let signature =
            SigningKey::from_bytes(viewing_private_key.as_bytes()).sign(encoded_data.as_bytes());

        parse_fee_message_payload(
            &serde_json::json!({
                "data": encoded_data,
                "signature": format!("0x{}", hex::encode(signature.to_bytes())),
            })
            .to_string(),
        )
        .unwrap_or_else(|error| panic!("sample fee message should parse: {error}"))
    }

    #[test]
    fn fee_message_round_trips() {
        let payload = sample_fee_message();
        let serialized = serialize_fee_message_payload(&payload)
            .unwrap_or_else(|error| panic!("fee message should serialize: {error}"));
        let reparsed = parse_fee_message_payload(&serialized)
            .unwrap_or_else(|error| panic!("fee message should parse: {error}"));

        assert_eq!(reparsed, payload);
    }

    #[test]
    fn transact_envelope_round_trips_with_canonical_fields() {
        let payload = BroadcasterTransactEnvelope::new(
            BlindedViewingPublicKey::new([9_u8; 32]),
            BroadcasterEncryptedData::new(["ciphertext".to_owned(), "ivtag".to_owned()]),
        );
        let serialized = serialize_transact_envelope_payload(&payload)
            .unwrap_or_else(|error| panic!("envelope should serialize: {error}"));
        let reparsed = parse_transact_envelope_payload(&serialized)
            .unwrap_or_else(|error| panic!("envelope should parse: {error}"));
        let json: serde_json::Value = serde_json::from_str(&serialized)
            .unwrap_or_else(|error| panic!("envelope json should parse: {error}"));

        assert_eq!(reparsed, payload);
        assert_eq!(json["method"], "transact");
        assert_eq!(json["params"]["pubkey"], format!("0x{}", "09".repeat(32)));
        assert_eq!(json["params"]["encryptedData"][0], "ciphertext");
        assert_eq!(json["params"]["encryptedData"][1], "ivtag");
    }

    #[test]
    fn transact_response_with_tx_hash_round_trips() {
        let payload = BroadcasterTransactResponse::new(
            "request-1".to_owned(),
            Some(TxHash::new([5_u8; 32])),
            None,
        )
        .unwrap_or_else(|error| panic!("response should construct: {error}"));
        let serialized = serialize_transact_response_payload(&payload)
            .unwrap_or_else(|error| panic!("response should serialize: {error}"));
        let reparsed = parse_transact_response_payload(&serialized)
            .unwrap_or_else(|error| panic!("response should parse: {error}"));

        assert_eq!(reparsed, payload);
    }

    #[test]
    fn transact_response_with_error_round_trips() {
        let payload = BroadcasterTransactResponse::new(
            "request-2".to_owned(),
            None,
            Some("failed to submit".to_owned()),
        )
        .unwrap_or_else(|error| panic!("response should construct: {error}"));
        let serialized = serialize_transact_response_payload(&payload)
            .unwrap_or_else(|error| panic!("response should serialize: {error}"));
        let reparsed = parse_transact_response_payload(&serialized)
            .unwrap_or_else(|error| panic!("response should parse: {error}"));

        assert_eq!(reparsed, payload);
    }

    #[test]
    fn rejects_wrong_transact_method() {
        let Err(error) = parse_transact_envelope_payload(
            &serde_json::json!({
                "method": "fee",
                "params": {
                    "pubkey": format!("0x{}", "09".repeat(32)),
                    "encryptedData": ["ciphertext", "ivtag"]
                }
            })
            .to_string(),
        ) else {
            panic!("wrong method should fail");
        };

        assert_eq!(
            error,
            BroadcasterError::InvalidTransactEnvelopePayload(
                "broadcaster transact envelope method must be 'transact'",
            )
        );
    }

    #[test]
    fn rejects_invalid_encrypted_data_tuple_shape() {
        let Err(error) = parse_transact_envelope_payload(
            &serde_json::json!({
                "method": "transact",
                "params": {
                    "pubkey": format!("0x{}", "09".repeat(32)),
                    "encryptedData": ["only-one"]
                }
            })
            .to_string(),
        ) else {
            panic!("invalid tuple shape should fail");
        };

        assert_eq!(error, BroadcasterError::InvalidTransactEnvelopePayloadJson);
    }

    #[test]
    fn rejects_invalid_response_shape() {
        let Err(error) = parse_transact_response_payload(
            &serde_json::json!({
                "id": "request-3",
                "txHash": format!("0x{}", "05".repeat(32)),
                "error": "also set"
            })
            .to_string(),
        ) else {
            panic!("invalid response should fail");
        };

        assert_eq!(
            error,
            BroadcasterError::InvalidTransactResponsePayload(
                "broadcaster transact response must contain exactly one of txHash or error",
            )
        );
    }

    #[test]
    fn rejects_missing_response_id() {
        let Err(error) = parse_transact_response_payload(
            &serde_json::json!({
                "id": "",
                "error": "failed"
            })
            .to_string(),
        ) else {
            panic!("missing response id should fail");
        };

        assert_eq!(
            error,
            BroadcasterError::InvalidTransactResponsePayload(
                "broadcaster transact response id must not be empty",
            )
        );
    }
}
