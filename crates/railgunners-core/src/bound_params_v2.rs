//! Canonical V2 bound params ABI encoding, decoding, and hash derivation.

use core::fmt;

use alloy_primitives::{Address as AlloyAddress, Bytes, FixedBytes, aliases::U48};
use alloy_sol_types::{SolValue, sol};
use num_bigint::BigUint;
use railgunners_types::{
    AdaptParams, BoundParamsHash, MinGasPrice, ParseDomainError, V2BoundParams, V2UnshieldFlag,
    bn254_scalar_field_modulus,
};
use sha3::{Digest, Keccak256};

use crate::{CommitmentCiphertextError, parse_commitment_ciphertext_v2};

sol! {
    struct CommitmentCiphertextV2Abi {
        bytes32[4] ciphertext;
        bytes32 blindedSenderViewingKey;
        bytes32 blindedReceiverViewingKey;
        bytes annotationData;
        bytes memo;
    }

    struct V2BoundParamsAbi {
        uint16 treeNumber;
        uint48 minGasPrice;
        uint8 unshield;
        uint64 chainID;
        address adaptContract;
        bytes32 adaptParams;
        CommitmentCiphertextV2Abi[] commitmentCiphertext;
    }
}

/// Error returned when V2 bound params encoding, decoding, or hashing fails.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum V2BoundParamsError {
    /// `minGasPrice` was not valid for a Solidity `uint48`.
    InvalidMinGasPrice,
    /// `unshield` was not one of the canonical V2 flag values.
    InvalidUnshieldFlag,
    /// ABI decoding failed or did not match the expected tuple shape.
    AbiDecodeFailed,
    /// A decoded field failed domain validation.
    InvalidDomainValue(String),
    /// A decoded commitment ciphertext entry failed normalization.
    InvalidCommitmentCiphertext(CommitmentCiphertextError),
}

impl fmt::Display for V2BoundParamsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMinGasPrice => {
                formatter.write_str("invalid v2 bound params min gas price")
            }
            Self::InvalidUnshieldFlag => {
                formatter.write_str("invalid v2 bound params unshield flag")
            }
            Self::AbiDecodeFailed => {
                formatter.write_str("failed to decode v2 bound params abi payload")
            }
            Self::InvalidDomainValue(message) => formatter.write_str(message),
            Self::InvalidCommitmentCiphertext(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for V2BoundParamsError {}

fn biguint_to_32_bytes(value: &BigUint) -> [u8; 32] {
    let bytes = value.to_bytes_be();
    let mut padded = [0_u8; 32];
    let start = 32 - bytes.len();
    padded[start..].copy_from_slice(&bytes);
    padded
}

fn parse_domain_error(error: &ParseDomainError) -> V2BoundParamsError {
    V2BoundParamsError::InvalidDomainValue(error.to_string())
}

fn parse_min_gas_price(value: u64) -> Result<MinGasPrice, V2BoundParamsError> {
    MinGasPrice::new(value).map_err(|_| V2BoundParamsError::InvalidMinGasPrice)
}

fn parse_unshield_flag(value: u8) -> Result<V2UnshieldFlag, V2BoundParamsError> {
    V2UnshieldFlag::try_from(value).map_err(|_| V2BoundParamsError::InvalidUnshieldFlag)
}

fn encode_commitment_ciphertext(
    commitment_ciphertext: &railgunners_types::CommitmentCiphertextV2,
) -> CommitmentCiphertextV2Abi {
    let ciphertext = [
        FixedBytes::<32>::from(*commitment_ciphertext.ciphertext().iv_tag().as_bytes()),
        FixedBytes::<32>::from(*commitment_ciphertext.ciphertext().data()[0].as_bytes()),
        FixedBytes::<32>::from(*commitment_ciphertext.ciphertext().data()[1].as_bytes()),
        FixedBytes::<32>::from(*commitment_ciphertext.ciphertext().data()[2].as_bytes()),
    ];

    CommitmentCiphertextV2Abi {
        // The first word must remain the packed `iv | tag` header to match the canonical V2
        // Solidity tuple layout used by upstream transaction hashing.
        ciphertext,
        blindedSenderViewingKey: FixedBytes::<32>::from(
            *commitment_ciphertext.blinded_sender_viewing_key().as_bytes(),
        ),
        blindedReceiverViewingKey: FixedBytes::<32>::from(
            *commitment_ciphertext.blinded_receiver_viewing_key().as_bytes(),
        ),
        annotationData: Bytes::copy_from_slice(
            commitment_ciphertext.ciphertext().annotation_data(),
        ),
        memo: Bytes::copy_from_slice(commitment_ciphertext.ciphertext().memo()),
    }
}

fn decode_commitment_ciphertext(
    commitment_ciphertext: &CommitmentCiphertextV2Abi,
) -> Result<railgunners_types::CommitmentCiphertextV2, V2BoundParamsError> {
    let ciphertext_words = [
        commitment_ciphertext.ciphertext[0].as_slice(),
        commitment_ciphertext.ciphertext[1].as_slice(),
        commitment_ciphertext.ciphertext[2].as_slice(),
        commitment_ciphertext.ciphertext[3].as_slice(),
    ];

    parse_commitment_ciphertext_v2(
        &ciphertext_words,
        commitment_ciphertext.blindedSenderViewingKey.as_slice(),
        commitment_ciphertext.blindedReceiverViewingKey.as_slice(),
        commitment_ciphertext.annotationData.as_ref(),
        commitment_ciphertext.memo.as_ref(),
    )
    .map_err(V2BoundParamsError::InvalidCommitmentCiphertext)
}

fn to_abi(bound_params: &V2BoundParams) -> V2BoundParamsAbi {
    V2BoundParamsAbi {
        treeNumber: bound_params.tree_number(),
        minGasPrice: U48::from(bound_params.min_gas_price().get()),
        unshield: bound_params.unshield().as_u8(),
        chainID: bound_params.chain_id().get(),
        adaptContract: AlloyAddress::from_slice(bound_params.adapt_contract().as_bytes()),
        adaptParams: FixedBytes::<32>::from(*bound_params.adapt_params().as_bytes()),
        commitmentCiphertext: bound_params
            .commitment_ciphertext()
            .iter()
            .map(encode_commitment_ciphertext)
            .collect(),
    }
}

fn from_abi(bound_params: &V2BoundParamsAbi) -> Result<V2BoundParams, V2BoundParamsError> {
    let min_gas_price = parse_min_gas_price(bound_params.minGasPrice.to::<u64>())?;
    let unshield = parse_unshield_flag(bound_params.unshield)?;
    let chain_id = railgunners_types::ChainId::new(bound_params.chainID)
        .map_err(|error| parse_domain_error(&error))?;
    let adapt_params = AdaptParams::from_slice(bound_params.adaptParams.as_slice())
        .map_err(|error| parse_domain_error(&error))?;
    let commitment_ciphertext = bound_params
        .commitmentCiphertext
        .iter()
        .map(decode_commitment_ciphertext)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(V2BoundParams::new(
        bound_params.treeNumber,
        min_gas_price,
        unshield,
        chain_id,
        railgunners_types::Address::from_slice(bound_params.adaptContract.as_slice())
            .map_err(|error| parse_domain_error(&error))?,
        adapt_params,
        commitment_ciphertext,
    ))
}

/// ABI-encodes canonical V2 bound params using the exact Solidity tuple layout.
#[must_use]
pub fn encode_v2_bound_params(bound_params: &V2BoundParams) -> Vec<u8> {
    to_abi(bound_params).abi_encode()
}

/// Decodes ABI-encoded V2 bound params back into the normalized domain model.
///
/// # Errors
///
/// Returns an error if the payload does not match the canonical V2 tuple shape or any decoded
/// field fails domain validation.
pub fn decode_v2_bound_params(bytes: &[u8]) -> Result<V2BoundParams, V2BoundParamsError> {
    let decoded = V2BoundParamsAbi::abi_decode_validate(bytes)
        .map_err(|_| V2BoundParamsError::AbiDecodeFailed)?;
    let bound_params = from_abi(&decoded)?;

    if encode_v2_bound_params(&bound_params) == bytes {
        Ok(bound_params)
    } else {
        Err(V2BoundParamsError::AbiDecodeFailed)
    }
}

/// Derives the canonical V2 bound params hash as `keccak256(abi.encode(boundParams)) mod SNARK_PRIME`.
///
/// # Errors
///
/// Returns an error if an internal conversion from the typed domain model becomes invalid.
pub fn derive_v2_bound_params_hash(
    bound_params: &V2BoundParams,
) -> Result<BoundParamsHash, V2BoundParamsError> {
    let digest = Keccak256::digest(encode_v2_bound_params(bound_params));
    let reduced = BigUint::from_bytes_be(&digest) % bn254_scalar_field_modulus();
    BoundParamsHash::from_slice(&biguint_to_32_bytes(&reduced))
        .map_err(|error| parse_domain_error(&error))
}

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;
    use railgunners_types::{
        AdaptParams, Address, BlindedViewingPublicKey, MinGasPrice, ParseDomainError,
        V2BoundParams, V2CiphertextBlock, V2CiphertextBundle, V2UnshieldFlag,
    };

    use super::{
        V2BoundParamsError, decode_v2_bound_params, derive_v2_bound_params_hash,
        encode_v2_bound_params,
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

    fn zero_vector_bound_params() -> V2BoundParams {
        let commitment_ciphertext = railgunners_types::CommitmentCiphertextV2::new(
            V2CiphertextBundle::new(
                V2CiphertextBlock::new([0_u8; 32]),
                [
                    V2CiphertextBlock::new([0_u8; 32]),
                    V2CiphertextBlock::new([0_u8; 32]),
                    V2CiphertextBlock::new([0_u8; 32]),
                ],
                vec![0_u8],
                vec![0_u8],
            ),
            BlindedViewingPublicKey::new([0_u8; 32]),
            BlindedViewingPublicKey::new([0_u8; 32]),
        );

        V2BoundParams::new(
            0,
            MinGasPrice::new(3000).unwrap_or_else(|_| panic!("min gas price should be valid")),
            V2UnshieldFlag::None,
            railgunners_types::ChainId::new(1)
                .unwrap_or_else(|_| panic!("chain id should be valid")),
            Address::new([0_u8; 20]),
            AdaptParams::new([0_u8; 32]),
            vec![commitment_ciphertext],
        )
    }

    #[test]
    fn roundtrips_canonical_issue_vector() {
        let bound_params = zero_vector_bound_params();

        let encoded = encode_v2_bound_params(&bound_params);
        let decoded = decode_v2_bound_params(&encoded)
            .unwrap_or_else(|error| panic!("canonical bound params should decode: {error}"));

        assert_eq!(decoded, bound_params);
    }

    #[test]
    fn derives_expected_hash_for_canonical_issue_vector() {
        let hash = derive_v2_bound_params_hash(&zero_vector_bound_params())
            .unwrap_or_else(|error| panic!("canonical bound params hash should derive: {error}"));

        assert_eq!(
            BigUint::from_bytes_be(hash.as_bytes()),
            BigUint::parse_bytes(
                b"7297316625290769368067090402207718021912518614094704642142032948132837136470",
                10,
            )
            .unwrap_or_else(|| panic!("expected decimal hash should parse"))
        );
    }

    #[test]
    fn preserves_empty_dynamic_fields() {
        let commitment_ciphertext = railgunners_types::CommitmentCiphertextV2::new(
            V2CiphertextBundle::new(
                V2CiphertextBlock::new([1_u8; 32]),
                [
                    V2CiphertextBlock::new([2_u8; 32]),
                    V2CiphertextBlock::new([3_u8; 32]),
                    V2CiphertextBlock::new([4_u8; 32]),
                ],
                Vec::new(),
                Vec::new(),
            ),
            BlindedViewingPublicKey::new([5_u8; 32]),
            BlindedViewingPublicKey::new([6_u8; 32]),
        );
        let bound_params = V2BoundParams::new(
            9,
            MinGasPrice::new(77).unwrap_or_else(|_| panic!("min gas price should be valid")),
            V2UnshieldFlag::Override,
            railgunners_types::ChainId::new(1)
                .unwrap_or_else(|_| panic!("chain id should be valid")),
            Address::new([7_u8; 20]),
            AdaptParams::new([8_u8; 32]),
            vec![commitment_ciphertext],
        );

        let decoded = decode_v2_bound_params(&encode_v2_bound_params(&bound_params))
            .unwrap_or_else(|error| panic!("bound params should roundtrip: {error}"));

        assert!(decoded.commitment_ciphertext()[0].ciphertext().annotation_data().is_empty());
        assert!(decoded.commitment_ciphertext()[0].ciphertext().memo().is_empty());
    }

    #[test]
    fn preserves_normalized_v2_ciphertext_word_order() {
        let bound_params = V2BoundParams::new(
            0,
            MinGasPrice::new(1).unwrap_or_else(|_| panic!("min gas price should be valid")),
            V2UnshieldFlag::Unshield,
            railgunners_types::ChainId::new(1)
                .unwrap_or_else(|_| panic!("chain id should be valid")),
            Address::new([0_u8; 20]),
            AdaptParams::new([0_u8; 32]),
            vec![railgunners_types::CommitmentCiphertextV2::new(
                V2CiphertextBundle::new(
                    V2CiphertextBlock::new(decode_hex::<32>(
                        "0xba002e1e01f1d63d7fa06c83880b2bef23063903d3f4a2b8f7eb800f6c45491c",
                    )),
                    [
                        V2CiphertextBlock::new(decode_hex::<32>(
                            "0x8687c2941bddfc807aa3512ebef36e889a82f3885383877e55b7f86e488b6360",
                        )),
                        V2CiphertextBlock::new(decode_hex::<32>(
                            "0x40521d04c766273db030a1ee070706493383f26b8fd677cb51acf0fd30682a37",
                        )),
                        V2CiphertextBlock::new(decode_hex::<32>(
                            "0x6588e860594d6709193c391b4e79de12cecdaed31eef71a2894af5729c0209f7",
                        )),
                    ],
                    vec![0xaa, 0xbb],
                    vec![0xcc],
                ),
                BlindedViewingPublicKey::new([9_u8; 32]),
                BlindedViewingPublicKey::new([10_u8; 32]),
            )],
        );

        let decoded = decode_v2_bound_params(&encode_v2_bound_params(&bound_params))
            .unwrap_or_else(|error| panic!("bound params should roundtrip: {error}"));

        assert_eq!(
            decoded.commitment_ciphertext()[0].ciphertext().iv_tag().as_bytes(),
            bound_params.commitment_ciphertext()[0].ciphertext().iv_tag().as_bytes()
        );
        assert_eq!(
            decoded.commitment_ciphertext()[0].ciphertext().data(),
            bound_params.commitment_ciphertext()[0].ciphertext().data()
        );
    }

    #[test]
    fn rejects_truncated_abi_payload() {
        let mut encoded = encode_v2_bound_params(&zero_vector_bound_params());
        encoded.pop();

        let Err(error) = decode_v2_bound_params(&encoded) else {
            panic!("truncated abi payload should fail");
        };

        assert_eq!(error, V2BoundParamsError::AbiDecodeFailed);
    }

    #[test]
    fn invalid_domain_error_message_is_stable() {
        let error = ParseDomainError::new("address must be exactly 20 bytes");
        assert_eq!(error.to_string(), "address must be exactly 20 bytes");
    }
}
