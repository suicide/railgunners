//! Canonical V3 bound params ABI encoding, decoding, and hash derivation.

use core::fmt;

use alloy_primitives::{Address as AlloyAddress, Bytes, FixedBytes};
use alloy_sol_types::{SolValue, sol};
use num_bigint::BigUint;
use railgun_types::{
    BoundParamsHash, ParseDomainError, V3BoundParams, V3BoundParamsGlobal, V3BoundParamsLocal,
    V3ChainId, V3MinGasPrice, bn254_scalar_field_modulus,
};
use sha3::{Digest, Keccak256};

use crate::{CommitmentCiphertextError, parse_commitment_ciphertext_v3};

sol! {
    struct CommitmentCiphertextV3Abi {
        bytes ciphertext;
        bytes32 blindedSenderViewingKey;
        bytes32 blindedReceiverViewingKey;
    }

    struct V3BoundParamsLocalAbi {
        uint32 treeNumber;
        CommitmentCiphertextV3Abi[] commitmentCiphertext;
    }

    struct V3BoundParamsGlobalAbi {
        uint128 minGasPrice;
        uint128 chainID;
        bytes senderCiphertext;
        address to;
        bytes data;
    }

    struct V3BoundParamsAbi {
        V3BoundParamsLocalAbi local;
        V3BoundParamsGlobalAbi global;
    }
}

/// Error returned when V3 bound params encoding, decoding, or hashing fails.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum V3BoundParamsError {
    /// ABI decoding failed or did not match the expected nested tuple shape.
    AbiDecodeFailed,
    /// A decoded field failed domain validation.
    InvalidDomainValue(String),
    /// A decoded local commitment ciphertext entry failed normalization.
    InvalidCommitmentCiphertext(CommitmentCiphertextError),
}

impl fmt::Display for V3BoundParamsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AbiDecodeFailed => {
                formatter.write_str("failed to decode v3 bound params abi payload")
            }
            Self::InvalidDomainValue(message) => formatter.write_str(message),
            Self::InvalidCommitmentCiphertext(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for V3BoundParamsError {}

fn biguint_to_32_bytes(value: &BigUint) -> [u8; 32] {
    let bytes = value.to_bytes_be();
    let mut padded = [0_u8; 32];
    let start = 32 - bytes.len();
    padded[start..].copy_from_slice(&bytes);
    padded
}

fn parse_domain_error(error: &ParseDomainError) -> V3BoundParamsError {
    V3BoundParamsError::InvalidDomainValue(error.to_string())
}

fn encode_commitment_ciphertext(
    commitment_ciphertext: &railgun_types::CommitmentCiphertextV3,
) -> CommitmentCiphertextV3Abi {
    let mut ciphertext = Vec::with_capacity(
        railgun_types::V3StoredNonce::LENGTH + commitment_ciphertext.bundle().len(),
    );
    // V3 local commitment ciphertext ABI stores the concatenated `nonce | bundle` payload.
    ciphertext.extend_from_slice(commitment_ciphertext.nonce().as_bytes());
    ciphertext.extend_from_slice(commitment_ciphertext.bundle());

    CommitmentCiphertextV3Abi {
        ciphertext: Bytes::from(ciphertext),
        blindedSenderViewingKey: FixedBytes::<32>::from(
            *commitment_ciphertext.blinded_sender_viewing_key().as_bytes(),
        ),
        blindedReceiverViewingKey: FixedBytes::<32>::from(
            *commitment_ciphertext.blinded_receiver_viewing_key().as_bytes(),
        ),
    }
}

fn decode_commitment_ciphertext(
    commitment_ciphertext: &CommitmentCiphertextV3Abi,
) -> Result<railgun_types::CommitmentCiphertextV3, V3BoundParamsError> {
    parse_commitment_ciphertext_v3(
        commitment_ciphertext.ciphertext.as_ref(),
        commitment_ciphertext.blindedSenderViewingKey.as_slice(),
        commitment_ciphertext.blindedReceiverViewingKey.as_slice(),
    )
    .map_err(V3BoundParamsError::InvalidCommitmentCiphertext)
}

fn to_abi(bound_params: &V3BoundParams) -> V3BoundParamsAbi {
    V3BoundParamsAbi {
        local: V3BoundParamsLocalAbi {
            treeNumber: bound_params.local().tree_number(),
            commitmentCiphertext: bound_params
                .local()
                .commitment_ciphertext()
                .iter()
                .map(encode_commitment_ciphertext)
                .collect(),
        },
        global: V3BoundParamsGlobalAbi {
            minGasPrice: bound_params.global().min_gas_price().get(),
            chainID: bound_params.global().chain_id().get(),
            senderCiphertext: Bytes::copy_from_slice(bound_params.global().sender_ciphertext()),
            to: AlloyAddress::from_slice(bound_params.global().to().as_bytes()),
            data: Bytes::copy_from_slice(bound_params.global().data()),
        },
    }
}

fn from_abi(bound_params: &V3BoundParamsAbi) -> Result<V3BoundParams, V3BoundParamsError> {
    let local = V3BoundParamsLocal::new(
        bound_params.local.treeNumber,
        bound_params
            .local
            .commitmentCiphertext
            .iter()
            .map(decode_commitment_ciphertext)
            .collect::<Result<Vec<_>, _>>()?,
    );
    let global = V3BoundParamsGlobal::new(
        V3MinGasPrice::new(bound_params.global.minGasPrice),
        V3ChainId::new(bound_params.global.chainID),
        bound_params.global.senderCiphertext.as_ref().to_vec(),
        railgun_types::Address::from_slice(bound_params.global.to.as_slice())
            .map_err(|error| parse_domain_error(&error))?,
        bound_params.global.data.as_ref().to_vec(),
    );

    Ok(V3BoundParams::new(local, global))
}

/// ABI-encodes canonical V3 bound params using the exact nested Solidity tuple layout.
#[must_use]
pub fn encode_v3_bound_params(bound_params: &V3BoundParams) -> Vec<u8> {
    to_abi(bound_params).abi_encode()
}

/// Decodes ABI-encoded V3 bound params back into the normalized domain model.
///
/// # Errors
///
/// Returns an error if the payload does not match the canonical V3 tuple shape or any decoded
/// field fails domain validation.
pub fn decode_v3_bound_params(bytes: &[u8]) -> Result<V3BoundParams, V3BoundParamsError> {
    let decoded = V3BoundParamsAbi::abi_decode(bytes, true)
        .map_err(|_| V3BoundParamsError::AbiDecodeFailed)?;
    from_abi(&decoded)
}

/// Derives the canonical V3 bound params hash as `keccak256(abi.encode(boundParams)) mod SNARK_PRIME`.
///
/// # Errors
///
/// Returns an error if an internal conversion from the typed domain model becomes invalid.
pub fn derive_v3_bound_params_hash(
    bound_params: &V3BoundParams,
) -> Result<BoundParamsHash, V3BoundParamsError> {
    let digest = Keccak256::digest(encode_v3_bound_params(bound_params));
    let reduced = BigUint::from_bytes_be(&digest) % bn254_scalar_field_modulus();
    BoundParamsHash::from_slice(&biguint_to_32_bytes(&reduced))
        .map_err(|error| parse_domain_error(&error))
}

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;
    use railgun_types::{
        Address, BlindedViewingPublicKey, V3BoundParams, V3BoundParamsGlobal, V3BoundParamsLocal,
        V3ChainId, V3CiphertextBundle, V3MinGasPrice, V3StoredNonce,
    };

    use super::{
        V3BoundParamsError, decode_v3_bound_params, derive_v3_bound_params_hash,
        encode_v3_bound_params,
    };

    fn zero_vector_bound_params() -> V3BoundParams {
        V3BoundParams::new(
            V3BoundParamsLocal::new(
                0,
                vec![railgun_types::CommitmentCiphertextV3::new(
                    V3CiphertextBundle::new(
                        V3StoredNonce::new([0_u8; 16]),
                        vec![0_u8; 112],
                        Vec::new(),
                    ),
                    BlindedViewingPublicKey::new([0_u8; 32]),
                    BlindedViewingPublicKey::new([0_u8; 32]),
                )],
            ),
            V3BoundParamsGlobal::new(
                V3MinGasPrice::new(1),
                V3ChainId::new(1),
                Vec::new(),
                Address::new([0_u8; 20]),
                Vec::new(),
            ),
        )
    }

    #[test]
    fn roundtrips_canonical_issue_vector() {
        let bound_params = zero_vector_bound_params();

        let encoded = encode_v3_bound_params(&bound_params);
        let decoded = decode_v3_bound_params(&encoded)
            .unwrap_or_else(|error| panic!("canonical v3 bound params should decode: {error}"));

        assert_eq!(decoded, bound_params);
    }

    #[test]
    fn derives_expected_hash_for_canonical_issue_vector() {
        let hash =
            derive_v3_bound_params_hash(&zero_vector_bound_params()).unwrap_or_else(|error| {
                panic!("canonical v3 bound params hash should derive: {error}")
            });

        assert_eq!(
            BigUint::from_bytes_be(hash.as_bytes()),
            BigUint::parse_bytes(
                b"1042853354636355096886642476862765074115784833677897463840889848516202023630",
                10,
            )
            .unwrap_or_else(|| panic!("expected decimal hash should parse"))
        );
    }

    #[test]
    fn preserves_empty_global_dynamic_fields() {
        let decoded = decode_v3_bound_params(&encode_v3_bound_params(&zero_vector_bound_params()))
            .unwrap_or_else(|error| panic!("v3 bound params should roundtrip: {error}"));

        assert!(decoded.global().sender_ciphertext().is_empty());
        assert!(decoded.global().data().is_empty());
    }

    #[test]
    fn preserves_local_nonce_bundle_concatenation() {
        let bound_params = V3BoundParams::new(
            V3BoundParamsLocal::new(
                7,
                vec![railgun_types::CommitmentCiphertextV3::new(
                    V3CiphertextBundle::new(
                        V3StoredNonce::new([1_u8; 16]),
                        vec![2_u8; 48],
                        Vec::new(),
                    ),
                    BlindedViewingPublicKey::new([3_u8; 32]),
                    BlindedViewingPublicKey::new([4_u8; 32]),
                )],
            ),
            V3BoundParamsGlobal::new(
                V3MinGasPrice::new(5),
                V3ChainId::new(6),
                vec![7_u8; 8],
                Address::new([8_u8; 20]),
                vec![9_u8; 10],
            ),
        );

        let decoded = decode_v3_bound_params(&encode_v3_bound_params(&bound_params))
            .unwrap_or_else(|error| panic!("v3 bound params should roundtrip: {error}"));

        assert_eq!(decoded.local().commitment_ciphertext()[0].nonce().as_bytes(), &[1_u8; 16]);
        assert_eq!(decoded.local().commitment_ciphertext()[0].bundle(), &[2_u8; 48]);
        assert_eq!(decoded.global().sender_ciphertext(), &[7_u8; 8]);
    }

    #[test]
    fn rejects_truncated_abi_payload() {
        let mut encoded = encode_v3_bound_params(&zero_vector_bound_params());
        encoded.pop();

        let Err(error) = decode_v3_bound_params(&encoded) else {
            panic!("truncated v3 abi payload should fail");
        };

        assert_eq!(error, V3BoundParamsError::AbiDecodeFailed);
    }
}
