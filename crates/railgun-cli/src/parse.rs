use num_bigint::BigUint;
use railgun_types::{
    ChainScope, ChainType, MasterPublicKey, PackedSpendingPublicKey, RailgunChain,
    SpendingPrivateKey, ViewingPrivateKey, ViewingPublicKey,
};

use crate::error::CliError;

pub(crate) fn parse_hex<const N: usize>(
    value: &str,
    label: &str,
    json: bool,
) -> Result<[u8; N], CliError> {
    let bytes = hex::decode(value).map_err(|_| {
        CliError::command(format!("invalid {label}: expected lowercase or uppercase hex"), json)
    })?;
    bytes.try_into().map_err(|_: Vec<u8>| {
        CliError::command(format!("invalid {label}: expected {N} bytes"), json)
    })
}

pub(crate) fn parse_viewing_private_key(
    value: &str,
    json: bool,
) -> Result<ViewingPrivateKey, CliError> {
    let bytes = parse_hex::<32>(value, "viewing private key", json)?;
    Ok(ViewingPrivateKey::new(bytes))
}

pub(crate) fn parse_spending_private_key(
    value: &str,
    json: bool,
) -> Result<SpendingPrivateKey, CliError> {
    let bytes = parse_hex::<32>(value, "spending private key", json)?;
    Ok(SpendingPrivateKey::new(bytes))
}

pub(crate) fn parse_packed_spending_public_key(
    value: &str,
    json: bool,
) -> Result<PackedSpendingPublicKey, CliError> {
    let bytes = parse_hex::<32>(value, "packed spending public key", json)?;
    Ok(PackedSpendingPublicKey::new(bytes))
}

pub(crate) fn parse_viewing_public_key(
    value: &str,
    json: bool,
) -> Result<ViewingPublicKey, CliError> {
    let bytes = parse_hex::<32>(value, "viewing public key", json)?;
    Ok(ViewingPublicKey::new(bytes))
}

pub(crate) fn parse_master_public_key(
    value: &str,
    json: bool,
) -> Result<MasterPublicKey, CliError> {
    let bytes = parse_hex::<32>(value, "master public key", json)?;
    MasterPublicKey::new(BigUint::from_bytes_be(&bytes))
        .map_err(|error| CliError::command(error.to_string(), json))
}

pub(crate) fn parse_decimal_biguint(
    value: &str,
    label: &str,
    json: bool,
) -> Result<BigUint, CliError> {
    BigUint::parse_bytes(value.as_bytes(), 10).ok_or_else(|| {
        CliError::command(format!("invalid {label}: expected unsigned decimal"), json)
    })
}

pub(crate) fn parse_chain_scope(
    chain_type: Option<u8>,
    chain_id: Option<u64>,
    json: bool,
) -> Result<ChainScope, CliError> {
    match (chain_type, chain_id) {
        (None, None) => Ok(ChainScope::AllChains),
        (Some(chain_type), Some(chain_id)) => {
            let chain =
                RailgunChain::new(ChainType::new(chain_type), chain_id).map_err(|error| {
                    CliError::command(format!("invalid chain selection: {error}"), json)
                })?;
            Ok(ChainScope::Chain(chain))
        }
        _ => Err(CliError::command(
            "chain selection requires both --chain-type and --chain-id".to_owned(),
            json,
        )),
    }
}
