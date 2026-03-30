use crate::{
    cli::AddressCommand,
    error::CliError,
    output::write_json,
    parse::{parse_chain_scope, parse_master_public_key, parse_viewing_public_key},
    workflows::address::{DecodedAddress, decode_address, encode_address, validate_address},
};
use railgun_types::ChainScope;
use serde::Serialize;
use std::io::Write;

pub(crate) fn execute(command: AddressCommand, stdout: &mut dyn Write) -> Result<(), CliError> {
    match command {
        AddressCommand::Encode {
            version,
            master_public_key,
            chain_type,
            chain_id,
            viewing_public_key,
            json,
        } => {
            let master_public_key = parse_master_public_key(&master_public_key, json)?;
            let viewing_public_key = parse_viewing_public_key(&viewing_public_key, json)?;
            let chain_scope = parse_chain_scope(chain_type, chain_id, json)?;
            let address =
                encode_address(version, &master_public_key, chain_scope, &viewing_public_key)
                    .map_err(|error| CliError::command(error.to_string(), json))?;

            if json {
                write_json(stdout, &EncodedAddressJson { address: address.as_str() })?;
            } else {
                writeln!(stdout, "{}", address.as_str())?;
            }
        }
        AddressCommand::Decode { address, json } => {
            let decoded = decode_address(&address)
                .map_err(|error| CliError::command(error.to_string(), json))?;

            if json {
                write_json(stdout, &DecodedAddressJson::from_decoded(&decoded))?;
            } else {
                write_text_decoded(stdout, &decoded)?;
            }
        }
        AddressCommand::Validate { address, json } => match validate_address(&address) {
            Ok(decoded) => {
                if json {
                    write_json(stdout, &ValidatedAddressJson::from_decoded(&decoded))?;
                } else {
                    writeln!(stdout, "valid")?;
                }
            }
            Err(error) => {
                if json {
                    return Err(CliError::RawJson(serde_json::to_string(&ValidationErrorJson {
                        valid: false,
                        error: error.to_string(),
                    })?));
                }
                return Err(CliError::command(error.to_string(), false));
            }
        },
    }

    Ok(())
}

fn write_text_decoded(stdout: &mut dyn Write, decoded: &DecodedAddress) -> Result<(), CliError> {
    writeln!(stdout, "version: {}", decoded.version())?;
    writeln!(stdout, "masterPublicKey: {}", format_master_public_key_hex(decoded))?;
    writeln!(stdout, "networkID: {}", decoded.network_id_hex())?;
    writeln!(stdout, "viewingPublicKey: {}", hex::encode(decoded.viewing_public_key().as_bytes()))?;
    match decoded.chain_scope() {
        ChainScope::AllChains => writeln!(stdout, "chainScope: all-chains")?,
        ChainScope::Chain(chain) => {
            writeln!(stdout, "chainScope.type: chain")?;
            writeln!(stdout, "chainScope.chainType: {}", chain.chain_type().get())?;
            writeln!(stdout, "chainScope.chainId: {}", chain.chain_id())?;
        }
    }
    Ok(())
}

fn format_master_public_key_hex(decoded: &DecodedAddress) -> String {
    let bytes = decoded.master_public_key().value().to_bytes_be();
    let mut padded = [0_u8; 32];
    let offset = padded.len() - bytes.len();
    padded[offset..].copy_from_slice(&bytes);
    hex::encode(padded)
}

#[derive(Serialize)]
struct EncodedAddressJson<'a> {
    address: &'a str,
}

#[derive(Serialize)]
struct ChainScopeJson {
    #[serde(rename = "type")]
    kind: &'static str,
    #[serde(rename = "chainType", skip_serializing_if = "Option::is_none")]
    chain_type: Option<u8>,
    #[serde(rename = "chainId", skip_serializing_if = "Option::is_none")]
    chain_id: Option<u64>,
}

impl ChainScopeJson {
    fn from_chain_scope(chain_scope: ChainScope) -> Self {
        match chain_scope {
            ChainScope::AllChains => Self { kind: "all-chains", chain_type: None, chain_id: None },
            ChainScope::Chain(chain) => Self {
                kind: "chain",
                chain_type: Some(chain.chain_type().get()),
                chain_id: Some(chain.chain_id()),
            },
        }
    }
}

#[derive(Serialize)]
struct DecodedAddressJson {
    version: u8,
    #[serde(rename = "masterPublicKey")]
    master_public_key: String,
    #[serde(rename = "networkID")]
    network_id: String,
    #[serde(rename = "viewingPublicKey")]
    viewing_public_key: String,
    #[serde(rename = "chainScope")]
    chain_scope: ChainScopeJson,
}

impl DecodedAddressJson {
    fn from_decoded(decoded: &DecodedAddress) -> Self {
        Self {
            version: decoded.version(),
            master_public_key: format_master_public_key_hex(decoded),
            network_id: decoded.network_id_hex().to_owned(),
            viewing_public_key: hex::encode(decoded.viewing_public_key().as_bytes()),
            chain_scope: ChainScopeJson::from_chain_scope(decoded.chain_scope()),
        }
    }
}

#[derive(Serialize)]
struct ValidatedAddressJson {
    valid: bool,
    version: u8,
    #[serde(rename = "masterPublicKey")]
    master_public_key: String,
    #[serde(rename = "networkID")]
    network_id: String,
    #[serde(rename = "viewingPublicKey")]
    viewing_public_key: String,
    #[serde(rename = "chainScope")]
    chain_scope: ChainScopeJson,
}

impl ValidatedAddressJson {
    fn from_decoded(decoded: &DecodedAddress) -> Self {
        Self {
            valid: true,
            version: decoded.version(),
            master_public_key: format_master_public_key_hex(decoded),
            network_id: decoded.network_id_hex().to_owned(),
            viewing_public_key: hex::encode(decoded.viewing_public_key().as_bytes()),
            chain_scope: ChainScopeJson::from_chain_scope(decoded.chain_scope()),
        }
    }
}

#[derive(Serialize)]
struct ValidationErrorJson {
    valid: bool,
    error: String,
}

#[cfg(test)]
mod tests {
    use crate::run;

    #[test]
    fn encodes_vector_one_with_defaults_as_json() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit_code = run(
            [
                "railguncli",
                "address",
                "encode",
                "--master-public-key",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "--chain-type",
                "0",
                "--chain-id",
                "1",
                "--viewing-public-key",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "--json",
            ],
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(exit_code, 0);
        assert_eq!(
            String::from_utf8_lossy(&stdout),
            "{\"address\":\"0zk1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqunpd9kxwatwqyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqhshkca\"}\n"
        );
        assert!(stderr.is_empty());
    }

    #[test]
    fn decodes_vector_one_as_json() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit_code = run(
            [
                "railguncli",
                "address",
                "decode",
                "--address",
                "0zk1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqunpd9kxwatwqyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqhshkca",
                "--json",
            ],
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(exit_code, 0);
        assert_eq!(
            String::from_utf8_lossy(&stdout),
            "{\"version\":1,\"masterPublicKey\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"networkID\":\"7261696c67756e01\",\"viewingPublicKey\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"chainScope\":{\"type\":\"chain\",\"chainType\":0,\"chainId\":1}}\n"
        );
        assert!(stderr.is_empty());
    }

    #[test]
    fn validates_and_rejects_invalid_checksum_vector() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit_code = run(
            [
                "railguncli",
                "address",
                "validate",
                "--address",
                "rgany1pnj7u66vwqhcquxgmh4pewutpa4y55vtwlag60umdpshkej92rn47ey76ges3t3enn",
                "--json",
            ],
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(exit_code, 1);
        assert_eq!(
            String::from_utf8_lossy(&stdout),
            "{\"valid\":false,\"error\":\"invalid bech32m address\"}\n"
        );
        assert!(stderr.is_empty());
    }

    #[test]
    fn encode_defaults_to_all_chains() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit_code = run(
            [
                "railguncli",
                "address",
                "encode",
                "--master-public-key",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "--viewing-public-key",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "--json",
            ],
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(exit_code, 0);
        assert!(String::from_utf8_lossy(&stdout).contains("\"address\":\"0zk1"));
        assert!(stderr.is_empty());
    }

    #[test]
    fn rejects_partial_chain_override() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit_code = run(
            [
                "railguncli",
                "address",
                "encode",
                "--master-public-key",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "--chain-type",
                "0",
                "--viewing-public-key",
                "0000000000000000000000000000000000000000000000000000000000000000",
            ],
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(exit_code, 1);
        assert!(stdout.is_empty());
        assert_eq!(
            String::from_utf8_lossy(&stderr),
            "chain selection requires both --chain-type and --chain-id\n"
        );
    }
}
