use crate::{
    cli::AddressCommand,
    error::CliError,
    output::write_json,
    parse::{
        parse_address, parse_chain_scope, parse_master_public_key, parse_required_suffix,
        parse_viewing_public_key,
    },
    workflows::address::{DecodedAddress, decode_address, encode_address, validate_address},
    workflows::address_search::{AddressSearchMatch, AddressSearchOptions, search_lower_address},
};
use railgun_core::Bip39WordCount;
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
        AddressCommand::SearchLower {
            target_addresses,
            word_count,
            index,
            required_suffix,
            jobs,
            progress_every,
            max_attempts,
            show_secrets,
            json,
        } => {
            if !show_secrets {
                return Err(CliError::command(
                    "address search requires --show-secrets".to_owned(),
                    json,
                ));
            }

            let word_count = Bip39WordCount::try_from(word_count).map_err(|error| {
                CliError::command(format!("invalid --word-count value: {error}"), json)
            })?;
            let target_addresses = target_addresses
                .iter()
                .map(|address| parse_address(address, json))
                .collect::<Result<Vec<_>, _>>()?;
            let required_suffix = required_suffix
                .as_deref()
                .map(|suffix| parse_required_suffix(suffix, json))
                .transpose()?;
            let worker_count = jobs.unwrap_or_else(default_worker_count);
            if worker_count == 0 {
                return Err(CliError::command("--jobs must be at least 1".to_owned(), json));
            }

            let result = search_lower_address(
                AddressSearchOptions {
                    target_addresses,
                    word_count,
                    index,
                    required_suffix,
                    worker_count,
                    progress_every,
                    max_attempts,
                },
                json,
            )?;

            if json {
                write_json(stdout, &SearchLowerJson::from_match(&result))?;
            } else {
                write_text_search_lower(stdout, &result)?;
            }
        }
    }

    Ok(())
}

fn default_worker_count() -> usize {
    std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
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

fn write_text_search_lower(
    stdout: &mut dyn Write,
    result: &AddressSearchMatch,
) -> Result<(), CliError> {
    writeln!(stdout, "Found matching address after {} attempts.", result.attempts())?;
    writeln!(stdout, "minimumTargetAddress: {}", result.minimum_target_address().as_str())?;
    writeln!(stdout, "derivedAddress: {}", result.derived_address().as_str())?;
    writeln!(stdout, "mnemonic: {}", result.mnemonic())?;
    writeln!(stdout, "index: {}", result.index())?;
    writeln!(stdout, "wordCount: {}", result.word_count())?;
    if let Some(required_suffix) = result.required_suffix() {
        writeln!(stdout, "requiredSuffix: {required_suffix}")?;
    }
    writeln!(stdout, "viewingPrivateKey: {}", result.viewing_private_key_hex())?;
    writeln!(stdout, "packedSpendingPublicKey: {}", result.packed_spending_public_key_hex())?;
    writeln!(stdout, "shareableViewingKey: {}", result.shareable_viewing_key())?;
    writeln!(stdout, "workerCount: {}", result.worker_count())?;
    Ok(())
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

#[derive(Serialize)]
struct SearchLowerJson<'a> {
    #[serde(rename = "minimumTargetAddress")]
    minimum_target_address: &'a str,
    #[serde(rename = "derivedAddress")]
    derived_address: &'a str,
    mnemonic: &'a str,
    index: u32,
    #[serde(rename = "wordCount")]
    word_count: usize,
    #[serde(rename = "requiredSuffix", skip_serializing_if = "Option::is_none")]
    required_suffix: Option<&'a str>,
    #[serde(rename = "viewingPrivateKey")]
    viewing_private_key: &'a str,
    #[serde(rename = "packedSpendingPublicKey")]
    packed_spending_public_key: &'a str,
    #[serde(rename = "shareableViewingKey")]
    shareable_viewing_key: &'a str,
    attempts: u64,
    #[serde(rename = "workerCount")]
    worker_count: usize,
}

impl<'a> SearchLowerJson<'a> {
    fn from_match(result: &'a AddressSearchMatch) -> Self {
        Self {
            minimum_target_address: result.minimum_target_address().as_str(),
            derived_address: result.derived_address().as_str(),
            mnemonic: result.mnemonic(),
            index: result.index(),
            word_count: result.word_count(),
            required_suffix: result.required_suffix(),
            viewing_private_key: result.viewing_private_key_hex(),
            packed_spending_public_key: result.packed_spending_public_key_hex(),
            shareable_viewing_key: result.shareable_viewing_key(),
            attempts: result.attempts(),
            worker_count: result.worker_count(),
        }
    }
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

    #[test]
    fn search_lower_requires_show_secrets() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit_code = run(
            [
                "railguncli",
                "address",
                "search-lower",
                "--target-address",
                "0zk1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqunpd9kxwatwqyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqhshkca",
            ],
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(exit_code, 1);
        assert!(stdout.is_empty());
        assert_eq!(String::from_utf8_lossy(&stderr), "address search requires --show-secrets\n");
    }

    #[test]
    fn search_lower_rejects_invalid_required_suffix() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit_code = run(
            [
                "railguncli",
                "address",
                "search-lower",
                "--target-address",
                "0zk1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqunpd9kxwatwqyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqhshkca",
                "--required-suffix",
                "0zk1bad",
                "--show-secrets",
            ],
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(exit_code, 1);
        assert!(stdout.is_empty());
        assert_eq!(
            String::from_utf8_lossy(&stderr),
            "invalid required suffix: suffix must use only Bech32 lowercase payload characters and must not include the 0zk1 prefix\n"
        );
    }

    #[test]
    fn search_lower_reports_capped_failure_as_json() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit_code = run(
            [
                "railguncli",
                "address",
                "search-lower",
                "--target-address",
                "0zk1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqunpd9kxwatwqyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqhshkca",
                "--max-attempts",
                "0",
                "--show-secrets",
                "--json",
            ],
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(exit_code, 1);
        assert_eq!(
            String::from_utf8_lossy(&stdout),
            "{\"error\":\"no matching address found in 0 attempts\"}\n"
        );
        assert!(stderr.is_empty());
    }
}
