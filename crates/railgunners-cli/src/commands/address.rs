use crate::{
    cli::{AddressCommand, SearchSeedModeArg},
    error::CliError,
    output::write_json,
    parse::{
        parse_address, parse_chain_scope, parse_master_public_key, parse_prefix, parse_suffix,
        parse_viewing_public_key,
    },
    workflows::address::{DecodedAddress, decode_address, encode_address, validate_address},
    workflows::address_search::{
        AddressSearchMatch, AddressSearchOptions, SearchSeedMode, search_address,
    },
};
use railgunners_core::Bip39WordCount;
use railgunners_types::ChainScope;
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
        } => execute_encode(
            stdout,
            version,
            &master_public_key,
            chain_type,
            chain_id,
            &viewing_public_key,
            json,
        )?,
        AddressCommand::Decode { address, json } => execute_decode(stdout, &address, json)?,
        AddressCommand::Validate { address, json } => execute_validate(stdout, &address, json)?,
        AddressCommand::Search {
            lower_than_addresses,
            leading_zeroes,
            seed_mode,
            word_count,
            index,
            prefix,
            suffix,
            jobs,
            progress_every,
            max_attempts,
            show_secrets,
            json,
        } => execute_search(
            stdout,
            &lower_than_addresses,
            leading_zeroes,
            seed_mode,
            word_count,
            index,
            prefix.as_deref(),
            suffix.as_deref(),
            jobs,
            progress_every,
            max_attempts,
            show_secrets,
            json,
        )?,
    }

    Ok(())
}

fn execute_encode(
    stdout: &mut dyn Write,
    version: u8,
    master_public_key: &str,
    chain_type: Option<u8>,
    chain_id: Option<u64>,
    viewing_public_key: &str,
    json: bool,
) -> Result<(), CliError> {
    let master_public_key = parse_master_public_key(master_public_key, json)?;
    let viewing_public_key = parse_viewing_public_key(viewing_public_key, json)?;
    let chain_scope = parse_chain_scope(chain_type, chain_id, json)?;
    let address = encode_address(version, &master_public_key, chain_scope, &viewing_public_key)
        .map_err(|error| CliError::command(error.to_string(), json))?;

    if json {
        write_json(stdout, &EncodedAddressJson { address: address.as_str() })?;
    } else {
        writeln!(stdout, "{}", address.as_str())?;
    }

    Ok(())
}

fn execute_decode(stdout: &mut dyn Write, address: &str, json: bool) -> Result<(), CliError> {
    let decoded =
        decode_address(address).map_err(|error| CliError::command(error.to_string(), json))?;

    if json {
        write_json(stdout, &DecodedAddressJson::from_decoded(&decoded))?;
    } else {
        write_text_decoded(stdout, &decoded)?;
    }

    Ok(())
}

fn execute_validate(stdout: &mut dyn Write, address: &str, json: bool) -> Result<(), CliError> {
    match validate_address(address) {
        Ok(decoded) => {
            if json {
                write_json(stdout, &ValidatedAddressJson::from_decoded(&decoded))?;
            } else {
                writeln!(stdout, "valid")?;
            }
            Ok(())
        }
        Err(error) => {
            if json {
                return Err(CliError::RawJson(serde_json::to_string(&ValidationErrorJson {
                    valid: false,
                    error: error.to_string(),
                })?));
            }
            Err(CliError::command(error.to_string(), false))
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn execute_search(
    stdout: &mut dyn Write,
    lower_than_addresses: &[String],
    leading_zeroes: Option<usize>,
    seed_mode: SearchSeedModeArg,
    word_count: usize,
    index: u32,
    prefix: Option<&str>,
    suffix: Option<&str>,
    jobs: Option<usize>,
    progress_every: u64,
    max_attempts: Option<u64>,
    show_secrets: bool,
    json: bool,
) -> Result<(), CliError> {
    if !show_secrets {
        return Err(CliError::command("address search requires --show-secrets".to_owned(), json));
    }

    let word_count = Bip39WordCount::try_from(word_count)
        .map_err(|error| CliError::command(format!("invalid --word-count value: {error}"), json))?;
    let lower_than_addresses = lower_than_addresses
        .iter()
        .map(|address| parse_address(address, json))
        .collect::<Result<Vec<_>, _>>()?;
    let prefix = prefix.map(|value| parse_prefix(value, json)).transpose()?;
    let suffix = suffix.map(|value| parse_suffix(value, json)).transpose()?;
    if lower_than_addresses.is_empty()
        && leading_zeroes.is_none()
        && prefix.is_none()
        && suffix.is_none()
    {
        return Err(CliError::command(
            "at least one of --lower-than, --leading-zeroes, --prefix, or --suffix is required"
                .to_owned(),
            json,
        ));
    }

    let worker_count = jobs.unwrap_or_else(default_worker_count);
    if worker_count == 0 {
        return Err(CliError::command("--jobs must be at least 1".to_owned(), json));
    }

    let result = search_address(
        AddressSearchOptions {
            lower_than_addresses,
            leading_zeroes,
            seed_mode: match seed_mode {
                SearchSeedModeArg::Bip39 => SearchSeedMode::Bip39,
                SearchSeedModeArg::Raw => SearchSeedMode::Raw,
            },
            word_count,
            index,
            prefix,
            suffix,
            worker_count,
            progress_every,
            max_attempts,
        },
        json,
    )?;

    if json {
        write_json(stdout, &SearchJson::from_match(&result))?;
    } else {
        write_text_search(stdout, &result)?;
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

fn write_text_search(stdout: &mut dyn Write, result: &AddressSearchMatch) -> Result<(), CliError> {
    writeln!(stdout, "Found matching address after {} attempts.", result.attempts())?;
    if let Some(minimum_lower_than_address) = result.minimum_lower_than_address() {
        writeln!(stdout, "minimumLowerThanAddress: {}", minimum_lower_than_address.as_str())?;
    }
    writeln!(stdout, "derivedAddress: {}", result.derived_address().as_str())?;
    writeln!(stdout, "seedMode: {}", result.seed_mode().as_str())?;
    if let Some(mnemonic) = result.mnemonic() {
        writeln!(stdout, "mnemonic: {mnemonic}")?;
    }
    if let Some(raw_seed_hex) = result.raw_seed_hex() {
        writeln!(stdout, "rawSeed: {raw_seed_hex}")?;
    }
    writeln!(stdout, "index: {}", result.index())?;
    if let Some(word_count) = result.word_count() {
        writeln!(stdout, "wordCount: {word_count}")?;
    }
    if let Some(prefix) = result.prefix() {
        writeln!(stdout, "prefix: {prefix}")?;
    }
    if let Some(leading_zeroes) = result.leading_zeroes() {
        writeln!(stdout, "leadingZeroes: {leading_zeroes}")?;
    }
    if let Some(suffix) = result.suffix() {
        writeln!(stdout, "suffix: {suffix}")?;
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
struct SearchJson<'a> {
    #[serde(rename = "minimumLowerThanAddress", skip_serializing_if = "Option::is_none")]
    minimum_lower_than_address: Option<&'a str>,
    #[serde(rename = "derivedAddress")]
    derived_address: &'a str,
    #[serde(rename = "seedMode")]
    seed_mode: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    mnemonic: Option<&'a str>,
    #[serde(rename = "rawSeed", skip_serializing_if = "Option::is_none")]
    raw_seed_hex: Option<&'a str>,
    index: u32,
    #[serde(rename = "wordCount", skip_serializing_if = "Option::is_none")]
    word_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    prefix: Option<&'a str>,
    #[serde(rename = "leadingZeroes", skip_serializing_if = "Option::is_none")]
    leading_zeroes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    suffix: Option<&'a str>,
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

impl<'a> SearchJson<'a> {
    fn from_match(result: &'a AddressSearchMatch) -> Self {
        Self {
            minimum_lower_than_address: result
                .minimum_lower_than_address()
                .map(railgunners_types::RailgunAddress::as_str),
            derived_address: result.derived_address().as_str(),
            seed_mode: result.seed_mode().as_str(),
            mnemonic: result.mnemonic(),
            raw_seed_hex: result.raw_seed_hex(),
            index: result.index(),
            word_count: result.word_count(),
            prefix: result.prefix(),
            leading_zeroes: result.leading_zeroes(),
            suffix: result.suffix(),
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
    use railgunners_types::RailgunAddress;

    use crate::run;

    fn sample_lower_than() -> &'static str {
        "0zk1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqunpd9kxwatwqyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqhshkca"
    }

    fn sample_prefix() -> String {
        let address = RailgunAddress::parse(sample_lower_than())
            .unwrap_or_else(|_| panic!("sample lower-than address should parse"));
        address
            .as_str()
            .strip_prefix("0zk1qy")
            .unwrap_or_else(|| panic!("sample lower-than address should use the all-chains stem"))
            .chars()
            .take(3)
            .collect()
    }

    fn sample_suffix() -> String {
        let address = RailgunAddress::parse(sample_lower_than())
            .unwrap_or_else(|_| panic!("sample lower-than address should parse"));
        address.as_str()[address.as_str().len() - 3..].to_owned()
    }

    #[test]
    fn search_accepts_leading_zeroes_as_filter() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit_code = run(
            [
                "railguncli",
                "address",
                "search",
                "--leading-zeroes",
                "0",
                "--show-secrets",
                "--max-attempts",
                "0",
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

    #[test]
    fn search_accepts_raw_seed_mode_as_filter() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit_code = run(
            [
                "railguncli",
                "address",
                "search",
                "--seed-mode",
                "raw",
                "--leading-zeroes",
                "0",
                "--show-secrets",
                "--max-attempts",
                "0",
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
    fn search_requires_show_secrets() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit_code = run(
            ["railguncli", "address", "search", "--lower-than", sample_lower_than()],
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(exit_code, 1);
        assert!(stdout.is_empty());
        assert_eq!(String::from_utf8_lossy(&stderr), "address search requires --show-secrets\n");
    }

    #[test]
    fn search_requires_at_least_one_filter() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit_code =
            run(["railguncli", "address", "search", "--show-secrets"], &mut stdout, &mut stderr);

        assert_eq!(exit_code, 1);
        assert!(stdout.is_empty());
        assert_eq!(
            String::from_utf8_lossy(&stderr),
            "at least one of --lower-than, --leading-zeroes, --prefix, or --suffix is required\n"
        );
    }

    #[test]
    fn search_supports_prefix_only_without_lower_than() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit_code = run(
            [
                "railguncli",
                "address",
                "search",
                "--prefix",
                &sample_prefix(),
                "--show-secrets",
                "--max-attempts",
                "0",
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

    #[test]
    fn search_rejects_invalid_prefix() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit_code = run(
            ["railguncli", "address", "search", "--prefix", "0zk1bad", "--show-secrets"],
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(exit_code, 1);
        assert!(stdout.is_empty());
        assert_eq!(
            String::from_utf8_lossy(&stderr),
            "invalid prefix: prefix must use only Bech32 lowercase payload characters and must not include the 0zk1 or 0zk1qy prefix\n"
        );
    }

    #[test]
    fn search_supports_suffix_only_without_lower_than() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit_code = run(
            [
                "railguncli",
                "address",
                "search",
                "--suffix",
                &sample_suffix(),
                "--show-secrets",
                "--max-attempts",
                "0",
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

    #[test]
    fn search_rejects_invalid_suffix() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit_code = run(
            ["railguncli", "address", "search", "--suffix", "0zk1bad", "--show-secrets"],
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(exit_code, 1);
        assert!(stdout.is_empty());
        assert_eq!(
            String::from_utf8_lossy(&stderr),
            "invalid suffix: suffix must use only Bech32 lowercase payload characters\n"
        );
    }

    #[test]
    fn search_reports_capped_failure_as_json() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit_code = run(
            [
                "railguncli",
                "address",
                "search",
                "--lower-than",
                sample_lower_than(),
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
