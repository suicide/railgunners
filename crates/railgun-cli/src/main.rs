//! Thin command-line surface for the RAILGUN workspace.

use clap::{Parser, Subcommand};
use num_bigint::BigUint;
use railgun_core::{
    Bip39Mnemonic, Bip39WordCount, derive_wallet_keys, inspect_master_public_key,
    inspect_spending_private_key, inspect_viewing_private_key, sdk_info,
};
use railgun_types::{NullifyingKey, SpendingPrivateKey, SpendingPublicKey, ViewingPrivateKey};
use serde::Serialize;
use std::io::{self, Write};

fn main() {
    let exit_code = run(std::env::args_os(), &mut io::stdout(), &mut io::stderr());
    std::process::exit(exit_code);
}

fn run<I, T>(args: I, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(error) => {
            if write!(stderr, "{}", error.render()).is_err() {
                return error.exit_code();
            }
            return error.exit_code();
        }
    };

    match execute(cli, stdout) {
        Ok(()) => 0,
        Err(CliError::Command { message, json }) => {
            if json {
                let payload = CommandErrorJson { error: message };
                if write_json(stdout, &payload).is_err() {
                    let _ = writeln!(stderr, "failed to write JSON output");
                }
            } else {
                let _ = writeln!(stderr, "{message}");
            }
            1
        }
        Err(CliError::RawJson(message)) => {
            if writeln!(stdout, "{message}").is_err() {
                let _ = writeln!(stderr, "failed to write JSON output");
            }
            1
        }
        Err(CliError::Io(error)) => {
            let _ = writeln!(stderr, "I/O error: {error}");
            1
        }
        Err(CliError::Json(error)) => {
            let _ = writeln!(stderr, "JSON error: {error}");
            1
        }
    }
}

fn execute(cli: Cli, stdout: &mut dyn Write) -> Result<(), CliError> {
    match cli.command {
        Command::Version => {
            let info = sdk_info();
            writeln!(stdout, "{} {}", info.name, info.version)?;
        }
        Command::ScaffoldInfo => {
            writeln!(stdout, "The RAILGUN workspace scaffold is in place.")?;
            writeln!(stdout, "Core crates define typed protocol models and capability traits.")?;
            writeln!(stdout, "Adapter crates are reserved for concrete external integrations.")?;
            writeln!(
                stdout,
                "The CLI is intentionally thin and will grow through public SDK APIs."
            )?;
        }
        Command::Mnemonic(command) => execute_mnemonic(command, stdout)?,
        Command::Keys(command) => execute_keys(command, stdout)?,
    }

    Ok(())
}

fn execute_mnemonic(command: MnemonicCommand, stdout: &mut dyn Write) -> Result<(), CliError> {
    match command {
        MnemonicCommand::Generate { words, json } => {
            let word_count = Bip39WordCount::try_from(words).map_err(|error| {
                CliError::command(format!("invalid --words value: {error}"), json)
            })?;
            let mnemonic = Bip39Mnemonic::generate(word_count)
                .map_err(|error| CliError::command(error.to_string(), json))?;
            let phrase = mnemonic.phrase();

            if json {
                write_json(
                    stdout,
                    &GeneratedMnemonicJson { mnemonic: &phrase, word_count: mnemonic.word_count() },
                )?;
            } else {
                writeln!(stdout, "{phrase}")?;
            }
        }
        MnemonicCommand::Validate { mnemonic, json } => match Bip39Mnemonic::parse(&mnemonic) {
            Ok(_) => {
                if json {
                    write_json(stdout, &ValidationSuccessJson { valid: true })?;
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
                return Err(CliError::command(format!("invalid: {error}"), false));
            }
        },
        MnemonicCommand::Seed { mnemonic, password, show_secrets, json } => {
            if !show_secrets {
                return Err(CliError::command(
                    "seed export requires --show-secrets".to_owned(),
                    json,
                ));
            }

            let mnemonic = Bip39Mnemonic::parse(&mnemonic)
                .map_err(|error| CliError::command(format!("invalid: {error}"), json))?;
            let seed = hex::encode(mnemonic.seed(password.as_deref()));

            if json {
                write_json(stdout, &SeedJson { seed: &seed })?;
            } else {
                writeln!(stdout, "{seed}")?;
            }
        }
    }

    Ok(())
}

fn execute_keys(command: KeysCommand, stdout: &mut dyn Write) -> Result<(), CliError> {
    match command {
        KeysCommand::Derive { mnemonic, index, show_secrets, json } => {
            if !show_secrets {
                return Err(CliError::command(
                    "key derivation requires --show-secrets".to_owned(),
                    json,
                ));
            }

            let mnemonic = Bip39Mnemonic::parse(&mnemonic)
                .map_err(|error| CliError::command(format!("invalid: {error}"), json))?;
            let derived = derive_wallet_keys(&mnemonic, index)
                .map_err(|error| CliError::command(error.to_string(), json))?;

            if json {
                let payload = DerivedKeysJson::from_derived(&derived);
                write_json(stdout, &payload)?;
            } else {
                writeln!(stdout, "index: {}", derived.index())?;
                writeln!(stdout, "spendingPath: {}", derived.spending_path())?;
                writeln!(stdout, "viewingPath: {}", derived.viewing_path())?;
                writeln!(
                    stdout,
                    "spendingPrivateKey: {}",
                    hex::encode(derived.spending_private_key().as_bytes())
                )?;
                writeln!(stdout, "spendingPublicKey.x: {}", derived.spending_public_key().x())?;
                writeln!(stdout, "spendingPublicKey.y: {}", derived.spending_public_key().y())?;
                writeln!(
                    stdout,
                    "viewingPrivateKey: {}",
                    hex::encode(derived.viewing_private_key().as_bytes())
                )?;
                writeln!(
                    stdout,
                    "viewingPublicKey: {}",
                    hex::encode(derived.viewing_public_key().as_bytes())
                )?;
                writeln!(stdout, "nullifyingKey: {}", derived.nullifying_key().value())?;
                writeln!(stdout, "masterPublicKey: {}", derived.master_public_key().value())?;
            }
        }
        KeysCommand::InspectViewingPrivate { private_key, json } => {
            let private_key = parse_viewing_private_key(&private_key, json)?;
            let inspection = inspect_viewing_private_key(&private_key)
                .map_err(|error| CliError::command(error.to_string(), json))?;

            if json {
                write_json(
                    stdout,
                    &ViewingKeyInspectionJson {
                        viewing_public_key: hex::encode(inspection.viewing_public_key().as_bytes()),
                        nullifying_key: inspection.nullifying_key().value().to_string(),
                    },
                )?;
            } else {
                writeln!(
                    stdout,
                    "viewingPublicKey: {}",
                    hex::encode(inspection.viewing_public_key().as_bytes())
                )?;
                writeln!(stdout, "nullifyingKey: {}", inspection.nullifying_key().value())?;
            }
        }
        KeysCommand::InspectSpendingPrivate { private_key, json } => {
            let private_key = parse_spending_private_key(&private_key, json)?;
            let public_key = inspect_spending_private_key(&private_key)
                .map_err(|error| CliError::command(error.to_string(), json))?;

            if json {
                write_json(
                    stdout,
                    &SpendingPublicKeyOnlyJson {
                        spending_public_key: SpendingPublicKeyJson::from_key(&public_key),
                    },
                )?;
            } else {
                writeln!(stdout, "spendingPublicKey.x: {}", public_key.x())?;
                writeln!(stdout, "spendingPublicKey.y: {}", public_key.y())?;
            }
        }
        KeysCommand::InspectMasterPublic {
            spending_public_key_x,
            spending_public_key_y,
            nullifying_key,
            json,
        } => {
            let spending_public_key = SpendingPublicKey::new(
                parse_decimal_biguint(&spending_public_key_x, "spending public key x", json)?,
                parse_decimal_biguint(&spending_public_key_y, "spending public key y", json)?,
            );
            let nullifying_key =
                NullifyingKey::new(parse_decimal_biguint(&nullifying_key, "nullifying key", json)?);
            let master_public_key =
                inspect_master_public_key(&spending_public_key, &nullifying_key)
                    .map_err(|error| CliError::command(error.to_string(), json))?;

            if json {
                write_json(
                    stdout,
                    &MasterPublicKeyJson {
                        master_public_key: master_public_key.value().to_string(),
                    },
                )?;
            } else {
                writeln!(stdout, "masterPublicKey: {}", master_public_key.value())?;
            }
        }
    }

    Ok(())
}

fn parse_hex<const N: usize>(value: &str, label: &str, json: bool) -> Result<[u8; N], CliError> {
    let bytes = hex::decode(value).map_err(|_| {
        CliError::command(format!("invalid {label}: expected lowercase or uppercase hex"), json)
    })?;
    bytes.try_into().map_err(|_: Vec<u8>| {
        CliError::command(format!("invalid {label}: expected {N} bytes"), json)
    })
}

fn parse_viewing_private_key(value: &str, json: bool) -> Result<ViewingPrivateKey, CliError> {
    let bytes = parse_hex::<32>(value, "viewing private key", json)?;
    Ok(ViewingPrivateKey::new(bytes))
}

fn parse_spending_private_key(value: &str, json: bool) -> Result<SpendingPrivateKey, CliError> {
    let bytes = parse_hex::<32>(value, "spending private key", json)?;
    Ok(SpendingPrivateKey::new(bytes))
}

fn parse_decimal_biguint(value: &str, label: &str, json: bool) -> Result<BigUint, CliError> {
    BigUint::parse_bytes(value.as_bytes(), 10).ok_or_else(|| {
        CliError::command(format!("invalid {label}: expected unsigned decimal"), json)
    })
}

fn write_json<T: Serialize>(stdout: &mut dyn Write, value: &T) -> Result<(), CliError> {
    serde_json::to_writer(&mut *stdout, value)?;
    writeln!(stdout)?;
    Ok(())
}

#[derive(Parser, Debug)]
#[command(name = "railgun-rs")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Show the workspace version.
    Version,
    /// Describe the current scaffold.
    ScaffoldInfo,
    /// Run mnemonic-related offline workflows.
    #[command(subcommand)]
    Mnemonic(MnemonicCommand),
    /// Derive and inspect Railgun keys.
    #[command(subcommand)]
    Keys(KeysCommand),
}

#[derive(Subcommand, Debug)]
enum MnemonicCommand {
    /// Generate a new BIP-39 mnemonic.
    Generate {
        /// Number of BIP-39 words to generate.
        #[arg(long, default_value_t = 12)]
        words: usize,
        /// Emit stable machine-readable output.
        #[arg(long)]
        json: bool,
    },
    /// Validate a BIP-39 mnemonic.
    Validate {
        /// The mnemonic phrase to validate.
        #[arg(long)]
        mnemonic: String,
        /// Emit stable machine-readable output.
        #[arg(long)]
        json: bool,
    },
    /// Export the 64-byte BIP-39 seed as lowercase hex.
    Seed {
        /// The mnemonic phrase to derive from.
        #[arg(long)]
        mnemonic: String,
        /// Optional BIP-39 password.
        #[arg(long)]
        password: Option<String>,
        /// Explicitly allow secret-bearing output.
        #[arg(long)]
        show_secrets: bool,
        /// Emit stable machine-readable output.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
enum KeysCommand {
    /// Derive canonical Railgun keys from a mnemonic and wallet index.
    Derive {
        /// The mnemonic phrase to derive from.
        #[arg(long)]
        mnemonic: String,
        /// The canonical Railgun wallet index.
        #[arg(long, default_value_t = 0)]
        index: u32,
        /// Explicitly allow secret-bearing output.
        #[arg(long)]
        show_secrets: bool,
        /// Emit stable machine-readable output.
        #[arg(long)]
        json: bool,
    },
    /// Inspect a viewing private key.
    InspectViewingPrivate {
        /// The 32-byte viewing private key in hex.
        #[arg(long = "private-key")]
        private_key: String,
        /// Emit stable machine-readable output.
        #[arg(long)]
        json: bool,
    },
    /// Inspect a spending private key.
    InspectSpendingPrivate {
        /// The 32-byte spending private key in hex.
        #[arg(long = "private-key")]
        private_key: String,
        /// Emit stable machine-readable output.
        #[arg(long)]
        json: bool,
    },
    /// Inspect master-public-key inputs.
    InspectMasterPublic {
        /// The spending public key x coordinate as unsigned decimal.
        #[arg(long = "spending-public-key-x")]
        spending_public_key_x: String,
        /// The spending public key y coordinate as unsigned decimal.
        #[arg(long = "spending-public-key-y")]
        spending_public_key_y: String,
        /// The nullifying key as unsigned decimal.
        #[arg(long = "nullifying-key")]
        nullifying_key: String,
        /// Emit stable machine-readable output.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug)]
enum CliError {
    Command { message: String, json: bool },
    RawJson(String),
    Io(io::Error),
    Json(serde_json::Error),
}

impl CliError {
    fn command(message: String, json: bool) -> Self {
        Self::Command { message, json }
    }
}

impl From<io::Error> for CliError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for CliError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

#[derive(Serialize)]
struct GeneratedMnemonicJson<'a> {
    mnemonic: &'a str,
    #[serde(rename = "wordCount")]
    word_count: usize,
}

#[derive(Serialize)]
struct ValidationSuccessJson {
    valid: bool,
}

#[derive(Serialize)]
struct ValidationErrorJson {
    valid: bool,
    error: String,
}

#[derive(Serialize)]
struct SeedJson<'a> {
    seed: &'a str,
}

#[derive(Serialize)]
struct SpendingPublicKeyJson {
    x: String,
    y: String,
}

impl SpendingPublicKeyJson {
    fn from_key(key: &SpendingPublicKey) -> Self {
        Self { x: key.x().to_string(), y: key.y().to_string() }
    }
}

#[derive(Serialize)]
struct DerivedKeysJson {
    index: u32,
    #[serde(rename = "spendingPath")]
    spending_path: String,
    #[serde(rename = "viewingPath")]
    viewing_path: String,
    #[serde(rename = "spendingPrivateKey")]
    spending_private_key: String,
    #[serde(rename = "spendingPublicKey")]
    spending_public_key: SpendingPublicKeyJson,
    #[serde(rename = "viewingPrivateKey")]
    viewing_private_key: String,
    #[serde(rename = "viewingPublicKey")]
    viewing_public_key: String,
    #[serde(rename = "nullifyingKey")]
    nullifying_key: String,
    #[serde(rename = "masterPublicKey")]
    master_public_key: String,
}

impl DerivedKeysJson {
    fn from_derived(derived: &railgun_core::DerivedWalletKeys) -> Self {
        Self {
            index: derived.index(),
            spending_path: derived.spending_path().to_string(),
            viewing_path: derived.viewing_path().to_string(),
            spending_private_key: hex::encode(derived.spending_private_key().as_bytes()),
            spending_public_key: SpendingPublicKeyJson::from_key(derived.spending_public_key()),
            viewing_private_key: hex::encode(derived.viewing_private_key().as_bytes()),
            viewing_public_key: hex::encode(derived.viewing_public_key().as_bytes()),
            nullifying_key: derived.nullifying_key().value().to_string(),
            master_public_key: derived.master_public_key().value().to_string(),
        }
    }
}

#[derive(Serialize)]
struct ViewingKeyInspectionJson {
    #[serde(rename = "viewingPublicKey")]
    viewing_public_key: String,
    #[serde(rename = "nullifyingKey")]
    nullifying_key: String,
}

#[derive(Serialize)]
struct SpendingPublicKeyOnlyJson {
    #[serde(rename = "spendingPublicKey")]
    spending_public_key: SpendingPublicKeyJson,
}

#[derive(Serialize)]
struct MasterPublicKeyJson {
    #[serde(rename = "masterPublicKey")]
    master_public_key: String,
}

#[derive(Serialize)]
struct CommandErrorJson {
    error: String,
}

#[cfg(test)]
mod tests {
    use super::run;

    #[test]
    fn validates_issue_vector() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit_code = run(
            [
                "railgun-rs",
                "mnemonic",
                "validate",
                "--mnemonic",
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            ],
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(exit_code, 0);
        assert_eq!(String::from_utf8_lossy(&stdout), "valid\n");
        assert!(stderr.is_empty());
    }

    #[test]
    fn rejects_invalid_mnemonic_in_json_mode() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit_code = run(
            [
                "railgun-rs",
                "mnemonic",
                "validate",
                "--mnemonic",
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
                "--json",
            ],
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(exit_code, 1);
        assert_eq!(
            String::from_utf8_lossy(&stdout),
            "{\"valid\":false,\"error\":\"invalid BIP-39 checksum\"}\n"
        );
        assert!(stderr.is_empty());
    }

    #[test]
    fn exports_seed_issue_vector_as_json() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit_code = run(
            [
                "railgun-rs",
                "mnemonic",
                "seed",
                "--mnemonic",
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                "--show-secrets",
                "--json",
            ],
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(exit_code, 0);
        assert_eq!(
            String::from_utf8_lossy(&stdout),
            "{\"seed\":\"5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4\"}\n"
        );
        assert!(stderr.is_empty());
    }

    #[test]
    fn refuses_seed_export_without_explicit_secret_flag() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit_code = run(
            [
                "railgun-rs",
                "mnemonic",
                "seed",
                "--mnemonic",
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            ],
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(exit_code, 1);
        assert!(stdout.is_empty());
        assert_eq!(String::from_utf8_lossy(&stderr), "seed export requires --show-secrets\n");
    }

    #[test]
    fn generates_requested_word_count_in_json_mode() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit_code = run(
            ["railgun-rs", "mnemonic", "generate", "--words", "24", "--json"],
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(exit_code, 0);
        let output = String::from_utf8_lossy(&stdout);
        assert!(output.contains("\"wordCount\":24"));
        assert!(output.contains("\"mnemonic\":\""));
        assert!(stderr.is_empty());
    }

    #[test]
    fn derives_keys_issue_vector_as_json() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit_code = run(
            [
                "railgun-rs",
                "keys",
                "derive",
                "--mnemonic",
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                "--index",
                "0",
                "--show-secrets",
                "--json",
            ],
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(exit_code, 0);
        assert_eq!(
            String::from_utf8_lossy(&stdout),
            "{\"index\":0,\"spendingPath\":\"m/44'/1984'/0'/0'/0'\",\"viewingPath\":\"m/420'/1984'/0'/0'/0'\",\"spendingPrivateKey\":\"08b2d974aa7fffd9d068b78c34434c534ddcd9343fcbf5aa12cf78e1a3c1ccb9\",\"spendingPublicKey\":{\"x\":\"21725194683971601625357993914711234354000760307317172095138789827480990690892\",\"y\":\"18185059732936663794890181151638097537207598791675324797050194801074344044960\"},\"viewingPrivateKey\":\"9a9e1ca3b9476dc8500b43f30f34104c92a3eedfd727757ffd0ad15da8e11572\",\"viewingPublicKey\":\"df2dfb942aa6fb8cf9fe60d7984cd10b20b59027e677ecb4960d764f7d42408a\",\"nullifyingKey\":\"11357301776152573321369788690304620243322420398401862164527624501081803879965\",\"masterPublicKey\":\"19349903103956176070235423774157995896840157182198600174309409106416294821789\"}\n"
        );
        assert!(stderr.is_empty());
    }

    #[test]
    fn refuses_key_derivation_without_explicit_secret_flag() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit_code = run(
            [
                "railgun-rs",
                "keys",
                "derive",
                "--mnemonic",
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                "--index",
                "0",
            ],
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(exit_code, 1);
        assert!(stdout.is_empty());
        assert_eq!(String::from_utf8_lossy(&stderr), "key derivation requires --show-secrets\n");
    }

    #[test]
    fn inspects_viewing_private_key_issue_vector_as_json() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit_code = run(
            [
                "railgun-rs",
                "keys",
                "inspect-viewing-private",
                "--private-key",
                "67d7d19d00e6e3b3517fe68ac46505dd207df6e8fe3aa06ba3face352e7599ef",
                "--json",
            ],
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(exit_code, 0);
        assert_eq!(
            String::from_utf8_lossy(&stdout),
            "{\"viewingPublicKey\":\"0debf77d8e9436fc07a0dc3fe8bd90c2f592a08cab8dbe5f972a4783465cd6d4\",\"nullifyingKey\":\"12835268173099116305231859677177501123414588269721547120001227054861606950622\"}\n"
        );
        assert!(stderr.is_empty());
    }

    #[test]
    fn inspects_master_public_key_issue_vector_as_json() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit_code = run(
            [
                "railgun-rs",
                "keys",
                "inspect-master-public",
                "--spending-public-key-x",
                "15684838006997671713939066069845237677934334329285343229142447933587909549584",
                "--spending-public-key-y",
                "11878614856120328179849762231924033298788609151532558727282528569229552954628",
                "--nullifying-key",
                "8368299126798249740586535953124199418524409103803955764525436743456763691384",
                "--json",
            ],
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(exit_code, 0);
        assert_eq!(
            String::from_utf8_lossy(&stdout),
            "{\"masterPublicKey\":\"20060431504059690749153982049210720252589378133547582826474262520121417617087\"}\n"
        );
        assert!(stderr.is_empty());
    }

    #[test]
    fn rejects_invalid_viewing_private_key_hex() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit_code = run(
            ["railgun-rs", "keys", "inspect-viewing-private", "--private-key", "xyz"],
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(exit_code, 1);
        assert!(stdout.is_empty());
        assert_eq!(
            String::from_utf8_lossy(&stderr),
            "invalid viewing private key: expected lowercase or uppercase hex\n"
        );
    }
}
