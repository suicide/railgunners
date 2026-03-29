//! Thin command-line surface for the RAILGUN workspace.

use clap::{Parser, Subcommand};
use railgun_core::{Bip39Mnemonic, Bip39WordCount, sdk_info};
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
            let result = write!(stderr, "{}", error.render());
            if result.is_err() {
                return error.exit_code();
            }
            return error.exit_code();
        }
    };

    match execute(cli, stdout, stderr) {
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

fn execute(cli: Cli, stdout: &mut dyn Write, _stderr: &mut dyn Write) -> Result<(), CliError> {
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
}
