use crate::{
    cli::MnemonicCommand,
    error::CliError,
    output::write_json,
    workflows::mnemonic::{generate_mnemonic, mnemonic_seed_hex, validate_mnemonic},
};
use railgun_core::Bip39WordCount;
use serde::Serialize;
use std::io::Write;

pub(crate) fn execute(command: MnemonicCommand, stdout: &mut dyn Write) -> Result<(), CliError> {
    match command {
        MnemonicCommand::Generate { words, json } => {
            let word_count = Bip39WordCount::try_from(words).map_err(|error| {
                CliError::command(format!("invalid --words value: {error}"), json)
            })?;
            let mnemonic = generate_mnemonic(word_count)
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
        MnemonicCommand::Validate { mnemonic, json } => match validate_mnemonic(&mnemonic) {
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

            let mnemonic = validate_mnemonic(&mnemonic)
                .map_err(|error| CliError::command(format!("invalid: {error}"), json))?;
            let seed = mnemonic_seed_hex(&mnemonic, password.as_deref());

            if json {
                write_json(stdout, &SeedJson { seed: &seed })?;
            } else {
                writeln!(stdout, "{seed}")?;
            }
        }
    }

    Ok(())
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

#[cfg(test)]
mod tests {
    use crate::run;

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
