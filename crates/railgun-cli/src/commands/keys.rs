use crate::{
    cli::KeysCommand,
    error::CliError,
    output::write_json,
    parse::{
        parse_decimal_biguint, parse_raw_seed, parse_spending_private_key,
        parse_viewing_private_key,
    },
    workflows::keys::{
        DerivedWalletKeys, derive_wallet_keys, derive_wallet_keys_from_seed,
        inspect_master_public_key, inspect_spending_private_key, inspect_viewing_private_key,
        pack_derived_spending_public_key,
    },
};
use railgun_types::{NullifyingKey, SpendingPublicKey};
use serde::Serialize;
use std::io::Write;

pub(crate) fn execute(command: KeysCommand, stdout: &mut dyn Write) -> Result<(), CliError> {
    match command {
        KeysCommand::Derive { mnemonic, raw_seed, index, show_secrets, json } => {
            execute_derive(
                mnemonic.as_deref(),
                raw_seed.as_deref(),
                index,
                show_secrets,
                json,
                stdout,
            )?;
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
            )
            .map_err(|error| CliError::command(error.to_string(), json))?;
            let nullifying_key =
                NullifyingKey::new(parse_decimal_biguint(&nullifying_key, "nullifying key", json)?)
                    .map_err(|error| CliError::command(error.to_string(), json))?;
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

fn execute_derive(
    mnemonic: Option<&str>,
    raw_seed: Option<&str>,
    index: u32,
    show_secrets: bool,
    json: bool,
    stdout: &mut dyn Write,
) -> Result<(), CliError> {
    if !show_secrets {
        return Err(CliError::command("key derivation requires --show-secrets".to_owned(), json));
    }

    let derived = match (mnemonic, raw_seed) {
        (Some(mnemonic), None) => {
            let mnemonic = railgun_core::Bip39Mnemonic::parse(mnemonic)
                .map_err(|error| CliError::command(format!("invalid: {error}"), json))?;
            derive_wallet_keys(&mnemonic, index)
                .map_err(|error| CliError::command(error.to_string(), json))?
        }
        (None, Some(raw_seed)) => {
            let raw_seed = parse_raw_seed(raw_seed, json)?;
            derive_wallet_keys_from_seed(&raw_seed, index)
                .map_err(|error| CliError::command(error.to_string(), json))?
        }
        (Some(_), Some(_)) => {
            return Err(CliError::command(
                "key derivation requires exactly one of --mnemonic or --raw-seed".to_owned(),
                json,
            ));
        }
        (None, None) => {
            return Err(CliError::command(
                "key derivation requires one of --mnemonic or --raw-seed".to_owned(),
                json,
            ));
        }
    };
    let packed_spending_public_key =
        pack_derived_spending_public_key(derived.spending_public_key())
            .map_err(|error| CliError::command(error.to_string(), json))?;

    if json {
        write_json(stdout, &DerivedKeysJson::from_derived(&derived, &packed_spending_public_key))?;
    } else {
        write_derived_keys(stdout, &derived, &packed_spending_public_key)?;
    }

    Ok(())
}

fn write_derived_keys(
    stdout: &mut dyn Write,
    derived: &DerivedWalletKeys,
    packed_spending_public_key: &railgun_types::PackedSpendingPublicKey,
) -> Result<(), CliError> {
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
        "packedSpendingPublicKey: {}",
        hex::encode(packed_spending_public_key.as_bytes())
    )?;
    writeln!(
        stdout,
        "viewingPrivateKey: {}",
        hex::encode(derived.viewing_private_key().as_bytes())
    )?;
    writeln!(stdout, "viewingPublicKey: {}", hex::encode(derived.viewing_public_key().as_bytes()))?;
    writeln!(stdout, "nullifyingKey: {}", derived.nullifying_key().value())?;
    writeln!(stdout, "masterPublicKey: {}", derived.master_public_key().value())?;
    Ok(())
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
    #[serde(rename = "packedSpendingPublicKey")]
    packed_spending_public_key: String,
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
    fn from_derived(
        derived: &DerivedWalletKeys,
        packed_spending_public_key: &railgun_types::PackedSpendingPublicKey,
    ) -> Self {
        Self {
            index: derived.index(),
            spending_path: derived.spending_path().to_string(),
            viewing_path: derived.viewing_path().to_string(),
            spending_private_key: hex::encode(derived.spending_private_key().as_bytes()),
            spending_public_key: SpendingPublicKeyJson::from_key(derived.spending_public_key()),
            packed_spending_public_key: hex::encode(packed_spending_public_key.as_bytes()),
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

#[cfg(test)]
mod tests {
    use crate::run;

    #[test]
    fn derives_keys_issue_vector_as_json() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit_code = run(
            [
                "railguncli",
                "keys",
                "derive",
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
            "{\"index\":0,\"spendingPath\":\"m/44'/1984'/0'/0'/0'\",\"viewingPath\":\"m/420'/1984'/0'/0'/0'\",\"spendingPrivateKey\":\"08b2d974aa7fffd9d068b78c34434c534ddcd9343fcbf5aa12cf78e1a3c1ccb9\",\"spendingPublicKey\":{\"x\":\"21725194683971601625357993914711234354000760307317172095138789827480990690892\",\"y\":\"18185059732936663794890181151638097537207598791675324797050194801074344044960\"},\"packedSpendingPublicKey\":\"a029cc8b973c5ee7d592c5fbeb2d5e063908ebc8c0ed64a639e7c91e0a6134a8\",\"viewingPrivateKey\":\"9a9e1ca3b9476dc8500b43f30f34104c92a3eedfd727757ffd0ad15da8e11572\",\"viewingPublicKey\":\"df2dfb942aa6fb8cf9fe60d7984cd10b20b59027e677ecb4960d764f7d42408a\",\"nullifyingKey\":\"11357301776152573321369788690304620243322420398401862164527624501081803879965\",\"masterPublicKey\":\"19349903103956176070235423774157995896840157182198600174309409106416294821789\"}\n"
        );
        assert!(stderr.is_empty());
    }

    #[test]
    fn refuses_key_derivation_without_explicit_secret_flag() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit_code = run(
            [
                "railguncli",
                "keys",
                "derive",
                "--mnemonic",
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            ],
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(exit_code, 1);
        assert!(stdout.is_empty());
        assert_eq!(String::from_utf8_lossy(&stderr), "key derivation requires --show-secrets\n");
    }

    #[test]
    fn derives_keys_from_raw_seed_as_json() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit_code = run(
            [
                "railguncli",
                "keys",
                "derive",
                "--raw-seed",
                "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
                "--show-secrets",
                "--json",
            ],
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(exit_code, 0);
        assert_eq!(
            String::from_utf8_lossy(&stdout),
            "{\"index\":0,\"spendingPath\":\"m/44'/1984'/0'/0'/0'\",\"viewingPath\":\"m/420'/1984'/0'/0'/0'\",\"spendingPrivateKey\":\"08b2d974aa7fffd9d068b78c34434c534ddcd9343fcbf5aa12cf78e1a3c1ccb9\",\"spendingPublicKey\":{\"x\":\"21725194683971601625357993914711234354000760307317172095138789827480990690892\",\"y\":\"18185059732936663794890181151638097537207598791675324797050194801074344044960\"},\"packedSpendingPublicKey\":\"a029cc8b973c5ee7d592c5fbeb2d5e063908ebc8c0ed64a639e7c91e0a6134a8\",\"viewingPrivateKey\":\"9a9e1ca3b9476dc8500b43f30f34104c92a3eedfd727757ffd0ad15da8e11572\",\"viewingPublicKey\":\"df2dfb942aa6fb8cf9fe60d7984cd10b20b59027e677ecb4960d764f7d42408a\",\"nullifyingKey\":\"11357301776152573321369788690304620243322420398401862164527624501081803879965\",\"masterPublicKey\":\"19349903103956176070235423774157995896840157182198600174309409106416294821789\"}\n"
        );
        assert!(stderr.is_empty());
    }

    #[test]
    fn rejects_key_derivation_without_secret_source() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit_code =
            run(["railguncli", "keys", "derive", "--show-secrets"], &mut stdout, &mut stderr);

        assert_eq!(exit_code, 1);
        assert!(stdout.is_empty());
        assert_eq!(
            String::from_utf8_lossy(&stderr),
            "key derivation requires one of --mnemonic or --raw-seed\n"
        );
    }

    #[test]
    fn rejects_key_derivation_with_multiple_secret_sources() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit_code = run(
            [
                "railguncli",
                "keys",
                "derive",
                "--mnemonic",
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                "--raw-seed",
                "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
                "--show-secrets",
            ],
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(exit_code, 1);
        assert!(stdout.is_empty());
        assert_eq!(
            String::from_utf8_lossy(&stderr),
            "key derivation requires exactly one of --mnemonic or --raw-seed\n"
        );
    }

    #[test]
    fn rejects_invalid_raw_seed_hex() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit_code = run(
            ["railguncli", "keys", "derive", "--raw-seed", "xyz", "--show-secrets"],
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(exit_code, 1);
        assert!(stdout.is_empty());
        assert_eq!(
            String::from_utf8_lossy(&stderr),
            "invalid raw seed: expected lowercase or uppercase hex\n"
        );
    }

    #[test]
    fn rejects_invalid_raw_seed_length() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit_code = run(
            ["railguncli", "keys", "derive", "--raw-seed", "00", "--show-secrets"],
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(exit_code, 1);
        assert!(stdout.is_empty());
        assert_eq!(String::from_utf8_lossy(&stderr), "invalid raw seed: expected 64 bytes\n");
    }

    #[test]
    fn inspects_viewing_private_key_issue_vector_as_json() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit_code = run(
            [
                "railguncli",
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
                "railguncli",
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
            ["railguncli", "keys", "inspect-viewing-private", "--private-key", "xyz"],
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
