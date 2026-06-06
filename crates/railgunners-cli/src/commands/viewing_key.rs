use crate::{
    cli::ViewingKeyCommand,
    error::CliError,
    output::write_json,
    parse::{parse_chain_scope, parse_packed_spending_public_key, parse_viewing_private_key},
    workflows::viewing_key::inspect_shareable_viewing_key,
};
use railgunners_core::{encode_shareable_viewing_key, unpack_spending_public_key};
use railgunners_types::ShareableViewingKeyData;
use serde::Serialize;
use std::io::Write;

pub(crate) fn execute(command: ViewingKeyCommand, stdout: &mut dyn Write) -> Result<(), CliError> {
    match command {
        ViewingKeyCommand::Encode {
            viewing_private_key,
            packed_spending_public_key,
            show_secrets,
            json,
        } => {
            if !show_secrets {
                return Err(CliError::command(
                    "shareable viewing key encoding requires --show-secrets".to_owned(),
                    json,
                ));
            }

            let viewing_private_key = parse_viewing_private_key(&viewing_private_key, json)?;
            let packed_spending_public_key =
                parse_packed_spending_public_key(&packed_spending_public_key, json)?;
            unpack_spending_public_key(&packed_spending_public_key)
                .map_err(|error| CliError::command(error.to_string(), json))?;
            let payload =
                ShareableViewingKeyData::new(viewing_private_key, packed_spending_public_key);
            let shareable_viewing_key = encode_shareable_viewing_key(&payload)
                .map_err(|error| CliError::command(error.to_string(), json))?;

            if json {
                write_json(
                    stdout,
                    &EncodedViewingKeyJson { shareable_viewing_key: &shareable_viewing_key },
                )?;
            } else {
                writeln!(stdout, "{shareable_viewing_key}")?;
            }
        }
        ViewingKeyCommand::Decode {
            shareable_viewing_key,
            chain_type,
            chain_id,
            show_secrets,
            json,
        } => {
            if !show_secrets {
                return Err(CliError::command(
                    "shareable viewing key decoding requires --show-secrets".to_owned(),
                    json,
                ));
            }

            let chain_scope = parse_chain_scope(chain_type, chain_id, json)?;
            let inspection = inspect_shareable_viewing_key(&shareable_viewing_key, chain_scope)
                .map_err(|error| CliError::command(error.to_string(), json))?;

            if json {
                write_json(stdout, &DecodedViewingKeyJson::from_inspection(&inspection))?;
            } else {
                writeln!(
                    stdout,
                    "viewingPrivateKey: {}",
                    hex::encode(inspection.payload().viewing_private_key().as_bytes())
                )?;
                writeln!(
                    stdout,
                    "packedSpendingPublicKey: {}",
                    hex::encode(inspection.payload().packed_spending_public_key().as_bytes())
                )?;
                writeln!(stdout, "spendingPublicKey.x: {}", inspection.spending_public_key().x())?;
                writeln!(stdout, "spendingPublicKey.y: {}", inspection.spending_public_key().y())?;
                writeln!(
                    stdout,
                    "viewingPublicKey: {}",
                    hex::encode(inspection.viewing_public_key().as_bytes())
                )?;
                writeln!(stdout, "nullifyingKey: {}", inspection.nullifying_key().value())?;
                writeln!(stdout, "masterPublicKey: {}", inspection.master_public_key().value())?;
                writeln!(stdout, "address: {}", inspection.address().as_str())?;
            }
        }
    }

    Ok(())
}

#[derive(Serialize)]
struct EncodedViewingKeyJson<'a> {
    #[serde(rename = "shareableViewingKey")]
    shareable_viewing_key: &'a str,
}

#[derive(Serialize)]
struct SpendingPublicKeyJson {
    x: String,
    y: String,
}

#[derive(Serialize)]
struct DecodedViewingKeyJson {
    #[serde(rename = "viewingPrivateKey")]
    viewing_private_key: String,
    #[serde(rename = "packedSpendingPublicKey")]
    packed_spending_public_key: String,
    #[serde(rename = "spendingPublicKey")]
    spending_public_key: SpendingPublicKeyJson,
    #[serde(rename = "viewingPublicKey")]
    viewing_public_key: String,
    #[serde(rename = "nullifyingKey")]
    nullifying_key: String,
    #[serde(rename = "masterPublicKey")]
    master_public_key: String,
    address: String,
}

impl DecodedViewingKeyJson {
    fn from_inspection(
        inspection: &crate::workflows::viewing_key::ShareableViewingKeyInspection,
    ) -> Self {
        Self {
            viewing_private_key: hex::encode(inspection.payload().viewing_private_key().as_bytes()),
            packed_spending_public_key: hex::encode(
                inspection.payload().packed_spending_public_key().as_bytes(),
            ),
            spending_public_key: SpendingPublicKeyJson {
                x: inspection.spending_public_key().x().to_string(),
                y: inspection.spending_public_key().y().to_string(),
            },
            viewing_public_key: hex::encode(inspection.viewing_public_key().as_bytes()),
            nullifying_key: inspection.nullifying_key().value().to_string(),
            master_public_key: inspection.master_public_key().value().to_string(),
            address: inspection.address().as_str().to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::run;

    fn packed_spending_public_key_hex() -> String {
        let spending_public_key = railgunners_core::derive_spending_public_key(
            &railgunners_types::SpendingPrivateKey::new(
                hex::decode("67d7d19d00e6e3b3517fe68ac46505dd207df6e8fe3aa06ba3face352e7599ef")
                    .unwrap_or_else(|_| panic!("test spending private key should decode"))
                    .try_into()
                    .unwrap_or_else(|_| panic!("test spending private key length should match")),
            ),
        )
        .unwrap_or_else(|_| panic!("test spending public key derivation should succeed"));
        let packed = railgunners_core::pack_spending_public_key(&spending_public_key)
            .unwrap_or_else(|_| panic!("test spending public key packing should succeed"));
        hex::encode(packed.as_bytes())
    }

    #[test]
    fn encodes_and_decodes_shareable_viewing_key_as_json() {
        let packed_spending_public_key = packed_spending_public_key_hex();
        let mut encode_stdout = Vec::new();
        let mut encode_stderr = Vec::new();
        let encode_exit_code = run(
            [
                "railguncli",
                "viewing-key",
                "encode",
                "--viewing-private-key",
                "67d7d19d00e6e3b3517fe68ac46505dd207df6e8fe3aa06ba3face352e7599ef",
                "--packed-spending-public-key",
                &packed_spending_public_key,
                "--show-secrets",
                "--json",
            ],
            &mut encode_stdout,
            &mut encode_stderr,
        );

        assert_eq!(encode_exit_code, 0);
        assert!(encode_stderr.is_empty());

        let encoded = String::from_utf8_lossy(&encode_stdout);
        assert!(encoded.contains("\"shareableViewingKey\":\""));
    }

    #[test]
    fn decodes_shareable_viewing_key_with_all_chains_default() {
        let packed_spending_public_key = packed_spending_public_key_hex();
        let shareable_viewing_key = railgunners_core::encode_shareable_viewing_key(
            &railgunners_types::ShareableViewingKeyData::new(
                railgunners_types::ViewingPrivateKey::new(
                    hex::decode("67d7d19d00e6e3b3517fe68ac46505dd207df6e8fe3aa06ba3face352e7599ef")
                        .unwrap_or_else(|_| panic!("test viewing private key should decode"))
                        .try_into()
                        .unwrap_or_else(|_| panic!("test viewing private key length should match")),
                ),
                railgunners_types::PackedSpendingPublicKey::new(
                    hex::decode(&packed_spending_public_key)
                        .unwrap_or_else(|_| panic!("test packed spending public key should decode"))
                        .try_into()
                        .unwrap_or_else(|_| {
                            panic!("test packed spending public key length should match")
                        }),
                ),
            ),
        )
        .unwrap_or_else(|_| panic!("test shareable viewing key should encode"));
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit_code = run(
            [
                "railguncli",
                "viewing-key",
                "decode",
                "--shareable-viewing-key",
                &shareable_viewing_key,
                "--show-secrets",
                "--json",
            ],
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(exit_code, 0);
        let output = String::from_utf8_lossy(&stdout);
        assert!(output.contains("\"viewingPrivateKey\":\"67d7d19d00e6e3b3517fe68ac46505dd207df6e8fe3aa06ba3face352e7599ef\""));
        assert!(output.contains("\"address\":\"0zk1"));
        assert!(stderr.is_empty());
    }

    #[test]
    fn refuses_decode_without_explicit_secret_flag() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit_code = run(
            ["railguncli", "viewing-key", "decode", "--shareable-viewing-key", "deadbeef"],
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(exit_code, 1);
        assert!(stdout.is_empty());
        assert_eq!(
            String::from_utf8_lossy(&stderr),
            "shareable viewing key decoding requires --show-secrets\n"
        );
    }

    #[test]
    fn rejects_partial_chain_selection() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit_code = run(
            [
                "railguncli",
                "viewing-key",
                "decode",
                "--shareable-viewing-key",
                "deadbeef",
                "--chain-type",
                "0",
                "--show-secrets",
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
