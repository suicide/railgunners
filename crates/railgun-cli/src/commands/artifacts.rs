use crate::{cli::ArtifactsCommand, error::CliError, output::write_json};
use railgun_artifacts::{
    ArtifactFileVerification, ArtifactVerificationResult, parse_artifact_variant,
    verify_local_artifacts,
};
use serde::Serialize;
use std::{io::Write, path::Path};

pub(crate) fn execute(command: ArtifactsCommand, stdout: &mut dyn Write) -> Result<(), CliError> {
    match command {
        ArtifactsCommand::Verify { variant, zkey, wasm, dat, json } => {
            let variant = parse_artifact_variant(&variant)
                .map_err(|error| CliError::command(error.to_string(), json))?;
            let result = verify_local_artifacts(
                &variant,
                Path::new(&zkey),
                wasm.as_deref().map(Path::new),
                dat.as_deref().map(Path::new),
            )
            .map_err(|error| CliError::command(error.to_string(), json))?;

            if json {
                write_json(stdout, &ArtifactVerificationJson::from_result(&result))?;
            } else {
                write_text_result(stdout, &result)?;
            }
        }
    }

    Ok(())
}

fn write_text_result(
    stdout: &mut dyn Write,
    result: &ArtifactVerificationResult,
) -> Result<(), CliError> {
    writeln!(stdout, "variant: {}", result.variant())?;
    writeln!(stdout, "ok: {}", result.ok())?;
    write_text_file(stdout, result.files().zkey())?;
    if let Some(wasm) = result.files().wasm() {
        write_text_file(stdout, wasm)?;
    }
    if let Some(dat) = result.files().dat() {
        write_text_file(stdout, dat)?;
    }
    Ok(())
}

fn write_text_file(
    stdout: &mut dyn Write,
    verification: &ArtifactFileVerification,
) -> Result<(), CliError> {
    writeln!(stdout, "{}.ok: {}", verification.kind(), verification.ok())?;
    writeln!(stdout, "{}.path: {}", verification.kind(), verification.path().display())?;
    writeln!(stdout, "{}.expected: {}", verification.kind(), verification.expected_hash())?;
    writeln!(stdout, "{}.actual: {}", verification.kind(), verification.actual_hash())?;
    Ok(())
}

#[derive(Serialize)]
struct ArtifactVerificationJson {
    variant: String,
    ok: bool,
    files: ArtifactVerificationFilesJson,
}

impl ArtifactVerificationJson {
    fn from_result(result: &ArtifactVerificationResult) -> Self {
        Self {
            variant: result.variant().to_string(),
            ok: result.ok(),
            files: ArtifactVerificationFilesJson {
                zkey: ArtifactFileVerificationJson::from_file(result.files().zkey()),
                wasm: result.files().wasm().map(ArtifactFileVerificationJson::from_file),
                dat: result.files().dat().map(ArtifactFileVerificationJson::from_file),
            },
        }
    }
}

#[derive(Serialize)]
struct ArtifactVerificationFilesJson {
    zkey: ArtifactFileVerificationJson,
    #[serde(skip_serializing_if = "Option::is_none")]
    wasm: Option<ArtifactFileVerificationJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dat: Option<ArtifactFileVerificationJson>,
}

#[derive(Serialize)]
struct ArtifactFileVerificationJson {
    ok: bool,
    expected: String,
    actual: String,
}

impl ArtifactFileVerificationJson {
    fn from_file(file: &ArtifactFileVerification) -> Self {
        Self {
            ok: file.ok(),
            expected: file.expected_hash().to_owned(),
            actual: file.actual_hash().to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::run;
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn temp_file_path(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| panic!("system time should be after unix epoch"))
            .as_nanos();
        std::env::temp_dir().join(format!("railgun-cli-artifacts-{name}-{nanos}"))
    }

    #[test]
    fn verifies_local_artifacts_as_json_with_structured_mismatch_output() {
        let zkey = temp_file_path("zkey");
        let wasm = temp_file_path("wasm");
        fs::write(&zkey, b"wrong zkey").unwrap_or_else(|_| panic!("test zkey should write"));
        fs::write(&wasm, b"wrong wasm").unwrap_or_else(|_| panic!("test wasm should write"));

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit_code = run(
            [
                "railguncli",
                "artifacts",
                "verify",
                "--variant",
                "01x01",
                "--zkey",
                zkey.to_str().unwrap_or_else(|| panic!("test path should be valid utf-8")),
                "--wasm",
                wasm.to_str().unwrap_or_else(|| panic!("test path should be valid utf-8")),
                "--json",
            ],
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(exit_code, 0);
        let output = String::from_utf8_lossy(&stdout);
        assert!(output.contains("\"variant\":\"01x01\""));
        assert!(output.contains("\"ok\":false"));
        assert!(output.contains("\"zkey\":{\"ok\":false"));
        assert!(output.contains("\"wasm\":{\"ok\":false"));
        assert!(stderr.is_empty());

        let _ = fs::remove_file(zkey);
        let _ = fs::remove_file(wasm);
    }

    #[test]
    fn rejects_missing_backend_flags() {
        let zkey = temp_file_path("zkey-only");
        fs::write(&zkey, b"wrong zkey").unwrap_or_else(|_| panic!("test zkey should write"));

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit_code = run(
            [
                "railguncli",
                "artifacts",
                "verify",
                "--variant",
                "01x01",
                "--zkey",
                zkey.to_str().unwrap_or_else(|| panic!("test path should be valid utf-8")),
                "--json",
            ],
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(exit_code, 1);
        assert_eq!(
            String::from_utf8_lossy(&stdout),
            "{\"error\":\"artifact verification requires at least one of --wasm or --dat\"}\n"
        );
        assert!(stderr.is_empty());

        let _ = fs::remove_file(zkey);
    }

    #[test]
    fn rejects_unknown_variant_string() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let exit_code = run(
            [
                "railguncli",
                "artifacts",
                "verify",
                "--variant",
                "bad",
                "--zkey",
                "/tmp/zkey",
                "--wasm",
                "/tmp/wasm",
                "--json",
            ],
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(exit_code, 1);
        assert_eq!(
            String::from_utf8_lossy(&stdout),
            "{\"error\":\"unknown canonical artifact variant: bad\"}\n"
        );
        assert!(stderr.is_empty());
    }
}
