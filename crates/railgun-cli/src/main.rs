//! Thin command-line surface for the RAILGUN workspace.

mod cli;
mod commands;
mod error;
mod output;
mod parse;

use clap::Parser;
use cli::{Cli, Command};
use error::CliError;
use std::io::{self, Write};

fn main() {
    let exit_code = run(std::env::args_os(), &mut io::stdout(), &mut io::stderr());
    std::process::exit(exit_code);
}

pub(crate) fn run<I, T>(args: I, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32
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
                if output::write_json(stdout, &output::CommandErrorJson { error: message }).is_err()
                {
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
            let info = railgun_core::sdk_info();
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
        Command::Mnemonic(command) => commands::mnemonic::execute(command, stdout)?,
        Command::Keys(command) => commands::keys::execute(command, stdout)?,
        Command::ViewingKey(command) => commands::viewing_key::execute(command, stdout)?,
    }

    Ok(())
}
