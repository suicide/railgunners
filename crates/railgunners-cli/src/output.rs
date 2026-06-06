use crate::error::CliError;
use serde::Serialize;
use std::io::Write;

pub(crate) fn write_json<T: Serialize>(stdout: &mut dyn Write, value: &T) -> Result<(), CliError> {
    serde_json::to_writer(&mut *stdout, value)?;
    writeln!(stdout)?;
    Ok(())
}

#[derive(Serialize)]
pub(crate) struct CommandErrorJson {
    pub(crate) error: String,
}
