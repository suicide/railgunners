use std::io;

#[derive(Debug)]
pub(crate) enum CliError {
    Command { message: String, json: bool },
    RawJson(String),
    Io(io::Error),
    Json(serde_json::Error),
}

impl CliError {
    pub(crate) fn command(message: String, json: bool) -> Self {
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
