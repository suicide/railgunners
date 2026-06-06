use core::fmt;

/// Error returned when a domain value fails validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParseDomainError {
    message: &'static str,
}

impl ParseDomainError {
    /// Creates a new parse error with a static message.
    #[must_use]
    pub const fn new(message: &'static str) -> Self {
        Self { message }
    }
}

impl fmt::Display for ParseDomainError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for ParseDomainError {}
