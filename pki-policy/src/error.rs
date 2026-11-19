use std::fmt;

/// A failure to read or apply certificate policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    /// A configuration record is missing, malformed or contradictory.
    InvalidConfiguration(String),
    /// The access checker could not reach a decision.
    AccessCheck(String),
    /// A profile could not be built for an approved request.
    Profile(String),
}

impl fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(detail) => {
                write!(
                    formatter,
                    "invalid certificate policy configuration: {detail}"
                )
            }
            Self::AccessCheck(detail) => write!(formatter, "access check failed: {detail}"),
            Self::Profile(detail) => write!(formatter, "cannot build the certificate: {detail}"),
        }
    }
}

impl std::error::Error for PolicyError {}

impl From<pki_core::Error> for PolicyError {
    fn from(error: pki_core::Error) -> Self {
        Self::InvalidConfiguration(error.to_string())
    }
}
