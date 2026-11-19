use std::fmt;

/// A failure to parse a request or to build, issue or sign a certificate or CRL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A certificate signing request could not be parsed.
    MalformedRequest(String),
    /// A request's signature does not verify against its own public key.
    InvalidRequestSignature,
    /// A request asks for a name of a type the CA does not issue.
    UnsupportedName(String),
    /// A key uses an algorithm or size the CA does not accept.
    UnsupportedKey(String),
    /// A profile, name or other supplied value is invalid.
    InvalidValue(String),
    /// A CA certificate cannot act as the issuer.
    InvalidIssuer(String),
    /// The result would violate a constraint of the issuing CA.
    ConstraintViolation(String),
    /// A cryptographic operation failed, such as the signer producing a
    /// signature or drawing randomness for a serial number.
    Crypto(peios_crypto::Error),
    /// A certificate or CRL could not be encoded.
    Encoding(String),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedRequest(detail) => {
                write!(formatter, "malformed certificate request: {detail}")
            }
            Self::InvalidRequestSignature => {
                formatter.write_str("the certificate request's signature does not verify")
            }
            Self::UnsupportedName(detail) => write!(formatter, "unsupported name: {detail}"),
            Self::UnsupportedKey(detail) => write!(formatter, "unsupported key: {detail}"),
            Self::InvalidValue(detail) => write!(formatter, "invalid value: {detail}"),
            Self::InvalidIssuer(detail) => write!(formatter, "unusable issuing CA: {detail}"),
            Self::ConstraintViolation(detail) => {
                write!(formatter, "issuing CA constraint violated: {detail}")
            }
            Self::Crypto(error) => write!(formatter, "cryptography failed: {error}"),
            Self::Encoding(detail) => write!(formatter, "encoding failed: {detail}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<rcgen::Error> for Error {
    fn from(error: rcgen::Error) -> Self {
        Self::Encoding(error.to_string())
    }
}
