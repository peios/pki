use std::fmt;

use crate::{RequestId, RequestStatus};

/// A failure to read or change the CA database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// The database can't be used: it is unsafe to open, belongs to
    /// something else, has a newer schema, or failed its integrity check.
    Unusable(String),
    /// Another process already owns the database.
    InUse,
    /// The request does not exist.
    NoSuchRequest(RequestId),
    /// The certificate does not exist.
    NoSuchCertificate,
    /// The request was already decided.
    NotPending(RequestId, RequestStatus),
    /// The approver is the requester (R9).
    SelfApproval,
    /// The certificate is already revoked.
    AlreadyRevoked,
    /// The CA already issued a certificate with this serial number.
    DuplicateSerial,
    /// A value is invalid, such as an empty CA identifier.
    Invalid(String),
    /// A stored record can't be read back.
    Corrupt(String),
    /// SQLite failed.
    Database(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unusable(detail) => write!(formatter, "unusable CA database: {detail}"),
            Self::InUse => formatter.write_str("the CA database is in use by another process"),
            Self::NoSuchRequest(id) => write!(formatter, "request {id} does not exist"),
            Self::NoSuchCertificate => formatter.write_str("the certificate does not exist"),
            Self::NotPending(id, status) => {
                write!(formatter, "request {id} is already {status}")
            }
            Self::SelfApproval => {
                formatter.write_str("a request can't be approved by its requester")
            }
            Self::AlreadyRevoked => formatter.write_str("the certificate is already revoked"),
            Self::DuplicateSerial => {
                formatter.write_str("the CA already issued a certificate with this serial number")
            }
            Self::Invalid(detail) => write!(formatter, "invalid record: {detail}"),
            Self::Corrupt(detail) => write!(formatter, "corrupt record: {detail}"),
            Self::Database(detail) => write!(formatter, "database failure: {detail}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<rusqlite::Error> for StoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Database(error.to_string())
    }
}
