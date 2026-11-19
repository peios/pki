use std::fmt;

use pki_store::{RequestId, RequestStatus, StoreError};

/// Why the pipeline refused or failed an operation.
///
/// A request that policy refuses is not an error: it is recorded and
/// reported as a [`crate::Submission`]. These are the cases where nothing
/// was recorded, or a decision couldn't be made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PipelineError {
    /// The caller lacks the right this needs at the CA.
    AccessDenied,
    /// The CA does not issue from this template, or it doesn't exist.
    NoSuchTemplate(String),
    /// The request does not exist at this CA, or the caller may not see it.
    NoSuchRequest(RequestId),
    /// The certificate does not exist at this CA, or the caller may not
    /// see it.
    NoSuchCertificate,
    /// The certificate request can't be used.
    BadRequest(pki_core::Error),
    /// The request was already decided.
    NotPending(RequestId, RequestStatus),
    /// The officer is the requester (R9).
    SelfApproval,
    /// Policy as it now stands refuses a held request, so it can't be
    /// approved. An officer can deny it.
    NowRefused(Vec<String>),
    /// The certificate is already revoked.
    AlreadyRevoked,
    /// The CA's key is unavailable or locked, so nothing can be issued.
    KeyUnavailable,
    /// The configuration can't be applied.
    Configuration(String),
    /// Issuing failed.
    Issue(pki_core::Error),
    /// An identity couldn't be checked or restored.
    Identity(String),
    /// The CA database failed.
    Store(StoreError),
}

impl fmt::Display for PipelineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AccessDenied => formatter.write_str("access denied"),
            Self::NoSuchTemplate(template) => {
                write!(formatter, "the CA does not issue from template {template}")
            }
            Self::NoSuchRequest(id) => write!(formatter, "request {id} does not exist"),
            Self::NoSuchCertificate => formatter.write_str("the certificate does not exist"),
            Self::BadRequest(error) => write!(formatter, "unusable request: {error}"),
            Self::NotPending(id, status) => write!(formatter, "request {id} is already {status}"),
            Self::SelfApproval => {
                formatter.write_str("a request can't be approved by its requester")
            }
            Self::NowRefused(reasons) => {
                write!(
                    formatter,
                    "policy now refuses the request: {}",
                    reasons.join("; ")
                )
            }
            Self::AlreadyRevoked => formatter.write_str("the certificate is already revoked"),
            Self::KeyUnavailable => formatter.write_str("the CA's key is unavailable"),
            Self::Configuration(detail) => write!(formatter, "configuration: {detail}"),
            Self::Issue(error) => write!(formatter, "issuing failed: {error}"),
            Self::Identity(detail) => write!(formatter, "identity: {detail}"),
            Self::Store(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for PipelineError {}

impl From<StoreError> for PipelineError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::NoSuchRequest(id) => Self::NoSuchRequest(id),
            StoreError::NoSuchCertificate => Self::NoSuchCertificate,
            StoreError::NotPending(id, status) => Self::NotPending(id, status),
            StoreError::SelfApproval => Self::SelfApproval,
            StoreError::AlreadyRevoked => Self::AlreadyRevoked,
            error => Self::Store(error),
        }
    }
}

impl From<pki_policy::PolicyError> for PipelineError {
    fn from(error: pki_policy::PolicyError) -> Self {
        Self::Configuration(error.to_string())
    }
}
