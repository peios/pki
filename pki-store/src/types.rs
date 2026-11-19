use std::fmt;

use pki_core::{RevocationReason, SerialNumber, Sid};
use time::OffsetDateTime;

/// A request's number, assigned in order and never reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RequestId(pub(crate) i64);

impl RequestId {
    pub fn new(id: i64) -> Self {
        Self(id)
    }

    pub fn get(self) -> i64 {
        self.0
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Where a request stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RequestStatus {
    /// Held for an officer's approval.
    Pending,
    /// Issued, automatically or by an officer.
    Issued,
    /// Refused, by policy or by an officer.
    Denied,
}

impl RequestStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Issued => "issued",
            Self::Denied => "denied",
        }
    }

    pub(crate) fn parse(text: &str) -> Option<Self> {
        match text {
            "pending" => Some(Self::Pending),
            "issued" => Some(Self::Issued),
            "denied" => Some(Self::Denied),
            _ => None,
        }
    }
}

impl fmt::Display for RequestStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A request as received, before its outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewRequest {
    /// The CA it was made to, by its configuration identifier.
    pub ca: String,
    /// The template it was made under, by its Registry GUID.
    pub template: String,
    /// The DER certificate request.
    pub csr: Vec<u8>,
    /// The names it asks for, as text.
    pub names: Vec<String>,
    /// The principal that made it.
    pub requester: Sid,
    /// The requester's identity as the pipeline needs to check it again on
    /// approval, in the pipeline's own encoding.
    pub subject: Vec<u8>,
    pub submitted: OffsetDateTime,
}

/// A stored request and its outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub id: RequestId,
    pub ca: String,
    pub template: String,
    pub csr: Vec<u8>,
    pub names: Vec<String>,
    pub requester: Sid,
    pub subject: Vec<u8>,
    pub submitted: OffsetDateTime,
    pub status: RequestStatus,
    /// Why the request was held or refused.
    pub reasons: Vec<String>,
    /// When it was decided, unless it is pending.
    pub decided: Option<OffsetDateTime>,
    /// The officer who decided it. Requests issued or refused by policy
    /// alone have none.
    pub decider: Option<Sid>,
}

/// A certificate just issued.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewCertificate {
    pub serial: SerialNumber,
    pub der: Vec<u8>,
    pub not_before: OffsetDateTime,
    pub not_after: OffsetDateTime,
    /// The principal owning every name in it, if one does.
    pub owner: Option<Sid>,
}

/// A stored certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    pub ca: String,
    pub serial: SerialNumber,
    pub request: RequestId,
    pub der: Vec<u8>,
    pub not_before: OffsetDateTime,
    pub not_after: OffsetDateTime,
    pub owner: Option<Sid>,
    pub revocation: Option<Revocation>,
}

/// Why, when and by whom a certificate was revoked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revocation {
    pub revoked: OffsetDateTime,
    pub reason: RevocationReason,
    pub revoker: Sid,
}

/// Which requests to list, oldest first.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequestFilter {
    pub ca: Option<String>,
    pub status: Option<RequestStatus>,
    pub requester: Option<Sid>,
    /// Only requests after this one, to continue a listing.
    pub after: Option<RequestId>,
    /// At most this many; zero means no limit.
    pub limit: usize,
}

/// Which certificates to list, in order of their requests.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CertificateFilter {
    pub ca: Option<String>,
    pub owner: Option<Sid>,
    /// Only certificates whose requests this principal made.
    pub requester: Option<Sid>,
    /// Leave out revoked certificates.
    pub unrevoked_only: bool,
    /// Only certificates whose requests come after this one.
    pub after: Option<RequestId>,
    /// At most this many; zero means no limit.
    pub limit: usize,
}

/// A CA's latest CRL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Crl {
    /// Increases with every CRL the CA signs.
    pub number: u64,
    pub this_update: OffsetDateTime,
    pub next_update: OffsetDateTime,
    /// The CRL as signed.
    pub der: Vec<u8>,
}
