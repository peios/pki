//! Requests, replies and their encoding.

use std::fmt;

use crate::codec::{malformed, CodecError, Fields, MapWriter};

/// Where a request stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RequestStatus {
    Pending,
    Issued,
    Denied,
}

impl RequestStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Issued => "issued",
            Self::Denied => "denied",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "pending" => Some(Self::Pending),
            "issued" => Some(Self::Issued),
            "denied" => Some(Self::Denied),
            _ => None,
        }
    }
}

/// Which requests a listing returns, oldest first.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequestQuery {
    pub status: Option<RequestStatus>,
    /// Only requests after this one, to continue a listing.
    pub after: Option<i64>,
    /// At most this many, and never more than [`crate::MAX_LISTING`].
    pub limit: u32,
}

/// Which certificates a listing returns, in order of their requests.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CertificateQuery {
    pub unrevoked_only: bool,
    /// Only certificates whose requests come after this one.
    pub after: Option<i64>,
    pub limit: u32,
}

/// A request to pkid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// The CAs on this pkid.
    Authorities,
    /// A DER certificate request, under a template the CA offers.
    Submit {
        ca: String,
        template: String,
        csr: Vec<u8>,
    },
    Approve {
        ca: String,
        request: i64,
    },
    Deny {
        ca: String,
        request: i64,
        reason: Option<String>,
    },
    /// Revokes a certificate, with an RFC 5280 reason code.
    Revoke {
        ca: String,
        serial: Vec<u8>,
        reason: u8,
    },
    Request {
        ca: String,
        request: i64,
    },
    Requests {
        ca: String,
        query: RequestQuery,
    },
    Certificate {
        ca: String,
        serial: Vec<u8>,
    },
    /// The certificate issued for a request.
    CertificateFor {
        ca: String,
        request: i64,
    },
    Certificates {
        ca: String,
        query: CertificateQuery,
    },
}

impl Request {
    /// The operation's name on the wire.
    pub fn op(&self) -> &'static str {
        match self {
            Self::Authorities => "authorities",
            Self::Submit { .. } => "submit",
            Self::Approve { .. } => "approve",
            Self::Deny { .. } => "deny",
            Self::Revoke { .. } => "revoke",
            Self::Request { .. } => "request",
            Self::Requests { .. } => "requests",
            Self::Certificate { .. } => "certificate",
            Self::CertificateFor { .. } => "certificate-for",
            Self::Certificates { .. } => "certificates",
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        let mut map = MapWriter::new();
        map.str("op", self.op());
        match self {
            Self::Authorities => {}
            Self::Submit { ca, template, csr } => {
                map.str("ca", ca).str("template", template).bin("csr", csr);
            }
            Self::Approve { ca, request }
            | Self::Request { ca, request }
            | Self::CertificateFor { ca, request } => {
                map.str("ca", ca).int("request", *request);
            }
            Self::Deny {
                ca,
                request,
                reason,
            } => {
                map.str("ca", ca)
                    .int("request", *request)
                    .opt_str("reason", reason.as_deref());
            }
            Self::Revoke { ca, serial, reason } => {
                map.str("ca", ca)
                    .bin("serial", serial)
                    .uint("reason", u64::from(*reason));
            }
            Self::Requests { ca, query } => {
                map.str("ca", ca)
                    .opt_str("status", query.status.map(RequestStatus::as_str))
                    .opt_int("after", query.after)
                    .uint("limit", u64::from(query.limit));
            }
            Self::Certificate { ca, serial } => {
                map.str("ca", ca).bin("serial", serial);
            }
            Self::Certificates { ca, query } => {
                map.str("ca", ca)
                    .bool("unrevoked-only", query.unrevoked_only)
                    .opt_int("after", query.after)
                    .uint("limit", u64::from(query.limit));
            }
        }
        map.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        let fields = Fields::read(bytes)?;
        let ca = || fields.str("ca").map(str::to_owned);
        let limit = || -> Result<u32, CodecError> {
            Ok(u32::try_from(fields.uint("limit")?)
                .unwrap_or(u32::MAX)
                .min(crate::MAX_LISTING))
        };
        let request = match fields.str("op")? {
            "authorities" => Self::Authorities,
            "submit" => Self::Submit {
                ca: ca()?,
                template: fields.str("template")?.to_owned(),
                csr: fields.bin("csr")?.to_vec(),
            },
            "approve" => Self::Approve {
                ca: ca()?,
                request: fields.int("request")?,
            },
            "deny" => Self::Deny {
                ca: ca()?,
                request: fields.int("request")?,
                reason: fields.opt_str("reason")?.map(str::to_owned),
            },
            "revoke" => Self::Revoke {
                ca: ca()?,
                serial: fields.bin("serial")?.to_vec(),
                reason: u8::try_from(fields.uint("reason")?)
                    .map_err(|_| malformed("revocation reason out of range"))?,
            },
            "request" => Self::Request {
                ca: ca()?,
                request: fields.int("request")?,
            },
            "requests" => Self::Requests {
                ca: ca()?,
                query: RequestQuery {
                    status: fields
                        .opt_str("status")?
                        .map(|text| {
                            RequestStatus::parse(text)
                                .ok_or_else(|| malformed(format!("status {text}")))
                        })
                        .transpose()?,
                    after: fields.opt_int("after")?,
                    limit: limit()?,
                },
            },
            "certificate" => Self::Certificate {
                ca: ca()?,
                serial: fields.bin("serial")?.to_vec(),
            },
            "certificate-for" => Self::CertificateFor {
                ca: ca()?,
                request: fields.int("request")?,
            },
            "certificates" => Self::Certificates {
                ca: ca()?,
                query: CertificateQuery {
                    unrevoked_only: fields.bool("unrevoked-only")?,
                    after: fields.opt_int("after")?,
                    limit: limit()?,
                },
            },
            other => return Err(malformed(format!("unknown operation {other}"))),
        };
        Ok(request)
    }
}

/// A template a CA offers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemplateInfo {
    pub id: String,
    pub name: String,
}

/// A CA on this pkid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityInfo {
    pub id: String,
    pub name: String,
    /// The CA's DER certificate.
    pub certificate: Vec<u8>,
    pub templates: Vec<TemplateInfo>,
    /// Whether pkid can sign with the CA's key now.
    pub key_available: bool,
}

/// What became of a submitted or approved request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Issued: the DER certificate.
    Issued(Vec<u8>),
    Pending,
    Denied,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmissionInfo {
    pub request: i64,
    pub outcome: Outcome,
    /// Why the request was held or refused.
    pub reasons: Vec<String>,
}

/// A request as pkid recorded it. Times are Unix seconds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestInfo {
    pub id: i64,
    pub template: String,
    pub names: Vec<String>,
    /// The requester's SID.
    pub requester: String,
    pub submitted: i64,
    pub status: RequestStatus,
    pub reasons: Vec<String>,
    pub decided: Option<i64>,
    /// The officer who decided it, as a SID.
    pub decider: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationInfo {
    pub revoked: i64,
    /// The RFC 5280 reason code.
    pub reason: u8,
    pub revoker: String,
}

/// A certificate pkid issued. Times are Unix seconds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateInfo {
    pub serial: Vec<u8>,
    pub request: i64,
    pub der: Vec<u8>,
    pub not_before: i64,
    pub not_after: i64,
    pub owner: Option<String>,
    pub revocation: Option<RevocationInfo>,
}

/// Why pkid refused or failed a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// The caller lacks the right this needs.
    AccessDenied,
    /// The CA, template, request or certificate doesn't exist, or the caller
    /// may not see it.
    NotFound,
    /// The request is malformed or unusable.
    BadRequest,
    /// The request was already decided, or the certificate already revoked.
    Conflict,
    /// The officer is the requester.
    SelfApproval,
    /// Policy as it now stands refuses a held request.
    NowRefused,
    /// The CA's key is unavailable or locked.
    KeyUnavailable,
    /// pkid can't serve this now, such as while its configuration is
    /// invalid.
    Unavailable,
    /// pkid failed.
    Internal,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AccessDenied => "access-denied",
            Self::NotFound => "not-found",
            Self::BadRequest => "bad-request",
            Self::Conflict => "conflict",
            Self::SelfApproval => "self-approval",
            Self::NowRefused => "now-refused",
            Self::KeyUnavailable => "key-unavailable",
            Self::Unavailable => "unavailable",
            Self::Internal => "internal",
        }
    }

    /// Unknown codes from a newer pkid read as [`ErrorCode::Internal`].
    pub fn parse(text: &str) -> Self {
        match text {
            "access-denied" => Self::AccessDenied,
            "not-found" => Self::NotFound,
            "bad-request" => Self::BadRequest,
            "conflict" => Self::Conflict,
            "self-approval" => Self::SelfApproval,
            "now-refused" => Self::NowRefused,
            "key-unavailable" => Self::KeyUnavailable,
            "unavailable" => Self::Unavailable,
            _ => Self::Internal,
        }
    }
}

/// An error reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireError {
    pub code: ErrorCode,
    pub message: String,
}

impl WireError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for WireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for WireError {}

/// A successful reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    Authorities(Vec<AuthorityInfo>),
    Submission(SubmissionInfo),
    /// The operation was done; there is nothing to return.
    Done,
    Request(RequestInfo),
    Requests(Vec<RequestInfo>),
    Certificate(CertificateInfo),
    Certificates(Vec<CertificateInfo>),
}

impl Reply {
    fn kind(&self) -> &'static str {
        match self {
            Self::Authorities(_) => "authorities",
            Self::Submission(_) => "submission",
            Self::Done => "done",
            Self::Request(_) => "request",
            Self::Requests(_) => "requests",
            Self::Certificate(_) => "certificate",
            Self::Certificates(_) => "certificates",
        }
    }

    /// Encodes a reply, successful or not.
    pub fn encode(reply: &Result<Reply, WireError>) -> Result<Vec<u8>, CodecError> {
        let mut map = MapWriter::new();
        let reply = match reply {
            Ok(reply) => reply,
            Err(error) => {
                map.str("status", "error")
                    .str("code", error.code.as_str())
                    .str("message", &error.message);
                return map.finish();
            }
        };
        map.str("status", "ok").str("kind", reply.kind());
        match reply {
            Reply::Done => {}
            Reply::Authorities(authorities) => {
                let encoded = authorities
                    .iter()
                    .map(encode_authority)
                    .collect::<Result<Vec<_>, _>>()?;
                map.array("authorities", &encoded);
            }
            Reply::Submission(submission) => {
                map.int("request", submission.request)
                    .strings("reasons", &submission.reasons);
                match &submission.outcome {
                    Outcome::Issued(certificate) => {
                        map.str("outcome", "issued").bin("certificate", certificate);
                    }
                    Outcome::Pending => {
                        map.str("outcome", "pending");
                    }
                    Outcome::Denied => {
                        map.str("outcome", "denied");
                    }
                }
            }
            Reply::Request(request) => {
                map.raw("request", &encode_request_info(request)?);
            }
            Reply::Requests(requests) => {
                let encoded = requests
                    .iter()
                    .map(encode_request_info)
                    .collect::<Result<Vec<_>, _>>()?;
                map.array("requests", &encoded);
            }
            Reply::Certificate(certificate) => {
                map.raw("certificate", &encode_certificate(certificate)?);
            }
            Reply::Certificates(certificates) => {
                let encoded = certificates
                    .iter()
                    .map(encode_certificate)
                    .collect::<Result<Vec<_>, _>>()?;
                map.array("certificates", &encoded);
            }
        }
        map.finish()
    }

    /// Decodes a reply. An error reply decodes to `Ok(Err(..))`; a
    /// malformed one to `Err`.
    pub fn decode(bytes: &[u8]) -> Result<Result<Reply, WireError>, CodecError> {
        let fields = Fields::read(bytes)?;
        match fields.str("status")? {
            "ok" => {}
            "error" => {
                return Ok(Err(WireError {
                    code: ErrorCode::parse(fields.str("code")?),
                    message: fields.str("message")?.to_owned(),
                }))
            }
            other => return Err(malformed(format!("status {other}"))),
        }
        let reply = match fields.str("kind")? {
            "done" => Reply::Done,
            "authorities" => Reply::Authorities(fields.array("authorities", decode_authority)?),
            "submission" => Reply::Submission(SubmissionInfo {
                request: fields.int("request")?,
                reasons: fields.strings("reasons")?,
                outcome: match fields.str("outcome")? {
                    "issued" => Outcome::Issued(fields.bin("certificate")?.to_vec()),
                    "pending" => Outcome::Pending,
                    "denied" => Outcome::Denied,
                    other => return Err(malformed(format!("outcome {other}"))),
                },
            }),
            "request" => Reply::Request(decode_request_info_fields(&fields.map("request")?)?),
            "requests" => Reply::Requests(fields.array("requests", decode_request_info)?),
            "certificate" => {
                Reply::Certificate(decode_certificate_fields(&fields.map("certificate")?)?)
            }
            "certificates" => {
                Reply::Certificates(fields.array("certificates", decode_certificate)?)
            }
            other => return Err(malformed(format!("reply kind {other}"))),
        };
        Ok(Ok(reply))
    }
}

fn encode_authority(authority: &AuthorityInfo) -> Result<Vec<u8>, CodecError> {
    let templates = authority
        .templates
        .iter()
        .map(|template| {
            MapWriter::new()
                .str("id", &template.id)
                .str("name", &template.name)
                .finish()
        })
        .collect::<Result<Vec<_>, _>>()?;
    MapWriter::new()
        .str("id", &authority.id)
        .str("name", &authority.name)
        .bin("certificate", &authority.certificate)
        .array("templates", &templates)
        .bool("key-available", authority.key_available)
        .finish()
}

fn decode_authority(bytes: &[u8]) -> Result<AuthorityInfo, CodecError> {
    let fields = Fields::read(bytes)?;
    Ok(AuthorityInfo {
        id: fields.str("id")?.to_owned(),
        name: fields.str("name")?.to_owned(),
        certificate: fields.bin("certificate")?.to_vec(),
        templates: fields.array("templates", |bytes| {
            let template = Fields::read(bytes)?;
            Ok(TemplateInfo {
                id: template.str("id")?.to_owned(),
                name: template.str("name")?.to_owned(),
            })
        })?,
        key_available: fields.bool("key-available")?,
    })
}

fn encode_request_info(request: &RequestInfo) -> Result<Vec<u8>, CodecError> {
    MapWriter::new()
        .int("id", request.id)
        .str("template", &request.template)
        .strings("names", &request.names)
        .str("requester", &request.requester)
        .int("submitted", request.submitted)
        .str("status", request.status.as_str())
        .strings("reasons", &request.reasons)
        .opt_int("decided", request.decided)
        .opt_str("decider", request.decider.as_deref())
        .finish()
}

fn decode_request_info(bytes: &[u8]) -> Result<RequestInfo, CodecError> {
    decode_request_info_fields(&Fields::read(bytes)?)
}

fn decode_request_info_fields(fields: &Fields<'_>) -> Result<RequestInfo, CodecError> {
    let status = fields.str("status")?;
    Ok(RequestInfo {
        id: fields.int("id")?,
        template: fields.str("template")?.to_owned(),
        names: fields.strings("names")?,
        requester: fields.str("requester")?.to_owned(),
        submitted: fields.int("submitted")?,
        status: RequestStatus::parse(status)
            .ok_or_else(|| malformed(format!("status {status}")))?,
        reasons: fields.strings("reasons")?,
        decided: fields.opt_int("decided")?,
        decider: fields.opt_str("decider")?.map(str::to_owned),
    })
}

fn encode_certificate(certificate: &CertificateInfo) -> Result<Vec<u8>, CodecError> {
    let mut map = MapWriter::new();
    map.bin("serial", &certificate.serial)
        .int("request", certificate.request)
        .bin("der", &certificate.der)
        .int("not-before", certificate.not_before)
        .int("not-after", certificate.not_after)
        .opt_str("owner", certificate.owner.as_deref());
    if let Some(revocation) = &certificate.revocation {
        let revocation = MapWriter::new()
            .int("revoked", revocation.revoked)
            .uint("reason", u64::from(revocation.reason))
            .str("revoker", &revocation.revoker)
            .finish()?;
        map.raw("revocation", &revocation);
    }
    map.finish()
}

fn decode_certificate(bytes: &[u8]) -> Result<CertificateInfo, CodecError> {
    decode_certificate_fields(&Fields::read(bytes)?)
}

fn decode_certificate_fields(fields: &Fields<'_>) -> Result<CertificateInfo, CodecError> {
    let revocation = fields
        .opt_map("revocation")?
        .map(|revocation| -> Result<RevocationInfo, CodecError> {
            Ok(RevocationInfo {
                revoked: revocation.int("revoked")?,
                reason: u8::try_from(revocation.uint("reason")?)
                    .map_err(|_| malformed("revocation reason out of range"))?,
                revoker: revocation.str("revoker")?.to_owned(),
            })
        })
        .transpose()?;
    Ok(CertificateInfo {
        serial: fields.bin("serial")?.to_vec(),
        request: fields.int("request")?,
        der: fields.bin("der")?.to_vec(),
        not_before: fields.int("not-before")?,
        not_after: fields.int("not-after")?,
        owner: fields.opt_str("owner")?.map(str::to_owned),
        revocation,
    })
}
