//! Turning a wire request into a pipeline call, and its result into a reply.
//!
//! Nothing here touches the operating system: the caller, the directory and
//! the audit trail are supplied, so the whole of pkid's request handling is
//! tested without a Peios kernel.

use std::collections::HashMap;

use pki_core::{RevocationReason, SerialNumber, Sid};
use pki_keys::OpenKey;
use pki_pipeline::{
    Authority, Directory, Pipeline, PipelineError, Principal, Submission, CA_MANAGE, CA_OFFICER,
    CA_READ, CA_REQUEST,
};
use pki_store::{CertificateFilter, RequestFilter, RequestId, RequestStatus, Store};
use pkid_core::{
    AuthorityInfo, CertificateInfo, ErrorCode, Outcome, Reply, Request, RequestInfo,
    RevocationInfo, SubmissionInfo, TemplateInfo, WireError,
};
use time::OffsetDateTime;

use crate::config::{AuthorityConfig, Loaded};

/// Something pkid records in its audit trail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Submitted {
        ca: String,
        request: i64,
        requester: Sid,
        /// `issued`, `pending` or `denied`.
        outcome: &'static str,
    },
    Approved {
        ca: String,
        request: i64,
        officer: Sid,
    },
    Denied {
        ca: String,
        request: i64,
        officer: Sid,
    },
    Revoked {
        ca: String,
        serial: Vec<u8>,
        reason: u8,
        officer: Sid,
    },
}

/// Where events go: eventd, or a test's record.
pub trait Audit {
    fn record(&self, event: Event);
}

/// Everything a request is handled against.
pub struct State {
    /// The CA database, unless it couldn't be opened.
    pub store: Result<Store, String>,
    /// The configuration, unless it is invalid.
    pub loaded: Result<Loaded, String>,
    /// Each CA's opened key, by CA identifier. A CA whose key is
    /// unavailable or locked has none.
    pub keys: HashMap<String, OpenKey>,
}

/// Handles one request for `caller`.
pub fn handle(
    state: &mut State,
    request: Request,
    caller: &dyn Principal,
    directory: &dyn Directory,
    audit: &dyn Audit,
    now: OffsetDateTime,
) -> Result<Reply, WireError> {
    let loaded = state.loaded.as_ref().map_err(|reason| {
        WireError::new(
            ErrorCode::Unavailable,
            format!("pkid's configuration is invalid: {reason}"),
        )
    })?;
    let store = state.store.as_mut().map_err(|reason| {
        WireError::new(
            ErrorCode::Unavailable,
            format!("pkid's database is unavailable: {reason}"),
        )
    })?;

    if request == Request::Authorities {
        return authorities(loaded, &state.keys, caller);
    }
    let ca_id = match &request {
        Request::Submit { ca, .. }
        | Request::Approve { ca, .. }
        | Request::Deny { ca, .. }
        | Request::Revoke { ca, .. }
        | Request::Request { ca, .. }
        | Request::Requests { ca, .. }
        | Request::Certificate { ca, .. }
        | Request::CertificateFor { ca, .. }
        | Request::Certificates { ca, .. } => ca.clone(),
        Request::Authorities => unreachable!("handled above"),
    };
    let config = loaded
        .authority(&ca_id)
        .ok_or_else(|| WireError::new(ErrorCode::NotFound, format!("no CA {ca_id}")))?;
    let authority = Authority {
        id: config.id.clone(),
        certificate: config.certificate.clone(),
        security: config.security.clone(),
        templates: config.templates.clone(),
        crl_distribution_points: config.crl_distribution_points.clone(),
        signer: state.keys.get(&config.id).map(|key| key.as_ref() as _),
    };
    let mut pipeline = Pipeline::new(store, &loaded.configuration, directory);

    let reply = match request {
        Request::Authorities => unreachable!("handled above"),
        Request::Submit { template, csr, .. } => {
            let template = template.to_ascii_lowercase();
            let submission = pipeline
                .submit(&authority, &template, &csr, caller, now)
                .map_err(wire)?;
            let info = submission_info(submission);
            audit.record(Event::Submitted {
                ca: ca_id,
                request: info.request,
                requester: caller.sid().clone(),
                outcome: outcome_name(&info.outcome),
            });
            Reply::Submission(info)
        }
        Request::Approve { request, .. } => {
            let submission = pipeline
                .approve(&authority, RequestId::new(request), caller, now)
                .map_err(wire)?;
            audit.record(Event::Approved {
                ca: ca_id,
                request,
                officer: caller.sid().clone(),
            });
            Reply::Submission(submission_info(submission))
        }
        Request::Deny {
            request, reason, ..
        } => {
            pipeline
                .deny(
                    &authority,
                    RequestId::new(request),
                    caller,
                    reason.as_deref(),
                    now,
                )
                .map_err(wire)?;
            audit.record(Event::Denied {
                ca: ca_id,
                request,
                officer: caller.sid().clone(),
            });
            Reply::Done
        }
        Request::Revoke { serial, reason, .. } => {
            let number = serial_number(&serial)?;
            let code = revocation_reason(reason)?;
            pipeline
                .revoke(&authority, &number, code, caller, now)
                .map_err(wire)?;
            audit.record(Event::Revoked {
                ca: ca_id,
                serial,
                reason,
                officer: caller.sid().clone(),
            });
            Reply::Done
        }
        Request::Request { request, .. } => Reply::Request(request_info(
            pipeline
                .request(&authority, RequestId::new(request), caller)
                .map_err(wire)?,
        )),
        Request::Requests { query, .. } => {
            let filter = RequestFilter {
                status: query.status.map(|status| match status {
                    pkid_core::RequestStatus::Pending => RequestStatus::Pending,
                    pkid_core::RequestStatus::Issued => RequestStatus::Issued,
                    pkid_core::RequestStatus::Denied => RequestStatus::Denied,
                }),
                after: query.after.map(RequestId::new),
                limit: listing_limit(query.limit),
                ..RequestFilter::default()
            };
            let requests = pipeline
                .requests(&authority, filter, caller)
                .map_err(wire)?;
            Reply::Requests(requests.into_iter().map(request_info).collect())
        }
        Request::Certificate { serial, .. } => {
            let number = serial_number(&serial)?;
            Reply::Certificate(certificate_info(
                pipeline
                    .certificate(&authority, &number, caller)
                    .map_err(wire)?,
            ))
        }
        Request::CertificateFor { request, .. } => Reply::Certificate(certificate_info(
            pipeline
                .certificate_for(&authority, RequestId::new(request), caller)
                .map_err(wire)?,
        )),
        Request::Certificates { query, .. } => {
            let filter = CertificateFilter {
                unrevoked_only: query.unrevoked_only,
                after: query.after.map(RequestId::new),
                limit: listing_limit(query.limit),
                ..CertificateFilter::default()
            };
            let certificates = pipeline
                .certificates(&authority, filter, caller)
                .map_err(wire)?;
            Reply::Certificates(certificates.into_iter().map(certificate_info).collect())
        }
    };
    Ok(reply)
}

/// The CAs the caller holds any right at.
fn authorities(
    loaded: &Loaded,
    keys: &HashMap<String, OpenKey>,
    caller: &dyn Principal,
) -> Result<Reply, WireError> {
    let any = CA_READ | CA_REQUEST | CA_OFFICER | CA_MANAGE;
    let mut listed = Vec::new();
    for authority in &loaded.authorities {
        let granted = caller
            .checker()
            .granted(&authority.security, any, None)
            .map_err(|error| WireError::new(ErrorCode::Internal, error.to_string()))?;
        if granted != 0 {
            listed.push(authority_info(loaded, keys, authority));
        }
    }
    Ok(Reply::Authorities(listed))
}

fn authority_info(
    loaded: &Loaded,
    keys: &HashMap<String, OpenKey>,
    authority: &AuthorityConfig,
) -> AuthorityInfo {
    AuthorityInfo {
        id: authority.id.clone(),
        name: authority.name.clone(),
        certificate: authority.certificate.clone(),
        templates: authority
            .templates
            .iter()
            .filter_map(|id| {
                loaded
                    .configuration
                    .templates
                    .get(id)
                    .map(|template| TemplateInfo {
                        id: id.clone(),
                        name: template.name.clone(),
                    })
            })
            .collect(),
        key_available: keys.contains_key(&authority.id),
    }
}

fn listing_limit(limit: u32) -> usize {
    let limit = if limit == 0 {
        pkid_core::MAX_LISTING
    } else {
        limit.min(pkid_core::MAX_LISTING)
    };
    limit as usize
}

fn serial_number(bytes: &[u8]) -> Result<SerialNumber, WireError> {
    SerialNumber::from_bytes(bytes)
        .map_err(|_| WireError::new(ErrorCode::BadRequest, "not a certificate serial number"))
}

/// An RFC 5280 reason code. 7 is unused and 8, removeFromCRL, only appears
/// in delta CRLs.
fn revocation_reason(code: u8) -> Result<RevocationReason, WireError> {
    Ok(match code {
        0 => RevocationReason::Unspecified,
        1 => RevocationReason::KeyCompromise,
        2 => RevocationReason::CaCompromise,
        3 => RevocationReason::AffiliationChanged,
        4 => RevocationReason::Superseded,
        5 => RevocationReason::CessationOfOperation,
        6 => RevocationReason::CertificateHold,
        9 => RevocationReason::PrivilegeWithdrawn,
        _ => {
            return Err(WireError::new(
                ErrorCode::BadRequest,
                format!("{code} is not a revocation reason"),
            ))
        }
    })
}

fn reason_code(reason: RevocationReason) -> u8 {
    match reason {
        RevocationReason::Unspecified => 0,
        RevocationReason::KeyCompromise => 1,
        RevocationReason::CaCompromise => 2,
        RevocationReason::AffiliationChanged => 3,
        RevocationReason::Superseded => 4,
        RevocationReason::CessationOfOperation => 5,
        RevocationReason::CertificateHold => 6,
        RevocationReason::PrivilegeWithdrawn => 9,
    }
}

fn submission_info(submission: Submission) -> SubmissionInfo {
    match submission {
        Submission::Issued {
            request,
            certificate,
        } => SubmissionInfo {
            request: request.get(),
            outcome: Outcome::Issued(certificate),
            reasons: Vec::new(),
        },
        Submission::Pending { request, reasons } => SubmissionInfo {
            request: request.get(),
            outcome: Outcome::Pending,
            reasons,
        },
        Submission::Denied { request, reasons } => SubmissionInfo {
            request: request.get(),
            outcome: Outcome::Denied,
            reasons,
        },
    }
}

fn outcome_name(outcome: &Outcome) -> &'static str {
    match outcome {
        Outcome::Issued(_) => "issued",
        Outcome::Pending => "pending",
        Outcome::Denied => "denied",
    }
}

fn request_info(request: pki_store::Request) -> RequestInfo {
    RequestInfo {
        id: request.id.get(),
        template: request.template,
        names: request.names,
        requester: request.requester.as_str().to_owned(),
        submitted: request.submitted.unix_timestamp(),
        status: match request.status {
            RequestStatus::Pending => pkid_core::RequestStatus::Pending,
            RequestStatus::Issued => pkid_core::RequestStatus::Issued,
            RequestStatus::Denied => pkid_core::RequestStatus::Denied,
        },
        reasons: request.reasons,
        decided: request.decided.map(OffsetDateTime::unix_timestamp),
        decider: request.decider.map(|sid| sid.as_str().to_owned()),
    }
}

fn certificate_info(certificate: pki_store::Certificate) -> CertificateInfo {
    CertificateInfo {
        serial: certificate.serial.as_bytes().to_vec(),
        request: certificate.request.get(),
        der: certificate.der,
        not_before: certificate.not_before.unix_timestamp(),
        not_after: certificate.not_after.unix_timestamp(),
        owner: certificate.owner.map(|sid| sid.as_str().to_owned()),
        revocation: certificate.revocation.map(|revocation| RevocationInfo {
            revoked: revocation.revoked.unix_timestamp(),
            reason: reason_code(revocation.reason),
            revoker: revocation.revoker.as_str().to_owned(),
        }),
    }
}

/// The reply for a pipeline failure.
fn wire(error: PipelineError) -> WireError {
    let code = match &error {
        PipelineError::AccessDenied => ErrorCode::AccessDenied,
        PipelineError::NoSuchTemplate(_)
        | PipelineError::NoSuchRequest(_)
        | PipelineError::NoSuchCertificate => ErrorCode::NotFound,
        PipelineError::BadRequest(_) => ErrorCode::BadRequest,
        PipelineError::NotPending(..) | PipelineError::AlreadyRevoked => ErrorCode::Conflict,
        PipelineError::SelfApproval => ErrorCode::SelfApproval,
        PipelineError::NowRefused(_) => ErrorCode::NowRefused,
        PipelineError::KeyUnavailable => ErrorCode::KeyUnavailable,
        PipelineError::Configuration(_) => ErrorCode::Unavailable,
        PipelineError::Issue(_) | PipelineError::Identity(_) | PipelineError::Store(_) => {
            ErrorCode::Internal
        }
    };
    WireError::new(code, error.to_string())
}
