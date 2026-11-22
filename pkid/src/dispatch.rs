//! Turning a wire request into a pipeline call, and its result into a reply.
//!
//! Nothing here touches the operating system: the caller, the directory,
//! the audit trail, the configuration writer and the key providers are
//! supplied, so the whole of pkid's request handling is tested without a
//! Peios kernel.

use std::collections::HashMap;

use pki_core::{RevocationReason, SerialNumber, Sid};
use pki_keys::{KeyError, KeyProviders, OpenKey};
use pki_pipeline::{
    Authority, Directory, Pipeline, PipelineError, Principal, Submission, CA_ALL, CA_MANAGE,
};
use pki_policy::{SecurityBlob, Values, TEMPLATE_ENROLL};
use pki_store::{CertificateFilter, RequestFilter, RequestId, RequestStatus, Store};
use pkid_core::{
    AccessInfo, AuthorityInfo, CertificateInfo, ErrorCode, Outcome, Reply, Request, RequestInfo,
    RevocationInfo, SubmissionInfo, TemplateInfo, WireError,
};
use time::OffsetDateTime;

use crate::config::{self, AuthorityConfig, Defaults, Loaded, Source};
use crate::crl::{self, Publication, Publisher};
use crate::manage;

/// Something pkid records in its audit trail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// pkid took up a configuration; `error` says why it can't serve it.
    ConfigurationLoaded { error: Option<String> },
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
    /// A CA was created, imported, installed or reconfigured, or its key
    /// exported: `action` says which.
    Managed {
        ca: String,
        action: &'static str,
        operator: Sid,
    },
    /// A CA signed and published a CRL: on pkid's own schedule, or at an
    /// officer's request.
    CrlPublished {
        ca: String,
        number: u64,
        next_update: i64,
        officer: Option<Sid>,
    },
    /// A CA's CRL expires soon, or it has none to publish.
    CrlExpiring {
        ca: String,
        next_update: Option<i64>,
    },
}

/// Where events go: eventd, or a test's record.
pub trait Audit {
    fn record(&self, event: Event);
}

/// The configuration pkid may write: its CAs' records, and only those.
pub trait Configurator {
    /// Writes `values` to `Authorities\<id>`, creating the key if need be,
    /// and removes the values named in `remove`, all at once.
    fn write_authority(&self, id: &str, values: &Values, remove: &[&str]) -> Result<(), String>;

    /// Reads the configuration as it now stands.
    fn read(&self) -> Source;
}

/// What pkid needs besides its state to handle a request.
pub struct Services<'a> {
    pub directory: &'a dyn Directory,
    pub audit: &'a dyn Audit,
    pub configurator: &'a dyn Configurator,
    pub providers: &'a KeyProviders,
    pub defaults: &'a Defaults,
    /// Where CRLs go once signed.
    pub publishers: &'a [Box<dyn Publisher>],
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
    /// What `loaded` came from, so an unchanged Registry isn't loaded again.
    pub source: Option<Source>,
    /// What has been published and warned about since pkid started.
    pub publication: Publication,
}

/// Takes up the configuration read from `source`, unless it is what
/// `state` already has. An invalid configuration replaces a valid one, so
/// pkid stops issuing rather than serving what an administrator no longer
/// intends.
pub fn apply(state: &mut State, source: Source, services: &Services<'_>) {
    if state.source.as_ref() == Some(&source) {
        return;
    }
    let loaded = match &source {
        Ok(snapshot) => {
            config::load(snapshot, services.defaults).map_err(|error| error.to_string())
        }
        Err(error) => Err(error.clone()),
    };
    services.audit.record(Event::ConfigurationLoaded {
        error: loaded.as_ref().err().cloned(),
    });
    let previous_keys = std::mem::take(&mut state.keys);
    state.keys = match &loaded {
        Ok(loaded) => open_keys(
            loaded,
            state.loaded.as_ref().ok(),
            previous_keys,
            services.providers,
        ),
        Err(_) => HashMap::new(),
    };
    state.loaded = loaded;
    state.source = Some(source);
    // A CA's distribution points may have changed: publish every current
    // CRL again, to wherever its CA now says, on the next round.
    state.publication.forget_published();
}

/// Opens the keys of `loaded`'s CAs that need no passphrase, keeping those
/// in `previous` whose CA still uses the same key.
fn open_keys(
    loaded: &Loaded,
    previous_config: Option<&Loaded>,
    mut previous: HashMap<String, OpenKey>,
    providers: &KeyProviders,
) -> HashMap<String, OpenKey> {
    let mut keys = HashMap::new();
    for authority in &loaded.authorities {
        let unchanged = previous_config
            .and_then(|config| config.authority(&authority.id))
            .is_some_and(|old| old.key == authority.key);
        if unchanged {
            if let Some(key) = previous.remove(&authority.id) {
                keys.insert(authority.id.clone(), key);
                continue;
            }
        }
        let opened = providers
            .for_key(&authority.key)
            .and_then(|provider| provider.open(&authority.key, None));
        if let Ok(key) = opened {
            keys.insert(authority.id.clone(), key);
        }
    }
    keys
}

/// Handles one request for `caller`.
pub fn handle(
    state: &mut State,
    request: Request,
    caller: &dyn Principal,
    services: &Services<'_>,
    now: OffsetDateTime,
) -> Result<Reply, WireError> {
    if let Err(reason) = &state.loaded {
        return Err(WireError::new(
            ErrorCode::Unavailable,
            format!("pkid's configuration is invalid: {reason}"),
        ));
    }
    if let Err(reason) = &state.store {
        return Err(WireError::new(
            ErrorCode::Unavailable,
            format!("pkid's database is unavailable: {reason}"),
        ));
    }
    match request {
        Request::Authorities => authorities(state, caller),
        Request::Access => access(state, caller),
        Request::PublishCrl { ca, passphrase } => {
            crl::handle_publish(state, &ca, passphrase.as_ref(), caller, services, now)
        }
        Request::Revoke { ref ca, .. } => {
            let ca = ca.clone();
            let reply = pipeline_request(state, request, caller, services, now)?;
            crl::after_revocation(state, &ca, services, now);
            Ok(reply)
        }
        Request::CreateAuthority { .. }
        | Request::SignSubordinate { .. }
        | Request::InstallAuthority { .. }
        | Request::ImportAuthority { .. }
        | Request::ExportKey { .. }
        | Request::ConfigureAuthority { .. }
        | Request::SetAuthoritySecurity { .. } => {
            manage::handle(state, request, caller, services, now)
        }
        request => pipeline_request(state, request, caller, services, now),
    }
}

fn pipeline_request(
    state: &mut State,
    request: Request,
    caller: &dyn Principal,
    services: &Services<'_>,
    now: OffsetDateTime,
) -> Result<Reply, WireError> {
    let State {
        store,
        loaded,
        keys,
        ..
    } = state;
    let (Ok(store), Ok(loaded)) = (store.as_mut(), loaded.as_ref()) else {
        unreachable!("checked by handle");
    };
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
        _ => unreachable!("routed by handle"),
    };
    let config = loaded
        .authority(&ca_id)
        .ok_or_else(|| WireError::new(ErrorCode::NotFound, format!("no CA {ca_id}")))?;
    let authority = authority(config, keys)?;
    let mut pipeline = Pipeline::new(store, &loaded.configuration, services.directory);
    let audit = services.audit;

    let reply = match request {
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
        _ => unreachable!("routed by handle"),
    };
    Ok(reply)
}

/// A CA as the pipeline uses it. A CA awaiting its certificate takes no
/// requests.
pub(crate) fn authority<'a>(
    config: &AuthorityConfig,
    keys: &'a HashMap<String, OpenKey>,
) -> Result<Authority<'a>, WireError> {
    let certificate = config.certificate.clone().ok_or_else(|| {
        WireError::new(
            ErrorCode::Unavailable,
            format!("CA {} awaits its certificate", config.id),
        )
    })?;
    Ok(Authority {
        id: config.id.clone(),
        certificate,
        security: config.security.clone(),
        templates: config.templates.clone(),
        crl_distribution_points: config.crl_distribution_points.clone(),
        signer: keys
            .get(&config.id)
            .map(|key| key.as_ref() as &dyn peios_crypto::Signer),
    })
}

/// The CAs the caller holds any right at.
fn authorities(state: &State, caller: &dyn Principal) -> Result<Reply, WireError> {
    let Ok(loaded) = &state.loaded else {
        unreachable!("checked by handle");
    };
    let mut listed = Vec::new();
    for authority in &loaded.authorities {
        let info = authority_info(
            loaded,
            &state.keys,
            state.store.as_ref().ok(),
            authority,
            caller,
        )?;
        if info.granted != 0 {
            listed.push(info);
        }
    }
    Ok(Reply::Authorities(listed))
}

/// What the caller may do beyond any one CA.
fn access(state: &State, caller: &dyn Principal) -> Result<Reply, WireError> {
    let Ok(loaded) = &state.loaded else {
        unreachable!("checked by handle");
    };
    let granted = caller
        .checker()
        .granted(&loaded.manage_security, CA_MANAGE, None)
        .map_err(|error| WireError::new(ErrorCode::Internal, error.to_string()))?;
    Ok(Reply::Access(AccessInfo {
        create: granted & CA_MANAGE == CA_MANAGE,
    }))
}

/// A CA as `caller` sees it: with the rights they hold at it, and whether
/// they may enrol from each template it offers.
pub(crate) fn authority_info(
    loaded: &Loaded,
    keys: &HashMap<String, OpenKey>,
    store: Option<&Store>,
    authority: &AuthorityConfig,
    caller: &dyn Principal,
) -> Result<AuthorityInfo, WireError> {
    let check = |security: &SecurityBlob, desired: u32| {
        caller
            .checker()
            .granted(security, desired, None)
            .map_err(|error| WireError::new(ErrorCode::Internal, error.to_string()))
    };
    let mut templates = Vec::new();
    for id in &authority.templates {
        if let Some(template) = loaded.configuration.templates.get(id) {
            templates.push(TemplateInfo {
                id: id.clone(),
                name: template.name.clone(),
                enroll: check(&template.enroll_security, TEMPLATE_ENROLL)? & TEMPLATE_ENROLL != 0,
            });
        }
    }
    Ok(AuthorityInfo {
        id: authority.id.clone(),
        name: authority.name.clone(),
        certificate: authority.certificate.clone(),
        request: authority.request.clone(),
        key: authority.key.to_string(),
        granted: check(&authority.security, CA_ALL)?,
        security: authority.security.as_bytes().to_vec(),
        templates,
        key_available: keys.contains_key(&authority.id),
        crl_lifetime_days: authority.crl_lifetime_days,
        crl: crl::latest(store, &authority.id),
    })
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
pub(crate) fn wire(error: PipelineError) -> WireError {
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

/// The reply for a key storage failure.
pub(crate) fn key_error(error: KeyError) -> WireError {
    let code = match &error {
        KeyError::Locked | KeyError::Unavailable(_) => ErrorCode::KeyUnavailable,
        KeyError::WrongPassphraseOrDamaged
        | KeyError::WeakPassphrase(_)
        | KeyError::UnsupportedAlgorithm(_)
        | KeyError::UnsupportedOption(_)
        | KeyError::InvalidReference(_)
        | KeyError::Malformed(_) => ErrorCode::BadRequest,
        KeyError::NotExportable | KeyError::AlreadyExists(_) => ErrorCode::Conflict,
        KeyError::Storage(..) | KeyError::Crypto(_) => ErrorCode::Internal,
    };
    WireError::new(code, error.to_string())
}
