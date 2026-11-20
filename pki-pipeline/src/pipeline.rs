use pki_core::{
    CertificateRequest, CrlProfile, IssuingCa, RevocationReason, RevokedCertificate, SerialNumber,
};
use pki_policy::{
    evaluate, leaf_profile, CommonNameRule, Decision, IssueContext, Outcome, Template,
};
use pki_store::{
    Certificate, CertificateFilter, Crl, NewCertificate, NewRequest, Request, RequestFilter,
    RequestId, RequestStatus, Revocation, Store, StoreError,
};
use time::{Duration, OffsetDateTime};

use crate::authority::{Authority, Configuration, Directory, Principal};
use crate::{PipelineError, CA_OFFICER, CA_READ, CA_REQUEST};

/// How many serial numbers to try before giving up. A collision between
/// two 127-bit random serials is all but impossible; this guards against a
/// broken random source rather than bad luck.
const SERIAL_ATTEMPTS: usize = 3;

/// What became of a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Submission {
    /// Issued: the DER certificate.
    Issued {
        request: RequestId,
        certificate: Vec<u8>,
    },
    /// Held for an officer, with why.
    Pending {
        request: RequestId,
        reasons: Vec<String>,
    },
    /// Refused by policy, with why.
    Denied {
        request: RequestId,
        reasons: Vec<String>,
    },
}

/// The request pipeline over one CA database and one configuration.
pub struct Pipeline<'a> {
    store: &'a mut Store,
    configuration: &'a Configuration,
    directory: &'a dyn Directory,
}

impl<'a> Pipeline<'a> {
    pub fn new(
        store: &'a mut Store,
        configuration: &'a Configuration,
        directory: &'a dyn Directory,
    ) -> Self {
        Self {
            store,
            configuration,
            directory,
        }
    }

    /// Submits a DER certificate request to `ca` under `template`.
    ///
    /// The requester needs Request at the CA; nothing is recorded without
    /// it. Policy then decides the request, and the outcome is recorded
    /// whatever it is. A request policy would issue fails with
    /// [`PipelineError::KeyUnavailable`], unrecorded, while the CA's key is
    /// unavailable.
    pub fn submit(
        &mut self,
        ca: &Authority<'_>,
        template: &str,
        csr: &[u8],
        requester: &dyn Principal,
        now: OffsetDateTime,
    ) -> Result<Submission, PipelineError> {
        require(requester, ca, CA_REQUEST)?;
        let definition = self.template(ca, template)?;
        let request = CertificateRequest::from_der(csr).map_err(PipelineError::BadRequest)?;
        let decision = evaluate(
            &request,
            definition,
            &self.configuration.names,
            self.directory,
            requester.checker(),
        )?;
        let new = NewRequest {
            ca: ca.id.clone(),
            template: template.to_string(),
            csr: csr.to_vec(),
            names: request.names().iter().map(ToString::to_string).collect(),
            requester: requester.sid().clone(),
            subject: requester.snapshot()?,
            submitted: now,
        };
        let reasons = reasons(&decision);
        match decision.outcome {
            Outcome::Reject => {
                let id = self.store.record_denied(&new, &reasons, now)?;
                Ok(Submission::Denied {
                    request: id,
                    reasons,
                })
            }
            Outcome::Pend => {
                let id = self.store.record_pending(&new, &reasons)?;
                Ok(Submission::Pending {
                    request: id,
                    reasons,
                })
            }
            Outcome::Issue => {
                let (id, certificate) =
                    self.issue(ca, definition, &request, &decision, now, |store, issued| {
                        store.record_issued(&new, issued)
                    })?;
                Ok(Submission::Issued {
                    request: id,
                    certificate,
                })
            }
        }
    }

    /// Issues a held request on an officer's approval.
    ///
    /// The officer needs Issue and Manage Certificates and must not be the
    /// requester. Policy runs again for the requester, against the
    /// configuration as it now stands; if it now refuses, the request stays
    /// held and the officer can deny it.
    pub fn approve(
        &mut self,
        ca: &Authority<'_>,
        id: RequestId,
        officer: &dyn Principal,
        now: OffsetDateTime,
    ) -> Result<Submission, PipelineError> {
        require(officer, ca, CA_OFFICER)?;
        let stored = self.pending(ca, id)?;
        if &stored.requester == officer.sid() {
            return Err(PipelineError::SelfApproval);
        }
        let definition = self.template(ca, &stored.template)?;
        let request =
            CertificateRequest::from_der(&stored.csr).map_err(PipelineError::BadRequest)?;
        let requester = self.directory.restore(&stored.subject)?;
        if requester.sid() != &stored.requester {
            return Err(PipelineError::Identity(
                "the stored identity is not the requester's".into(),
            ));
        }
        let decision = evaluate(
            &request,
            definition,
            &self.configuration.names,
            self.directory,
            requester.checker(),
        )?;
        if decision.outcome == Outcome::Reject {
            return Err(PipelineError::NowRefused(reasons(&decision)));
        }
        let ((), certificate) =
            self.issue(ca, definition, &request, &decision, now, |store, issued| {
                store.approve(id, officer.sid(), now, issued)
            })?;
        Ok(Submission::Issued {
            request: id,
            certificate,
        })
    }

    /// Refuses a held request on an officer's decision.
    pub fn deny(
        &mut self,
        ca: &Authority<'_>,
        id: RequestId,
        officer: &dyn Principal,
        reason: Option<&str>,
        now: OffsetDateTime,
    ) -> Result<(), PipelineError> {
        require(officer, ca, CA_OFFICER)?;
        self.pending(ca, id)?;
        let reasons: Vec<String> = reason.map(str::to_owned).into_iter().collect();
        self.store.deny(id, officer.sid(), now, &reasons)?;
        Ok(())
    }

    /// Revokes a certificate the CA issued.
    pub fn revoke(
        &mut self,
        ca: &Authority<'_>,
        serial: &SerialNumber,
        reason: RevocationReason,
        officer: &dyn Principal,
        now: OffsetDateTime,
    ) -> Result<(), PipelineError> {
        require(officer, ca, CA_OFFICER)?;
        let revocation = Revocation {
            revoked: now,
            reason,
            revoker: officer.sid().clone(),
        };
        self.store.revoke(&ca.id, serial, &revocation)?;
        Ok(())
    }

    /// Signs a CRL for `ca`, valid from `now` for `lifetime`, listing every
    /// certificate it has revoked that hasn't expired, and records it as
    /// the CA's latest. No one's rights are checked: pkid's own schedule
    /// calls this, and officers reach it through [`Pipeline::publish_crl`].
    pub fn issue_crl(
        &mut self,
        ca: &Authority<'_>,
        now: OffsetDateTime,
        lifetime: Duration,
    ) -> Result<Crl, PipelineError> {
        let signer = ca.signer.ok_or(PipelineError::KeyUnavailable)?;
        let issuing = IssuingCa::new(&ca.certificate, signer)
            .map_err(|error| PipelineError::Configuration(error.to_string()))?;
        // Whole seconds, as the CRL encodes its times.
        let now = now.replace_nanosecond(0).unwrap_or(now);
        let number = self.store.crl(&ca.id)?.map_or(1, |crl| crl.number + 1);
        let revoked = self
            .store
            .revoked(&ca.id, now)?
            .into_iter()
            .map(|(serial, revocation)| RevokedCertificate {
                serial,
                revoked_at: revocation.revoked,
                // RFC 5280 §5.3.1: an unspecified reason is left out.
                reason: match revocation.reason {
                    RevocationReason::Unspecified => None,
                    reason => Some(reason),
                },
            })
            .collect();
        let profile = CrlProfile {
            this_update: now,
            next_update: now + lifetime,
            number,
            revoked,
        };
        let list = issuing.sign_crl(&profile).map_err(PipelineError::Issue)?;
        let crl = Crl {
            number,
            this_update: profile.this_update,
            next_update: profile.next_update,
            der: list.der().to_vec(),
        };
        self.store.record_crl(&ca.id, &crl)?;
        Ok(crl)
    }

    /// An officer's request for a new CRL now, such as after revoking with
    /// a CA whose key pkid can't use unattended.
    pub fn publish_crl(
        &mut self,
        ca: &Authority<'_>,
        officer: &dyn Principal,
        now: OffsetDateTime,
        lifetime: Duration,
    ) -> Result<Crl, PipelineError> {
        require(officer, ca, CA_OFFICER)?;
        self.issue_crl(ca, now, lifetime)
    }

    /// A request to the CA. Callers without Read see only their own;
    /// others look as though they don't exist.
    pub fn request(
        &self,
        ca: &Authority<'_>,
        id: RequestId,
        caller: &dyn Principal,
    ) -> Result<Request, PipelineError> {
        let reads_all = holds(caller, ca, CA_READ)?;
        self.store
            .request(id)?
            .filter(|request| request.ca == ca.id)
            .filter(|request| reads_all || &request.requester == caller.sid())
            .ok_or(PipelineError::NoSuchRequest(id))
    }

    /// Requests to the CA matching `filter`. Callers without Read see only
    /// their own.
    pub fn requests(
        &self,
        ca: &Authority<'_>,
        mut filter: RequestFilter,
        caller: &dyn Principal,
    ) -> Result<Vec<Request>, PipelineError> {
        filter.ca = Some(ca.id.clone());
        if !holds(caller, ca, CA_READ)? {
            filter.requester = Some(caller.sid().clone());
        }
        Ok(self.store.requests(&filter)?)
    }

    /// The certificate issued for a request, which its requester may always
    /// retrieve.
    pub fn certificate_for(
        &self,
        ca: &Authority<'_>,
        id: RequestId,
        caller: &dyn Principal,
    ) -> Result<Certificate, PipelineError> {
        self.request(ca, id, caller)?;
        self.store
            .certificate_for(id)?
            .ok_or(PipelineError::NoSuchCertificate)
    }

    /// A certificate the CA issued. Callers without Read see only those
    /// they requested or own.
    pub fn certificate(
        &self,
        ca: &Authority<'_>,
        serial: &SerialNumber,
        caller: &dyn Principal,
    ) -> Result<Certificate, PipelineError> {
        let certificate = self
            .store
            .certificate(&ca.id, serial)?
            .ok_or(PipelineError::NoSuchCertificate)?;
        if holds(caller, ca, CA_READ)? || certificate.owner.as_ref() == Some(caller.sid()) {
            return Ok(certificate);
        }
        let requested = self
            .store
            .request(certificate.request)?
            .is_some_and(|request| &request.requester == caller.sid());
        if requested {
            Ok(certificate)
        } else {
            Err(PipelineError::NoSuchCertificate)
        }
    }

    /// Certificates the CA issued matching `filter`. Callers without Read
    /// see only those they requested.
    pub fn certificates(
        &self,
        ca: &Authority<'_>,
        mut filter: CertificateFilter,
        caller: &dyn Principal,
    ) -> Result<Vec<Certificate>, PipelineError> {
        filter.ca = Some(ca.id.clone());
        if !holds(caller, ca, CA_READ)? {
            filter.requester = Some(caller.sid().clone());
        }
        Ok(self.store.certificates(&filter)?)
    }

    fn template(&self, ca: &Authority<'_>, template: &str) -> Result<&'a Template, PipelineError> {
        let configuration: &'a Configuration = self.configuration;
        if !ca.templates.iter().any(|offered| offered == template) {
            return Err(PipelineError::NoSuchTemplate(template.to_string()));
        }
        configuration
            .templates
            .get(template)
            .ok_or_else(|| PipelineError::NoSuchTemplate(template.to_string()))
    }

    fn pending(&self, ca: &Authority<'_>, id: RequestId) -> Result<Request, PipelineError> {
        let request = self
            .store
            .request(id)?
            .filter(|request| request.ca == ca.id)
            .ok_or(PipelineError::NoSuchRequest(id))?;
        if request.status != RequestStatus::Pending {
            return Err(PipelineError::NotPending(id, request.status));
        }
        Ok(request)
    }

    /// Signs a certificate for `request` and records it with `record`,
    /// drawing a new serial number if the CA already used one.
    fn issue<T>(
        &mut self,
        ca: &Authority<'_>,
        template: &Template,
        request: &CertificateRequest,
        decision: &Decision,
        now: OffsetDateTime,
        mut record: impl FnMut(&mut Store, &NewCertificate) -> Result<T, StoreError>,
    ) -> Result<(T, Vec<u8>), PipelineError> {
        let signer = ca.signer.ok_or(PipelineError::KeyUnavailable)?;
        let issuing = IssuingCa::new(&ca.certificate, signer)
            .map_err(|error| PipelineError::Configuration(error.to_string()))?;
        let display_name = match (template.common_name, &decision.owner) {
            (CommonNameRule::OwnerDisplayName, Some(owner)) => {
                self.directory.display_name(owner)?
            }
            _ => None,
        };
        let context = IssueContext {
            now,
            issuer_not_after: issuing.validity().not_after(),
            crl_distribution_points: ca.crl_distribution_points.clone(),
            sid_extension: self.configuration.sid_extension,
        };
        let profile = leaf_profile(template, decision, display_name.as_ref(), &context)?;
        let mut attempt = 0;
        loop {
            attempt += 1;
            let serial = SerialNumber::random().map_err(PipelineError::Issue)?;
            let certificate = issuing
                .issue(request.subject_key(), &profile, &serial)
                .map_err(PipelineError::Issue)?;
            let issued = NewCertificate {
                serial,
                der: certificate.der().to_vec(),
                not_before: profile.validity.not_before(),
                not_after: profile.validity.not_after(),
                owner: decision.owner.clone(),
            };
            match record(self.store, &issued) {
                Ok(recorded) => return Ok((recorded, issued.der)),
                Err(StoreError::DuplicateSerial) if attempt < SERIAL_ATTEMPTS => continue,
                Err(error) => return Err(error.into()),
            }
        }
    }
}

/// Whether `principal` holds `right` at `ca`.
fn holds(principal: &dyn Principal, ca: &Authority<'_>, right: u32) -> Result<bool, PipelineError> {
    let granted = principal
        .checker()
        .granted(&ca.security, right, None)
        .map_err(|error| PipelineError::Identity(error.to_string()))?;
    Ok(granted & right == right)
}

fn require(principal: &dyn Principal, ca: &Authority<'_>, right: u32) -> Result<(), PipelineError> {
    if holds(principal, ca, right)? {
        Ok(())
    } else {
        Err(PipelineError::AccessDenied)
    }
}

/// Every reason in a decision: the request's own, then each name's.
fn reasons(decision: &Decision) -> Vec<String> {
    let mut reasons = decision.reasons.clone();
    for name in &decision.names {
        if let Some(reason) = &name.reason {
            reasons.push(format!("{}: {reason}", name.name));
        }
    }
    reasons
}
