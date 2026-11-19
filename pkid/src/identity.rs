//! Callers' identities and access checks, by KACS.

use std::os::fd::AsFd;

use peios::access::{AccessCheck, SubjectAccessDecision, SubjectGroup, SuppliedSubject};
use peios::msgpack::{Reader, Writer};
use peios::security::{sddl, AccessMask, GenericMapping, SdBuilder, SecurityDescriptor, WellKnown};
use peios::token::Token;
use pki_core::{DisplayName, Sid};
use pki_pipeline::{Directory, PipelineError, Principal, CA_ALL};
use pki_policy::{AccessChecker, PolicyError, SecurityBlob, NAME_ALL, TEMPLATE_ALL};

/// What GENERIC_ALL means on pkid's objects: every right a CA, template or
/// name descriptor can grant. The other generic rights mean nothing, so a
/// descriptor grants pkid's rights only by naming them.
fn mapping() -> GenericMapping {
    GenericMapping::new(0, 0, 0, CA_ALL | TEMPLATE_ALL | NAME_ALL)
}

fn descriptor(security: &SecurityBlob) -> Result<SecurityDescriptor, PolicyError> {
    SecurityDescriptor::from_validated_bytes(security.as_bytes().to_vec())
        .map_err(|error| PolicyError::InvalidConfiguration(format!("security descriptor: {error}")))
}

fn native_sid(sid: &Sid) -> Result<peios::security::Sid, PolicyError> {
    sid.as_str()
        .parse()
        .map_err(|_| PolicyError::AccessCheck(format!("{} is not a SID", sid.as_str())))
}

fn portable_sid(sid: &peios::security::Sid) -> Result<Sid, PipelineError> {
    Sid::new(&sid.to_string()).map_err(|error| PipelineError::Identity(error.to_string()))
}

fn check_failed(error: peios::Error) -> PolicyError {
    PolicyError::AccessCheck(error.to_string())
}

/// The descriptor a name below `parent` inherits: its container-inherit
/// entries, by ordinary inheritance.
fn inherit(parent: &SecurityBlob) -> Result<SecurityBlob, PolicyError> {
    let system = peios::security::Sid::well_known(WellKnown::System);
    let empty = SdBuilder::new()
        .owner(system.as_ref())
        .group(system.as_ref())
        .build()
        .map_err(check_failed)?;
    let inherited =
        sddl::reinherit(parent.as_bytes(), empty.as_bytes(), true).map_err(check_failed)?;
    Ok(SecurityBlob::new(inherited.as_bytes().to_vec()))
}

/// A connected caller, checked by the token the kernel captured when it
/// connected.
pub struct Caller {
    token: Token,
    sid: Sid,
}

impl Caller {
    pub fn new(token: Token) -> Result<Self, PipelineError> {
        let user = token
            .user()
            .map_err(|error| PipelineError::Identity(error.to_string()))?;
        Ok(Self {
            sid: portable_sid(&user)?,
            token,
        })
    }
}

impl AccessChecker for Caller {
    fn granted(
        &self,
        security: &SecurityBlob,
        desired: u32,
        self_sid: Option<&Sid>,
    ) -> Result<u32, PolicyError> {
        let sd = descriptor(security)?;
        let principal_self = self_sid.map(native_sid).transpose()?;
        let mut check = AccessCheck::new(&sd, AccessMask::MAXIMUM_ALLOWED, mapping());
        check.token(self.token.as_fd());
        if let Some(sid) = &principal_self {
            check.self_sid(sid.as_ref());
        }
        let decision = check.check().map_err(check_failed)?;
        Ok(decision.granted.bits() & desired)
    }

    fn inherit(&self, parent: &SecurityBlob) -> Result<SecurityBlob, PolicyError> {
        inherit(parent)
    }
}

impl Principal for Caller {
    fn sid(&self) -> &Sid {
        &self.sid
    }

    fn checker(&self) -> &dyn AccessChecker {
        self
    }

    /// The user and enabled groups, which approval checks again.
    fn snapshot(&self) -> Result<Vec<u8>, PipelineError> {
        let user = self
            .token
            .user()
            .map_err(|error| PipelineError::Identity(error.to_string()))?;
        let groups = self
            .token
            .groups()
            .map_err(|error| PipelineError::Identity(error.to_string()))?;
        let mut writer = Writer::new();
        writer.write_array(2).write_str(&user.to_string());
        writer.write_array(groups.len() as u32);
        for (sid, attributes) in &groups {
            writer
                .write_array(2)
                .write_str(&sid.to_string())
                .write_uint(u64::from(*attributes));
        }
        writer
            .to_bytes()
            .map_err(|error| PipelineError::Identity(error.to_string()))
    }
}

/// A requester as a stored snapshot recorded them, checked as a supplied
/// subject since their token is long gone.
pub struct Recorded {
    sid: Sid,
    user: peios::security::Sid,
    groups: Vec<(peios::security::Sid, u32)>,
}

impl Recorded {
    pub fn decode(snapshot: &[u8]) -> Result<Self, PipelineError> {
        let corrupt = |detail: &str| PipelineError::Identity(format!("stored identity: {detail}"));
        let mut reader = Reader::new(snapshot);
        let parse = |text: &str| -> Result<peios::security::Sid, PipelineError> {
            text.parse().map_err(|_| corrupt("not a SID"))
        };
        if reader.read_array().map_err(|_| corrupt("not an array"))? != 2 {
            return Err(corrupt("wrong shape"));
        }
        let user = parse(reader.read_str().map_err(|_| corrupt("no user"))?)?;
        let count = reader.read_array().map_err(|_| corrupt("no groups"))?;
        let mut groups = Vec::with_capacity(count.min(1024));
        for _ in 0..count {
            if reader.read_array().map_err(|_| corrupt("group"))? != 2 {
                return Err(corrupt("group"));
            }
            let sid = parse(reader.read_str().map_err(|_| corrupt("group SID"))?)?;
            let attributes = u32::try_from(reader.read_uint().map_err(|_| corrupt("attributes"))?)
                .map_err(|_| corrupt("attributes"))?;
            groups.push((sid, attributes));
        }
        Ok(Self {
            sid: portable_sid(&user)?,
            user,
            groups,
        })
    }
}

impl AccessChecker for Recorded {
    fn granted(
        &self,
        security: &SecurityBlob,
        desired: u32,
        self_sid: Option<&Sid>,
    ) -> Result<u32, PolicyError> {
        let sd = descriptor(security)?;
        let principal_self = self_sid.map(native_sid).transpose()?;
        let groups: Vec<SubjectGroup<'_>> = self
            .groups
            .iter()
            .map(|(sid, attributes)| SubjectGroup {
                sid: sid.as_ref(),
                attributes: *attributes,
            })
            .collect();
        let subject = SuppliedSubject {
            user: Some(self.user.as_ref()),
            groups: Some(&groups),
            ..SuppliedSubject::default()
        };
        let mut check = AccessCheck::new(&sd, AccessMask::MAXIMUM_ALLOWED, mapping());
        if let Some(sid) = &principal_self {
            check.self_sid(sid.as_ref());
        }
        match check.check_subject(&subject).map_err(check_failed)? {
            SubjectAccessDecision::Granted { granted }
            | SubjectAccessDecision::Denied { granted } => Ok(granted.bits() & desired),
            SubjectAccessDecision::MissingContext { missing } => Err(PolicyError::AccessCheck(
                format!("the stored identity lacks {missing:?}"),
            )),
        }
    }

    fn inherit(&self, parent: &SecurityBlob) -> Result<SecurityBlob, PolicyError> {
        inherit(parent)
    }
}

impl Principal for Recorded {
    fn sid(&self) -> &Sid {
        &self.sid
    }

    fn checker(&self) -> &dyn AccessChecker {
        self
    }

    fn snapshot(&self) -> Result<Vec<u8>, PipelineError> {
        let mut writer = Writer::new();
        writer.write_array(2).write_str(&self.user.to_string());
        writer.write_array(self.groups.len() as u32);
        for (sid, attributes) in &self.groups {
            writer
                .write_array(2)
                .write_str(&sid.to_string())
                .write_uint(u64::from(*attributes));
        }
        writer
            .to_bytes()
            .map_err(|error| PipelineError::Identity(error.to_string()))
    }
}

/// Identity services on this machine.
pub struct LocalDirectory;

impl Directory for LocalDirectory {
    fn restore(&self, snapshot: &[u8]) -> Result<Box<dyn Principal>, PipelineError> {
        Ok(Box::new(Recorded::decode(snapshot)?))
    }

    /// Not yet available: identity data comes from authd, which pkid
    /// doesn't consult yet, so templates that name certificates after their
    /// owner can't issue.
    fn display_name(&self, _sid: &Sid) -> Result<Option<DisplayName>, PipelineError> {
        Ok(None)
    }
}
