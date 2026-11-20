//! Callers' identities and access checks, by KACS.

use std::os::fd::AsFd;

use auth_core::client::ident::Ident;
use auth_core::ident::{Fields, Key as IdentKey, Kind as IdentKind, Value};
use peios::access::{AccessCheck, SubjectAccessDecision, SubjectGroup, SuppliedSubject};
use peios::msgpack::{Reader, Writer};
use peios::security::SidRef;
use peios::security::{AccessMask, GenericMapping, SecurityDescriptor};
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
    pki_management::security::inherit(parent).map_err(check_failed)
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
        // A supplied subject has no implicit PRINCIPAL SELF: without one the
        // check reports it missing rather than matching nobody, as a token
        // check does. The Null SID, which no subject holds, keeps the two
        // alike.
        let principal_self = match self_sid {
            Some(sid) => native_sid(sid)?,
            None => "S-1-0-0"
                .parse()
                .map_err(|_| PolicyError::AccessCheck("the Null SID doesn't parse".into()))?,
        };
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
        check.self_sid(principal_self.as_ref());
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

/// Identity services on this machine: authd's identity socket.
pub struct LocalDirectory;

/// How long pkid waits for authd. A request is decided while pkid's state
/// is held, so a slow authd mustn't hold every other caller up for long.
const AUTHD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

fn ident() -> Ident {
    Ident::new().with_timeout(AUTHD_TIMEOUT)
}

impl pki_policy::Accounts for LocalDirectory {
    /// The principal authd knows by `name`, through its sources in their
    /// configured order. Account names are set by administrators, and a
    /// group never answers.
    fn account(&self, name: &str) -> Result<Option<Sid>, String> {
        let record = ident()
            .lookup(
                IdentKey::Name(name.to_owned()),
                IdentKind::Principal,
                Fields::empty(),
            )
            .map_err(|failure| failure.to_string())?;
        let Some(record) = record else {
            return Ok(None);
        };
        if record.kind_found != IdentKind::Principal {
            return Ok(None);
        }
        let sid = SidRef::from_bytes(&record.sid)
            .ok_or_else(|| "authd answered with a malformed SID".to_string())?;
        Sid::new(&sid.to_string())
            .map(Some)
            .map_err(|error| error.to_string())
    }
}

impl Directory for LocalDirectory {
    fn restore(&self, snapshot: &[u8]) -> Result<Box<dyn Principal>, PipelineError> {
        Ok(Box::new(Recorded::decode(snapshot)?))
    }

    /// The display name authd has for `sid`, never one from a request.
    fn display_name(&self, sid: &Sid) -> Result<Option<DisplayName>, PipelineError> {
        let native: peios::security::Sid = sid
            .as_str()
            .parse()
            .map_err(|_| PipelineError::Identity(format!("{} is not a SID", sid.as_str())))?;
        let record = ident()
            .lookup(
                IdentKey::Sid(native.as_bytes().to_vec()),
                IdentKind::Any,
                Fields::DISPLAY_NAME,
            )
            .map_err(|failure| PipelineError::Identity(failure.to_string()))?;
        let name = record.and_then(|record| match record.value(Fields::DISPLAY_NAME) {
            Some(Value::DisplayName(name)) if !name.trim().is_empty() => Some(name.clone()),
            _ => None,
        });
        name.map(|name| {
            DisplayName::new(&name).map_err(|error| PipelineError::Identity(error.to_string()))
        })
        .transpose()
    }
}
