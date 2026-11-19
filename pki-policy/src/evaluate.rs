//! Deciding whether a request is issued, held for approval or refused.

use pki_core::{AltName, CertificateRequest, Sid};

use crate::access::{
    AccessChecker, SecurityBlob, NAME_REQUEST, NAME_REQUEST_WILDCARD, NAME_REQUEST_WITH_APPROVAL,
    TEMPLATE_ENROLL,
};
use crate::template::{Issuance, Template};
use crate::tree::{name_path, NameTree, TreeKind};
use crate::PolicyError;

/// What happens to a request, or to one of its names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Outcome {
    Issue,
    /// Held until an officer approves it.
    Pend,
    Reject,
}

/// The decision for one requested name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameDecision {
    pub name: AltName,
    pub outcome: Outcome,
    /// Why the name was held or refused.
    pub reason: Option<String>,
}

/// The decision for a whole request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// The strictest outcome of any check: one refused name refuses the
    /// request, and one held name holds it.
    pub outcome: Outcome,
    pub names: Vec<NameDecision>,
    /// Reasons that concern the request as a whole.
    pub reasons: Vec<String>,
    /// The one principal that owns every requested name, if there is one.
    /// The certificate is bound to this principal.
    pub owner: Option<Sid>,
}

impl Decision {
    /// The requested names, in request order.
    pub fn approved_names(&self) -> Vec<AltName> {
        self.names
            .iter()
            .map(|decision| decision.name.clone())
            .collect()
    }
}

/// The name trees a CA checks requests against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamePolicy {
    pub dns: NameTree,
    pub principals: NameTree,
}

impl NamePolicy {
    pub fn new(dns: NameTree, principals: NameTree) -> Result<Self, PolicyError> {
        if dns.kind() != TreeKind::Dns || principals.kind() != TreeKind::Principal {
            return Err(PolicyError::InvalidConfiguration(
                "name trees of the wrong kind".into(),
            ));
        }
        Ok(Self { dns, principals })
    }

    fn tree(&self, kind: TreeKind) -> &NameTree {
        match kind {
            TreeKind::Dns => &self.dns,
            TreeKind::Principal => &self.principals,
        }
    }
}

/// Decides `request` against `template` and `names` for the requester that
/// `checker` represents.
///
/// Every check runs, so the decision lists every reason, not only the first.
pub fn evaluate(
    request: &CertificateRequest,
    template: &Template,
    names: &NamePolicy,
    checker: &dyn AccessChecker,
) -> Result<Decision, PolicyError> {
    let mut reasons = Vec::new();
    let mut outcome = Outcome::Issue;
    if checker.granted(&template.enroll_security, TEMPLATE_ENROLL, None)? & TEMPLATE_ENROLL == 0 {
        reasons.push(format!("not permitted to enrol for {}", template.name));
        outcome = Outcome::Reject;
    }
    if !template.accepts_key(request.subject_key()) {
        reasons.push(format!("{} does not accept this key", template.name));
        outcome = Outcome::Reject;
    }

    let mut decisions = Vec::new();
    for name in request.names() {
        let decision = decide_name(name, template, names, checker)?;
        outcome = outcome.max(decision.outcome);
        decisions.push(decision);
    }
    if template.issuance == Issuance::Approval && outcome == Outcome::Issue {
        reasons.push(format!("{} requires approval", template.name));
        outcome = Outcome::Pend;
    }
    let owner = common_owner(request.names(), names);
    Ok(Decision {
        outcome,
        names: decisions,
        reasons,
        owner,
    })
}

fn decide_name(
    name: &AltName,
    template: &Template,
    names: &NamePolicy,
    checker: &dyn AccessChecker,
) -> Result<NameDecision, PolicyError> {
    let decision = |outcome, reason: Option<String>| NameDecision {
        name: name.clone(),
        outcome,
        reason,
    };
    if !template.accepts_name(name) {
        let reason = format!("{} does not issue names like {name}", template.name);
        return Ok(decision(Outcome::Reject, Some(reason)));
    }
    let path = match name_path(name) {
        Ok(path) => path,
        Err(reason) => return Ok(decision(Outcome::Reject, Some(reason))),
    };
    let resolution = names.tree(path.tree).resolve(&path.path);
    let security = inherited(resolution.security, resolution.inherit_levels, checker)?;
    // A wildcard covers names nobody owns individually, so PRINCIPAL SELF
    // never applies to it.
    let self_sid = if path.wildcard {
        None
    } else {
        resolution.owner
    };
    let extra = if path.wildcard {
        NAME_REQUEST_WILDCARD
    } else {
        0
    };
    let desired = NAME_REQUEST | NAME_REQUEST_WITH_APPROVAL | extra;
    let granted = checker.granted(&security, desired, self_sid)?;
    if granted & extra != extra {
        let reason = format!("not permitted to request the wildcard {name}");
        return Ok(decision(Outcome::Reject, Some(reason)));
    }
    if granted & NAME_REQUEST != 0 {
        return Ok(decision(Outcome::Issue, None));
    }
    if granted & NAME_REQUEST_WITH_APPROVAL != 0 {
        return Ok(decision(
            Outcome::Pend,
            Some(format!("{name} requires approval")),
        ));
    }
    Ok(decision(
        Outcome::Reject,
        Some(format!("not permitted to request {name}")),
    ))
}

fn inherited(
    security: &SecurityBlob,
    levels: usize,
    checker: &dyn AccessChecker,
) -> Result<SecurityBlob, PolicyError> {
    let mut current = security.clone();
    for _ in 0..levels {
        current = checker.inherit(&current)?;
    }
    Ok(current)
}

fn common_owner(requested: &[AltName], names: &NamePolicy) -> Option<Sid> {
    let mut owners = requested.iter().map(|name| {
        let path = name_path(name).ok().filter(|path| !path.wildcard)?;
        names.tree(path.tree).resolve(&path.path).owner.cloned()
    });
    let first = owners.next()??;
    owners
        .all(|owner| owner.as_ref() == Some(&first))
        .then_some(first)
}
