//! Deciding whether a request is issued, held for approval or refused.

use pki_core::{AltName, CertificateRequest, DnsName, Sid};

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
    /// The domains whose principal names belong to accounts in the account
    /// directory: `alice@home`, with `home` listed and no `Owner` of its
    /// own, is owned by the account `alice`. None by default.
    pub principal_domains: Vec<DnsName>,
}

/// The account directory, for the owners of principal names in
/// [`NamePolicy::principal_domains`].
pub trait Accounts {
    /// The SID of the principal account named `name`, or nothing if there is
    /// none. Groups never answer: a principal name names a principal.
    fn account(&self, name: &str) -> Result<Option<Sid>, String>;
}

/// No account directory: principal names have only the owners the trees
/// give them.
pub struct NoAccounts;

impl Accounts for NoAccounts {
    fn account(&self, _: &str) -> Result<Option<Sid>, String> {
        Ok(None)
    }
}

impl NamePolicy {
    pub fn new(dns: NameTree, principals: NameTree) -> Result<Self, PolicyError> {
        if dns.kind() != TreeKind::Dns || principals.kind() != TreeKind::Principal {
            return Err(PolicyError::InvalidConfiguration(
                "name trees of the wrong kind".into(),
            ));
        }
        Ok(Self {
            dns,
            principals,
            principal_domains: Vec::new(),
        })
    }

    /// The same trees, with `domains`' principal names belonging to their
    /// accounts.
    pub fn with_principal_domains(mut self, domains: Vec<DnsName>) -> Self {
        self.principal_domains = domains;
        self
    }

    /// Who owns `name`: the owner its own node names, or, for a principal
    /// name in a listed domain, the account its user part names. A wildcard
    /// is owned by nobody.
    fn owner(&self, name: &AltName, accounts: &dyn Accounts) -> Result<Option<Sid>, String> {
        let Ok(path) = name_path(name) else {
            return Ok(None);
        };
        if path.wildcard {
            return Ok(None);
        }
        if let Some(owner) = self.tree(path.tree).resolve(&path.path).owner {
            return Ok(Some(owner.clone()));
        }
        let (user, domain) = match name {
            AltName::Email(mailbox) => (mailbox.local(), mailbox.domain().as_str()),
            AltName::Upn(upn) => upn.parts(),
            _ => return Ok(None),
        };
        let listed = self
            .principal_domains
            .iter()
            .any(|listed| listed.as_str().eq_ignore_ascii_case(domain));
        if !listed {
            return Ok(None);
        }
        accounts.account(user)
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
    accounts: &dyn Accounts,
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

    // Each name's owner once, so that the access check and the binding of
    // the certificate can't disagree. An owner that can't be looked up is
    // no owner: the request is refused or held, never granted on a guess.
    let mut owners = Vec::new();
    for name in request.names() {
        owners.push(names.owner(name, accounts).unwrap_or_else(|error| {
            reasons.push(format!("can't find who owns {name}: {error}"));
            None
        }));
    }
    let mut decisions = Vec::new();
    for (name, owner) in request.names().iter().zip(&owners) {
        let decision = decide_name(name, owner.as_ref(), template, names, checker)?;
        outcome = outcome.max(decision.outcome);
        decisions.push(decision);
    }
    if template.issuance == Issuance::Approval && outcome == Outcome::Issue {
        reasons.push(format!("{} requires approval", template.name));
        outcome = Outcome::Pend;
    }
    let owner = common_owner(&owners);
    Ok(Decision {
        outcome,
        names: decisions,
        reasons,
        owner,
    })
}

fn decide_name(
    name: &AltName,
    owner: Option<&Sid>,
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
    let self_sid = if path.wildcard { None } else { owner };
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

fn common_owner(owners: &[Option<Sid>]) -> Option<Sid> {
    let first = owners.first()?.as_ref()?;
    owners
        .iter()
        .all(|owner| owner.as_ref() == Some(first))
        .then(|| first.clone())
}
