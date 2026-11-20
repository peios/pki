//! Request decisions, checked with a small model of KACS access checks.

use pki_core::{AltName, CertificateRequest, CommonName, DisplayName, DnsName, Sid};
use pki_policy::defaults::{device_template, name_root, server_template};
use pki_policy::{
    evaluate, leaf_profile, AccessChecker, Accounts, CommonNameRule, Decision, Issuance,
    IssueContext, NameNode, NamePolicy, NameTree, NoAccounts, Outcome, PolicyError, RegData,
    SecurityBlob, Template, TreeKind, Values,
};
use time::macros::datetime;

const JACK: &str = "S-1-5-21-1-2-3-1001";
const RADIUS: &str = "S-1-5-80-1-2-3";
const ADMINISTRATORS: &str = "S-1-5-32-544";
const AUTHENTICATED_USERS: &str = "S-1-5-11";
const LAB_ADMINS: &str = "S-1-5-21-1-2-3-2001";

/// A stand-in descriptor: one `trustee:mask[:inherit]` entry per line, where
/// the trustee `self` means PRINCIPAL SELF and `inherit` marks an entry that
/// passes down to names below.
fn sd(entries: &[&str]) -> SecurityBlob {
    SecurityBlob::new(entries.join("\n").into_bytes())
}

/// The default name-tree root (DEFAULT_NAME_ROOT_SDDL).
fn default_root() -> SecurityBlob {
    sd(&["self:1:inherit", &format!("{ADMINISTRATORS}:7:inherit")])
}

/// The default enrolment descriptor (DEFAULT_TEMPLATE_ENROLL_SDDL).
fn default_enroll() -> SecurityBlob {
    sd(&[
        &format!("{AUTHENTICATED_USERS}:1"),
        &format!("{ADMINISTRATORS}:3"),
    ])
}

/// A requester whose token holds these SIDs.
struct Requester(Vec<&'static str>);

impl Requester {
    fn user(sid: &'static str) -> Self {
        Self(vec![sid, AUTHENTICATED_USERS])
    }
}

fn entries(security: &SecurityBlob) -> Vec<(String, u32, bool)> {
    let text = std::str::from_utf8(security.as_bytes()).unwrap();
    text.lines()
        .map(|line| {
            let mut parts = line.split(':');
            let trustee = parts.next().unwrap().to_string();
            let mask = parts.next().unwrap().parse().unwrap();
            (trustee, mask, parts.next() == Some("inherit"))
        })
        .collect()
}

impl AccessChecker for Requester {
    fn granted(
        &self,
        security: &SecurityBlob,
        desired: u32,
        self_sid: Option<&Sid>,
    ) -> Result<u32, PolicyError> {
        let holds = |sid: &str| self.0.contains(&sid);
        let mut granted = 0;
        for (trustee, mask, _) in entries(security) {
            let matches = match trustee.as_str() {
                "self" => self_sid.is_some_and(|sid| holds(sid.as_str())),
                sid => holds(sid),
            };
            if matches {
                granted |= mask;
            }
        }
        Ok(granted & desired)
    }

    fn inherit(&self, parent: &SecurityBlob) -> Result<SecurityBlob, PolicyError> {
        let kept: Vec<String> = entries(parent)
            .into_iter()
            .filter(|(_, _, inherit)| *inherit)
            .map(|(trustee, mask, _)| format!("{trustee}:{mask}:inherit"))
            .collect();
        Ok(SecurityBlob::new(kept.join("\n").into_bytes()))
    }
}

fn node(security: Option<SecurityBlob>, owner: Option<&str>) -> NameNode {
    NameNode {
        request_security: security,
        owner: owner.map(|sid| Sid::new(sid).unwrap()),
    }
}

fn path(segments: &[&str]) -> Vec<String> {
    segments.iter().map(|segment| segment.to_string()).collect()
}

/// The default roots, with radius.home owned by radiusd and jack@home by Jack.
fn policy_with(extra_dns: Vec<(Vec<String>, NameNode)>) -> NamePolicy {
    let mut dns = vec![
        (path(&[]), node(Some(default_root()), None)),
        (path(&["home", "radius"]), node(None, Some(RADIUS))),
    ];
    dns.extend(extra_dns);
    let principals = vec![
        (path(&[]), node(Some(default_root()), None)),
        (path(&["home", "@jack"]), node(None, Some(JACK))),
    ];
    NamePolicy::new(
        NameTree::new(TreeKind::Dns, dns).unwrap(),
        NameTree::new(TreeKind::Principal, principals).unwrap(),
    )
    .unwrap()
}

fn policy() -> NamePolicy {
    policy_with(Vec::new())
}

fn server() -> Template {
    Template::from_values(&server_template(&default_enroll())).unwrap()
}

fn device() -> Template {
    Template::from_values(&device_template(&default_enroll())).unwrap()
}

fn request(
    names: Vec<rcgen::SanType>,
    algorithm: &'static rcgen::SignatureAlgorithm,
) -> CertificateRequest {
    let key = rcgen::KeyPair::generate_for(algorithm).unwrap();
    let mut params = rcgen::CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.subject_alt_names = names;
    CertificateRequest::from_der(params.serialize_request(&key).unwrap().der()).unwrap()
}

fn dns_request(names: &[&str]) -> CertificateRequest {
    let names = names
        .iter()
        .map(|name| rcgen::SanType::DnsName((*name).try_into().unwrap()));
    request(names.collect(), &rcgen::PKCS_ECDSA_P256_SHA256)
}

fn upn_request(upn: &str) -> CertificateRequest {
    const UPN: &[u64] = &[1, 3, 6, 1, 4, 1, 311, 20, 2, 3];
    let name = rcgen::SanType::OtherName((UPN.to_vec(), upn.into()));
    request(vec![name], &rcgen::PKCS_ECDSA_P256_SHA256)
}

fn decide(request: &CertificateRequest, template: &Template, requester: &Requester) -> Decision {
    evaluate(request, template, &policy(), &NoAccounts, requester).unwrap()
}

#[test]
fn owner_obtains_its_own_name() {
    let decision = decide(
        &dns_request(&["radius.home"]),
        &server(),
        &Requester::user(RADIUS),
    );
    assert_eq!(decision.outcome, Outcome::Issue, "{decision:?}");
    assert_eq!(decision.owner, Some(Sid::new(RADIUS).unwrap()));
}

#[test]
fn someone_else_cannot_obtain_an_owned_name() {
    // ESC1: an ordinary principal asks for a name it does not own.
    let decision = decide(
        &dns_request(&["radius.home"]),
        &server(),
        &Requester::user(JACK),
    );
    assert_eq!(decision.outcome, Outcome::Reject, "{decision:?}");
}

#[test]
fn nobody_obtains_an_unowned_name_by_default() {
    let decision = decide(
        &dns_request(&["administrator.home"]),
        &server(),
        &Requester::user(JACK),
    );
    assert_eq!(decision.outcome, Outcome::Reject, "{decision:?}");
}

#[test]
fn administrators_obtain_any_name() {
    let admin = Requester(vec![JACK, ADMINISTRATORS, AUTHENTICATED_USERS]);
    let decision = decide(
        &dns_request(&["printer.home", "radius.home"]),
        &server(),
        &admin,
    );
    assert_eq!(decision.outcome, Outcome::Issue, "{decision:?}");
}

#[test]
fn one_refused_name_refuses_the_request() {
    let decision = decide(
        &dns_request(&["radius.home", "administrator.home"]),
        &server(),
        &Requester::user(RADIUS),
    );
    assert_eq!(decision.outcome, Outcome::Reject, "{decision:?}");
    assert_eq!(decision.names[0].outcome, Outcome::Issue);
    assert_eq!(decision.names[1].outcome, Outcome::Reject);
}

#[test]
fn approval_right_holds_the_request() {
    let lab = vec![(
        path(&["home", "lab"]),
        node(
            Some(sd(&[&format!("{LAB_ADMINS}:2:inherit"), "self:1:inherit"])),
            None,
        ),
    )];
    let requester = Requester(vec![JACK, LAB_ADMINS, AUTHENTICATED_USERS]);
    let decision = evaluate(
        &dns_request(&["printer.lab.home"]),
        &server(),
        &policy_with(lab),
        &NoAccounts,
        &requester,
    )
    .unwrap();
    assert_eq!(decision.outcome, Outcome::Pend, "{decision:?}");
}

#[test]
fn non_inheritable_entries_stay_on_their_node() {
    let lab = vec![(
        path(&["home", "lab"]),
        node(Some(sd(&[&format!("{LAB_ADMINS}:1")])), None),
    )];
    let policy = policy_with(lab);
    let requester = Requester(vec![LAB_ADMINS, AUTHENTICATED_USERS]);
    let own = evaluate(
        &dns_request(&["lab.home"]),
        &server(),
        &policy,
        &NoAccounts,
        &requester,
    )
    .unwrap();
    assert_eq!(own.outcome, Outcome::Issue, "{own:?}");
    let below = evaluate(
        &dns_request(&["printer.lab.home"]),
        &server(),
        &policy,
        &NoAccounts,
        &requester,
    )
    .unwrap();
    assert_eq!(below.outcome, Outcome::Reject, "{below:?}");
}

#[test]
fn wildcards_need_the_wildcard_right() {
    let lab = vec![(path(&["home", "lab"]), node(None, Some(LAB_ADMINS)))];
    let policy = policy_with(lab);
    // Owning lab.home doesn't extend to *.lab.home: PRINCIPAL SELF never
    // applies to wildcards.
    let owner = Requester(vec![LAB_ADMINS, AUTHENTICATED_USERS]);
    let decision = evaluate(
        &dns_request(&["*.lab.home"]),
        &server(),
        &policy,
        &NoAccounts,
        &owner,
    )
    .unwrap();
    assert_eq!(decision.outcome, Outcome::Reject, "{decision:?}");

    let granted = vec![(
        path(&["home", "lab"]),
        node(
            Some(sd(&[&format!("{LAB_ADMINS}:1"), &format!("{RADIUS}:5")])),
            None,
        ),
    )];
    let policy = policy_with(granted);
    let without = evaluate(
        &dns_request(&["*.lab.home"]),
        &server(),
        &policy,
        &NoAccounts,
        &owner,
    )
    .unwrap();
    assert_eq!(without.outcome, Outcome::Reject, "{without:?}");
    let with = Requester::user(RADIUS);
    let decision = evaluate(
        &dns_request(&["*.lab.home"]),
        &server(),
        &policy,
        &NoAccounts,
        &with,
    )
    .unwrap();
    assert_eq!(decision.outcome, Outcome::Issue, "{decision:?}");
}

#[test]
fn principal_names_use_their_own_tree() {
    let decision = decide(&upn_request("Jack@HOME"), &device(), &Requester::user(JACK));
    assert_eq!(decision.outcome, Outcome::Issue, "{decision:?}");
    assert_eq!(decision.owner, Some(Sid::new(JACK).unwrap()));
    let other = decide(
        &upn_request("jack@home"),
        &device(),
        &Requester::user(RADIUS),
    );
    assert_eq!(other.outcome, Outcome::Reject, "{other:?}");
}

#[test]
fn templates_only_issue_their_name_types() {
    let decision = decide(&upn_request("jack@home"), &server(), &Requester::user(JACK));
    assert_eq!(decision.outcome, Outcome::Reject, "{decision:?}");
    let decision = decide(
        &dns_request(&["radius.home"]),
        &device(),
        &Requester::user(RADIUS),
    );
    assert_eq!(decision.outcome, Outcome::Reject, "{decision:?}");
}

#[test]
fn ip_addresses_are_refused() {
    let name = rcgen::SanType::IpAddress("10.0.0.1".parse().unwrap());
    let request = request(vec![name], &rcgen::PKCS_ECDSA_P256_SHA256);
    let admin = Requester(vec![ADMINISTRATORS, AUTHENTICATED_USERS]);
    let decision = decide(&request, &server(), &admin);
    assert_eq!(decision.outcome, Outcome::Reject, "{decision:?}");
}

#[test]
fn enrolment_is_required() {
    let mut template = server();
    template.enroll_security = sd(&[&format!("{ADMINISTRATORS}:3")]);
    let decision = decide(
        &dns_request(&["radius.home"]),
        &template,
        &Requester::user(RADIUS),
    );
    assert_eq!(decision.outcome, Outcome::Reject, "{decision:?}");
    assert!(decision.reasons[0].contains("enrol"));
}

#[test]
fn templates_restrict_keys() {
    let mut values = server_template(&default_enroll());
    values.insert("KeyAlgorithms", RegData::MultiSz(vec!["ecdsa-p384".into()]));
    let template = Template::from_values(&values).unwrap();
    let decision = decide(
        &dns_request(&["radius.home"]),
        &template,
        &Requester::user(RADIUS),
    );
    assert_eq!(decision.outcome, Outcome::Reject, "{decision:?}");
}

#[test]
fn approval_templates_hold_every_request() {
    let mut template = server();
    template.issuance = Issuance::Approval;
    let decision = decide(
        &dns_request(&["radius.home"]),
        &template,
        &Requester::user(RADIUS),
    );
    assert_eq!(decision.outcome, Outcome::Pend, "{decision:?}");
}

fn context(sid_extension: bool) -> IssueContext {
    IssueContext {
        now: datetime!(2027-01-01 0:00 UTC),
        issuer_not_after: datetime!(2030-01-01 0:00 UTC),
        crl_distribution_points: vec!["http://pki.home/issuing.crl".into()],
        sid_extension,
    }
}

#[test]
fn profile_carries_the_names_owner_and_template() {
    let decision = decide(
        &dns_request(&["radius.home"]),
        &server(),
        &Requester::user(RADIUS),
    );
    let profile = leaf_profile(&server(), &decision, None, &context(true)).unwrap();
    let name = AltName::Dns(DnsName::new("radius.home").unwrap());
    assert_eq!(profile.alt_names, vec![name.clone()]);
    assert_eq!(profile.subject.common_name, Some(CommonName::Name(name)));
    assert_eq!(profile.owner_sid, Some(Sid::new(RADIUS).unwrap()));
    assert_eq!(profile.validity.not_after(), datetime!(2027-04-01 0:00 UTC));

    let without = leaf_profile(&server(), &decision, None, &context(false)).unwrap();
    assert_eq!(without.owner_sid, None);
}

#[test]
fn lifetime_is_cut_short_to_the_issuer() {
    let decision = decide(&upn_request("jack@home"), &device(), &Requester::user(JACK));
    let mut short = context(true);
    short.issuer_not_after = datetime!(2027-02-01 0:00 UTC);
    let profile = leaf_profile(&device(), &decision, None, &short).unwrap();
    assert_eq!(profile.validity.not_after(), datetime!(2027-02-01 0:00 UTC));
}

#[test]
fn display_names_come_only_from_the_caller_and_need_one_owner() {
    let mut template = device();
    template.common_name = CommonNameRule::OwnerDisplayName;
    let decision = decide(&upn_request("jack@home"), &template, &Requester::user(JACK));
    let display = DisplayName::new("Jack Palfrey").unwrap();
    let profile = leaf_profile(&template, &decision, Some(&display), &context(true)).unwrap();
    assert_eq!(
        profile.subject.common_name,
        Some(CommonName::DisplayName(display.clone()))
    );
    assert!(leaf_profile(&template, &decision, None, &context(true)).is_err());

    let admin = Requester(vec![ADMINISTRATORS, AUTHENTICATED_USERS]);
    let mut unowned = server();
    unowned.common_name = CommonNameRule::OwnerDisplayName;
    let decision = decide(&dns_request(&["printer.home"]), &unowned, &admin);
    assert_eq!(decision.owner, None);
    assert!(leaf_profile(&unowned, &decision, Some(&display), &context(true)).is_err());
}

#[test]
fn mixed_owners_bind_no_owner() {
    let admin = Requester(vec![ADMINISTRATORS, AUTHENTICATED_USERS]);
    let decision = decide(
        &dns_request(&["radius.home", "printer.home"]),
        &server(),
        &admin,
    );
    assert_eq!(decision.outcome, Outcome::Issue);
    assert_eq!(decision.owner, None);
}

#[test]
fn refused_requests_have_no_profile() {
    let decision = decide(
        &dns_request(&["radius.home"]),
        &server(),
        &Requester::user(JACK),
    );
    assert!(leaf_profile(&server(), &decision, None, &context(true)).is_err());
}

#[test]
fn templates_reject_bad_values() {
    let base = server_template(&default_enroll());
    let cases: Vec<(&str, RegData)> = vec![
        ("Purposes", RegData::MultiSz(vec![])),
        ("Purposes", RegData::MultiSz(vec!["2.5.29.37.0".into()])),
        ("NameTypes", RegData::MultiSz(vec!["ip".into()])),
        ("KeyAlgorithms", RegData::MultiSz(vec!["rsa-1024".into()])),
        ("RenewalWindowDays", RegData::Dword(90)),
        ("LifetimeDays", RegData::Dword(0)),
        ("CommonName", RegData::Sz("requester-supplied".into())),
        ("EnrollSecurity", RegData::Binary(vec![])),
        ("Name", RegData::Dword(1)),
    ];
    for (name, data) in cases {
        let mut values = base.clone();
        values.insert(name, data.clone());
        assert!(
            Template::from_values(&values).is_err(),
            "{name} = {data:?} accepted"
        );
    }
}

#[test]
fn trees_need_a_secured_root_and_valid_keys() {
    let unsecured = NameTree::new(TreeKind::Dns, vec![(path(&[]), node(None, None))]);
    assert!(unsecured.is_err());
    let root = || (path(&[]), node(Some(default_root()), None));
    let invalid = [
        (TreeKind::Dns, path(&["home", "@jack"])),
        (TreeKind::Dns, path(&["lab.home"])),
        (TreeKind::Principal, path(&["@jack", "home"])),
        (TreeKind::Dns, path(&["bad_label"])),
    ];
    for (kind, bad) in invalid {
        let tree = NameTree::new(kind, vec![root(), (bad.clone(), node(None, None))]);
        assert!(tree.is_err(), "{kind:?} {bad:?} accepted");
    }
    let node = NameNode::from_values(&{
        let mut values = Values::new();
        values.insert("Owner", RegData::Sz("not-a-sid".into()));
        values
    });
    assert!(node.is_err());
}

#[test]
fn default_templates_parse() {
    let root = name_root(&default_root());
    assert!(NameNode::from_values(&root)
        .unwrap()
        .request_security
        .is_some());
    assert_eq!(server().name, "Server");
    assert_eq!(device().name, "Device");
}

// Principal names owned by their accounts.

const ALICE: &str = "S-1-5-21-1-2-3-1003";
const BOB: &str = "S-1-5-21-1-2-3-1004";

/// alice and bob, and a directory that can't be reached when asked about
/// `offline`.
struct Directory;

impl Accounts for Directory {
    fn account(&self, name: &str) -> Result<Option<Sid>, String> {
        match name {
            "alice" => Ok(Some(Sid::new(ALICE).unwrap())),
            "bob" => Ok(Some(Sid::new(BOB).unwrap())),
            "offline" => Err("authd is unavailable".into()),
            _ => Ok(None),
        }
    }
}

fn with_home() -> NamePolicy {
    policy().with_principal_domains(vec![pki_core::DnsName::new("home").unwrap()])
}

fn decide_with(policy: &NamePolicy, upn: &str, requester: &Requester) -> Decision {
    evaluate(&upn_request(upn), &device(), policy, &Directory, requester).unwrap()
}

#[test]
fn an_account_owns_its_principal_name_in_a_listed_domain() {
    let decision = decide_with(&with_home(), "alice@home", &Requester::user(ALICE));
    assert_eq!(decision.outcome, Outcome::Issue, "{decision:?}");
    assert_eq!(decision.owner, Some(Sid::new(ALICE).unwrap()));
}

#[test]
fn nobody_obtains_anothers_principal_name() {
    let decision = decide_with(&with_home(), "alice@home", &Requester::user(BOB));
    assert_eq!(decision.outcome, Outcome::Reject, "{decision:?}");
}

#[test]
fn unlisted_domains_are_never_looked_up() {
    // Without the domain listed, alice@home has no owner: only an explicit
    // Owner would make it hers.
    let unlisted = evaluate(
        &upn_request("alice@home"),
        &device(),
        &policy(),
        &Directory,
        &Requester::user(ALICE),
    )
    .unwrap();
    assert_eq!(unlisted.outcome, Outcome::Reject, "{unlisted:?}");
    let elsewhere = decide_with(&with_home(), "alice@gmail.com", &Requester::user(ALICE));
    assert_eq!(elsewhere.outcome, Outcome::Reject, "{elsewhere:?}");
    assert_eq!(elsewhere.owner, None);
}

#[test]
fn an_explicit_owner_wins_over_the_directory() {
    // jack@home is Jack's by its node, whatever the directory says.
    let decision = decide_with(&with_home(), "jack@home", &Requester::user(JACK));
    assert_eq!(decision.owner, Some(Sid::new(JACK).unwrap()));
}

#[test]
fn an_unreachable_directory_fails_closed() {
    let decision = decide_with(&with_home(), "offline@home", &Requester::user(ALICE));
    assert_eq!(decision.outcome, Outcome::Reject, "{decision:?}");
    assert_eq!(decision.owner, None);
    assert!(
        decision
            .reasons
            .iter()
            .any(|reason| reason.contains("authd is unavailable")),
        "{decision:?}"
    );
}
