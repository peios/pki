//! The request pipeline end to end, with a small model of KACS access
//! checks and an in-memory CA database.

use std::collections::{BTreeMap, HashMap};

use peios_crypto::{KeyAlgorithm, PrivateKey};
use pki_core::{
    create_root, CaProfile, CaSubject, DisplayName, RevocationReason, SerialNumber, Sid, Validity,
};
use pki_pipeline::{
    Authority, Configuration, Directory, Pipeline, PipelineError, Principal, Submission,
};
use pki_policy::defaults::server_template;
use pki_policy::{
    AccessChecker, CommonNameRule, Issuance, NameNode, NamePolicy, NameTree, PolicyError,
    SecurityBlob, Template, TreeKind,
};
use pki_store::{CertificateFilter, RequestFilter, RequestId, RequestStatus, Store};
use time::macros::datetime;
use time::OffsetDateTime;
use x509_parser::prelude::{FromDer, X509Certificate};

const JACK: &str = "S-1-5-21-1-2-3-1001";
const ALEX: &str = "S-1-5-21-1-2-3-1002";
const RADIUS: &str = "S-1-5-80-1-2-3";
const ADMINISTRATORS: &str = "S-1-5-32-544";
const AUTHENTICATED_USERS: &str = "S-1-5-11";
const LAB_ADMINS: &str = "S-1-5-21-1-2-3-2001";

const CA_ID: &str = "issuing";
const SERVER: &str = "0e5b5a3c-2f4d-4c1a-8e9b-111111111111";
const APPROVED_SERVER: &str = "0e5b5a3c-2f4d-4c1a-8e9b-222222222222";
const NAMED_SERVER: &str = "0e5b5a3c-2f4d-4c1a-8e9b-333333333333";

const NOW: OffsetDateTime = datetime!(2027-01-01 12:00 UTC);

/// A stand-in descriptor: one `trustee:mask[:inherit]` entry per line, where
/// the trustee `self` means PRINCIPAL SELF.
fn sd(entries: &[&str]) -> SecurityBlob {
    SecurityBlob::new(entries.join("\n").into_bytes())
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

/// A principal whose token holds these SIDs, the first being its user.
#[derive(Clone)]
struct Person {
    sid: Sid,
    sids: Vec<String>,
}

impl Person {
    fn new(sids: &[&str]) -> Self {
        Self {
            sid: Sid::new(sids[0]).unwrap(),
            sids: sids.iter().map(|sid| sid.to_string()).collect(),
        }
    }

    fn user(sid: &str) -> Self {
        Self::new(&[sid, AUTHENTICATED_USERS])
    }

    fn admin(sid: &str) -> Self {
        Self::new(&[sid, ADMINISTRATORS, AUTHENTICATED_USERS])
    }
}

impl AccessChecker for Person {
    fn granted(
        &self,
        security: &SecurityBlob,
        desired: u32,
        self_sid: Option<&Sid>,
    ) -> Result<u32, PolicyError> {
        let holds = |sid: &str| self.sids.iter().any(|held| held == sid);
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

impl Principal for Person {
    fn sid(&self) -> &Sid {
        &self.sid
    }

    fn checker(&self) -> &dyn AccessChecker {
        self
    }

    fn snapshot(&self) -> Result<Vec<u8>, PipelineError> {
        Ok(self.sids.join(",").into_bytes())
    }
}

#[derive(Default)]
struct People {
    display_names: HashMap<String, String>,
}

impl Directory for People {
    fn restore(&self, snapshot: &[u8]) -> Result<Box<dyn Principal>, PipelineError> {
        let text = std::str::from_utf8(snapshot).unwrap();
        let sids: Vec<&str> = text.split(',').collect();
        Ok(Box::new(Person::new(&sids)))
    }

    fn display_name(&self, sid: &Sid) -> Result<Option<DisplayName>, PipelineError> {
        Ok(self
            .display_names
            .get(sid.as_str())
            .map(|name| DisplayName::new(name).unwrap()))
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

/// The default roots; radius.home is owned by radiusd, and members of Lab
/// Admins may request names under lab.home with approval.
fn names(radius_owner: &str) -> NamePolicy {
    let root = sd(&["self:1:inherit", &format!("{ADMINISTRATORS}:7:inherit")]);
    let dns = vec![
        (path(&[]), node(Some(root.clone()), None)),
        (path(&["home", "radius"]), node(None, Some(radius_owner))),
        (
            path(&["home", "lab"]),
            node(
                Some(sd(&[
                    &format!("{LAB_ADMINS}:2:inherit"),
                    &format!("{ADMINISTRATORS}:7:inherit"),
                ])),
                None,
            ),
        ),
    ];
    let principals = vec![(path(&[]), node(Some(root), None))];
    NamePolicy::new(
        NameTree::new(TreeKind::Dns, dns).unwrap(),
        NameTree::new(TreeKind::Principal, principals).unwrap(),
    )
    .unwrap()
}

fn configuration(radius_owner: &str) -> Configuration {
    let enroll = sd(&[
        &format!("{AUTHENTICATED_USERS}:1"),
        &format!("{ADMINISTRATORS}:3"),
    ]);
    let server = Template::from_values(&server_template(&enroll)).unwrap();
    let mut approved = server.clone();
    approved.issuance = Issuance::Approval;
    let mut named = server.clone();
    named.common_name = CommonNameRule::OwnerDisplayName;
    Configuration {
        templates: BTreeMap::from([
            (SERVER.to_string(), server),
            (APPROVED_SERVER.to_string(), approved),
            (NAMED_SERVER.to_string(), named),
        ]),
        names: names(radius_owner),
        sid_extension: true,
    }
}

/// A CA with its own self-signed certificate.
struct TestCa {
    key: PrivateKey,
    certificate: Vec<u8>,
}

impl TestCa {
    fn new() -> Self {
        let key = PrivateKey::generate(KeyAlgorithm::EcdsaP256).unwrap();
        let profile = CaProfile {
            subject: CaSubject {
                common_name: "Home Issuing CA".into(),
                attributes: Vec::new(),
            },
            validity: Validity::new(
                datetime!(2026-01-01 0:00 UTC),
                datetime!(2031-01-01 0:00 UTC),
            )
            .unwrap(),
            path_length: Some(0),
            name_constraints: None,
            extended_key_usages: None,
            crl_distribution_points: Vec::new(),
        };
        let certificate = create_root(&key, &profile, &SerialNumber::random().unwrap())
            .unwrap()
            .der()
            .to_vec();
        Self { key, certificate }
    }

    fn authority(&self) -> Authority<'_> {
        Authority {
            id: CA_ID.into(),
            certificate: self.certificate.clone(),
            security: sd(&[
                &format!("{AUTHENTICATED_USERS}:2"),
                &format!("{ADMINISTRATORS}:15"),
            ]),
            templates: vec![SERVER.into(), APPROVED_SERVER.into(), NAMED_SERVER.into()],
            crl_distribution_points: vec!["http://pki.home/issuing.crl".into()],
            signer: Some(&self.key),
        }
    }

    /// The CA with its key unavailable.
    fn locked(&self) -> Authority<'_> {
        Authority {
            signer: None,
            ..self.authority()
        }
    }
}

fn csr(names: &[&str]) -> Vec<u8> {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = rcgen::CertificateParams::new(
        names
            .iter()
            .map(|name| name.to_string())
            .collect::<Vec<_>>(),
    )
    .unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.serialize_request(&key).unwrap().der().to_vec()
}

struct World {
    ca: TestCa,
    store: Store,
    configuration: Configuration,
    people: People,
}

impl World {
    fn new() -> Self {
        Self {
            ca: TestCa::new(),
            store: Store::memory().unwrap(),
            configuration: configuration(RADIUS),
            people: People::default(),
        }
    }

    fn submit(&mut self, template: &str, names: &[&str], who: &Person) -> Submission {
        let authority = self.ca.authority();
        Pipeline::new(&mut self.store, &self.configuration, &self.people)
            .submit(&authority, template, &csr(names), who, NOW)
            .unwrap()
    }

    fn all_requests(&self) -> Vec<pki_store::Request> {
        self.store.requests(&RequestFilter::default()).unwrap()
    }
}

fn pending_id(submission: &Submission) -> RequestId {
    match submission {
        Submission::Pending { request, .. } => *request,
        other => panic!("expected a held request, got {other:?}"),
    }
}

fn issued(submission: &Submission) -> X509Certificate<'_> {
    match submission {
        Submission::Issued { certificate, .. } => X509Certificate::from_der(certificate).unwrap().1,
        other => panic!("expected an issued certificate, got {other:?}"),
    }
}

#[test]
fn owners_obtain_their_own_names_at_once() {
    let mut world = World::new();
    let submission = world.submit(SERVER, &["radius.home"], &Person::user(RADIUS));
    let certificate = issued(&submission);
    let names: Vec<String> = certificate
        .subject_alternative_name()
        .unwrap()
        .unwrap()
        .value
        .general_names
        .iter()
        .map(|name| name.to_string())
        .collect();
    assert_eq!(names, vec!["DNSName(radius.home)"]);

    let Submission::Issued { request, .. } = submission else {
        unreachable!()
    };
    let stored = world.store.request(request).unwrap().unwrap();
    assert_eq!(stored.status, RequestStatus::Issued);
    assert_eq!(stored.decider, None);
    assert_eq!(stored.template, SERVER);
    let certificate = world.store.certificate_for(request).unwrap().unwrap();
    assert_eq!(certificate.owner, Some(Sid::new(RADIUS).unwrap()));
}

#[test]
fn refused_requests_are_recorded_with_reasons() {
    let mut world = World::new();
    let submission = world.submit(SERVER, &["radius.home"], &Person::user(JACK));
    let Submission::Denied { request, reasons } = submission else {
        panic!("expected a refusal, got {submission:?}");
    };
    assert!(
        reasons
            .iter()
            .any(|reason| reason.starts_with("radius.home:")),
        "{reasons:?}"
    );
    let stored = world.store.request(request).unwrap().unwrap();
    assert_eq!(stored.status, RequestStatus::Denied);
    assert_eq!(stored.reasons, reasons);
}

#[test]
fn requesting_needs_the_request_right_at_the_ca() {
    let mut world = World::new();
    let anonymous = Person::new(&["S-1-5-7"]);
    let ca = world.ca.authority();
    let result = Pipeline::new(&mut world.store, &world.configuration, &world.people).submit(
        &ca,
        SERVER,
        &csr(&["radius.home"]),
        &anonymous,
        NOW,
    );
    assert_eq!(result, Err(PipelineError::AccessDenied));
    assert!(world.all_requests().is_empty());
}

#[test]
fn templates_the_ca_does_not_offer_are_refused() {
    let mut world = World::new();
    let mut ca = world.ca.authority();
    ca.templates = vec![SERVER.into()];
    let result = Pipeline::new(&mut world.store, &world.configuration, &world.people).submit(
        &ca,
        APPROVED_SERVER,
        &csr(&["radius.home"]),
        &Person::user(RADIUS),
        NOW,
    );
    assert_eq!(
        result,
        Err(PipelineError::NoSuchTemplate(APPROVED_SERVER.into()))
    );
    assert!(world.all_requests().is_empty());
}

#[test]
fn malformed_requests_are_not_recorded() {
    let mut world = World::new();
    let ca = world.ca.authority();
    let result = Pipeline::new(&mut world.store, &world.configuration, &world.people).submit(
        &ca,
        SERVER,
        b"not a request",
        &Person::user(RADIUS),
        NOW,
    );
    assert!(
        matches!(result, Err(PipelineError::BadRequest(_))),
        "{result:?}"
    );
    assert!(world.all_requests().is_empty());
}

#[test]
fn officers_approve_held_requests() {
    let mut world = World::new();
    let submission = world.submit(APPROVED_SERVER, &["radius.home"], &Person::user(RADIUS));
    let id = pending_id(&submission);

    let ca = world.ca.authority();
    let officer = Person::admin(ALEX);
    let approved = Pipeline::new(&mut world.store, &world.configuration, &world.people)
        .approve(&ca, id, &officer, NOW)
        .unwrap();
    issued(&approved);
    let stored = world.store.request(id).unwrap().unwrap();
    assert_eq!(stored.status, RequestStatus::Issued);
    assert_eq!(stored.decider, Some(Sid::new(ALEX).unwrap()));

    // The requester retrieves the certificate without needing Read.
    let pipeline = Pipeline::new(&mut world.store, &world.configuration, &world.people);
    let certificate = pipeline
        .certificate_for(&ca, id, &Person::user(RADIUS))
        .unwrap();
    assert_eq!(certificate.request, id);
}

#[test]
fn approval_rights_hold_requests_for_an_officer() {
    let mut world = World::new();
    let lab_admin = Person::new(&[JACK, LAB_ADMINS, AUTHENTICATED_USERS]);
    let submission = world.submit(SERVER, &["printer.lab.home"], &lab_admin);
    pending_id(&submission);
}

#[test]
fn nobody_approves_their_own_request() {
    let mut world = World::new();
    let admin = Person::admin(ALEX);
    let submission = world.submit(APPROVED_SERVER, &["printer.home"], &admin);
    let id = pending_id(&submission);
    let ca = world.ca.authority();
    let result = Pipeline::new(&mut world.store, &world.configuration, &world.people)
        .approve(&ca, id, &admin, NOW);
    assert_eq!(result, Err(PipelineError::SelfApproval));
    assert_eq!(
        world.store.request(id).unwrap().unwrap().status,
        RequestStatus::Pending
    );
}

#[test]
fn approval_runs_policy_again() {
    let mut world = World::new();
    let submission = world.submit(APPROVED_SERVER, &["radius.home"], &Person::user(RADIUS));
    let id = pending_id(&submission);

    // radius.home has since been given to someone else.
    world.configuration = configuration(JACK);
    let ca = world.ca.authority();
    let officer = Person::admin(ALEX);
    let result = Pipeline::new(&mut world.store, &world.configuration, &world.people)
        .approve(&ca, id, &officer, NOW);
    assert!(
        matches!(result, Err(PipelineError::NowRefused(_))),
        "{result:?}"
    );
    assert_eq!(
        world.store.request(id).unwrap().unwrap().status,
        RequestStatus::Pending
    );

    Pipeline::new(&mut world.store, &world.configuration, &world.people)
        .deny(&ca, id, &officer, Some("radius.home changed hands"), NOW)
        .unwrap();
    let stored = world.store.request(id).unwrap().unwrap();
    assert_eq!(stored.status, RequestStatus::Denied);
    assert_eq!(
        stored.reasons,
        vec!["radius.home changed hands".to_string()]
    );
    assert_eq!(stored.decider, Some(Sid::new(ALEX).unwrap()));
}

#[test]
fn only_officers_decide_and_revoke() {
    let mut world = World::new();
    let held = pending_id(&world.submit(APPROVED_SERVER, &["radius.home"], &Person::user(RADIUS)));
    let Submission::Issued { request, .. } =
        world.submit(SERVER, &["radius.home"], &Person::user(RADIUS))
    else {
        panic!("expected an issued certificate");
    };
    let serial = world
        .store
        .certificate_for(request)
        .unwrap()
        .unwrap()
        .serial;

    let ca = world.ca.authority();
    let user = Person::user(JACK);
    let mut pipeline = Pipeline::new(&mut world.store, &world.configuration, &world.people);
    assert_eq!(
        pipeline.approve(&ca, held, &user, NOW),
        Err(PipelineError::AccessDenied)
    );
    assert_eq!(
        pipeline.deny(&ca, held, &user, None, NOW),
        Err(PipelineError::AccessDenied)
    );
    assert_eq!(
        pipeline.revoke(&ca, &serial, RevocationReason::KeyCompromise, &user, NOW),
        Err(PipelineError::AccessDenied)
    );
}

#[test]
fn officers_revoke_certificates() {
    let mut world = World::new();
    let Submission::Issued { request, .. } =
        world.submit(SERVER, &["radius.home"], &Person::user(RADIUS))
    else {
        panic!("expected an issued certificate");
    };
    let serial = world
        .store
        .certificate_for(request)
        .unwrap()
        .unwrap()
        .serial;
    let ca = world.ca.authority();
    let officer = Person::admin(ALEX);
    let mut pipeline = Pipeline::new(&mut world.store, &world.configuration, &world.people);
    pipeline
        .revoke(&ca, &serial, RevocationReason::KeyCompromise, &officer, NOW)
        .unwrap();
    assert_eq!(
        pipeline.revoke(&ca, &serial, RevocationReason::KeyCompromise, &officer, NOW),
        Err(PipelineError::AlreadyRevoked)
    );
    let unknown = SerialNumber::random().unwrap();
    assert_eq!(
        pipeline.revoke(&ca, &unknown, RevocationReason::Unspecified, &officer, NOW),
        Err(PipelineError::NoSuchCertificate)
    );
    let revoked = world.store.revoked(CA_ID, NOW).unwrap();
    assert_eq!(revoked.len(), 1);
    assert_eq!(revoked[0].1.revoker, Sid::new(ALEX).unwrap());
}

#[test]
fn nothing_is_issued_while_the_key_is_unavailable() {
    let mut world = World::new();
    let locked = world.ca.locked();
    let result = Pipeline::new(&mut world.store, &world.configuration, &world.people).submit(
        &locked,
        SERVER,
        &csr(&["radius.home"]),
        &Person::user(RADIUS),
        NOW,
    );
    assert_eq!(result, Err(PipelineError::KeyUnavailable));
    assert!(world.all_requests().is_empty());

    // Requests are still held, and wait for the key to be approved.
    let held = Pipeline::new(&mut world.store, &world.configuration, &world.people)
        .submit(
            &locked,
            APPROVED_SERVER,
            &csr(&["radius.home"]),
            &Person::user(RADIUS),
            NOW,
        )
        .unwrap();
    let id = pending_id(&held);
    let result = Pipeline::new(&mut world.store, &world.configuration, &world.people).approve(
        &locked,
        id,
        &Person::admin(ALEX),
        NOW,
    );
    assert_eq!(result, Err(PipelineError::KeyUnavailable));
    assert_eq!(
        world.store.request(id).unwrap().unwrap().status,
        RequestStatus::Pending
    );
}

#[test]
fn requesters_see_only_their_own_requests() {
    let mut world = World::new();
    let radius = world.submit(SERVER, &["radius.home"], &Person::user(RADIUS));
    let jack = world.submit(SERVER, &["radius.home"], &Person::user(JACK));
    let (
        Submission::Issued {
            request: radius_id, ..
        },
        Submission::Denied {
            request: jack_id, ..
        },
    ) = (radius, jack)
    else {
        panic!("unexpected outcomes");
    };

    let ca = world.ca.authority();
    let pipeline = Pipeline::new(&mut world.store, &world.configuration, &world.people);
    let jack = Person::user(JACK);
    assert_eq!(
        pipeline.request(&ca, radius_id, &jack),
        Err(PipelineError::NoSuchRequest(radius_id))
    );
    assert!(pipeline.request(&ca, jack_id, &jack).is_ok());
    let listed: Vec<_> = pipeline
        .requests(&ca, RequestFilter::default(), &jack)
        .unwrap()
        .iter()
        .map(|request| request.id)
        .collect();
    assert_eq!(listed, vec![jack_id]);
    assert!(pipeline
        .certificates(&ca, CertificateFilter::default(), &jack)
        .unwrap()
        .is_empty());
    let serial = pipeline
        .certificate_for(&ca, radius_id, &Person::user(RADIUS))
        .unwrap()
        .serial;
    assert_eq!(
        pipeline.certificate(&ca, &serial, &jack),
        Err(PipelineError::NoSuchCertificate)
    );

    // Readers see everything.
    let admin = Person::admin(ALEX);
    assert_eq!(
        pipeline
            .requests(&ca, RequestFilter::default(), &admin)
            .unwrap()
            .len(),
        2
    );
    assert!(pipeline.certificate(&ca, &serial, &admin).is_ok());
}

#[test]
fn owner_display_names_come_from_the_directory() {
    let mut world = World::new();
    world
        .people
        .display_names
        .insert(RADIUS.into(), "RADIUS Service".into());
    let submission = world.submit(NAMED_SERVER, &["radius.home"], &Person::user(RADIUS));
    let certificate = issued(&submission);
    let common_name = certificate
        .subject()
        .iter_common_name()
        .next()
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(common_name, "RADIUS Service");
}
