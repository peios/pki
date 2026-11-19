//! pkid's configuration and request handling, with a model of KACS access
//! checks in place of the kernel.

use std::cell::RefCell;
use std::collections::HashMap;

use peios_crypto::{KeyAlgorithm, PrivateKey};
use pki_core::{create_root, CaProfile, CaSubject, DisplayName, SerialNumber, Sid, Validity};
use pki_keys::OpenKey;
use pki_pipeline::{Directory, PipelineError, Principal};
use pki_policy::defaults::{name_root, server_template};
use pki_policy::{AccessChecker, PolicyError, RegData, SecurityBlob, Values};
use pki_store::Store;
use pkid::config::{load, Snapshot};
use pkid::dispatch::{handle, Audit, Event, State};
use pkid_core::{ErrorCode, Outcome, Reply, Request, RequestQuery};
use time::macros::datetime;
use time::OffsetDateTime;

const RADIUS: &str = "S-1-5-80-1-2-3";
const JACK: &str = "S-1-5-21-1-2-3-1001";
const ADMINISTRATORS: &str = "S-1-5-32-544";
const AUTHENTICATED_USERS: &str = "S-1-5-11";
const SERVER: &str = "0e5b5a3c-2f4d-4c1a-8e9b-111111111111";
const NOW: OffsetDateTime = datetime!(2027-01-01 12:00 UTC);

/// A stand-in descriptor: `trustee:mask[:inherit]` per line.
fn sd(entries: &[&str]) -> SecurityBlob {
    SecurityBlob::new(entries.join("\n").into_bytes())
}

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
}

impl AccessChecker for Person {
    fn granted(
        &self,
        security: &SecurityBlob,
        desired: u32,
        self_sid: Option<&Sid>,
    ) -> Result<u32, PolicyError> {
        let text = std::str::from_utf8(security.as_bytes()).unwrap();
        let mut granted = 0;
        for line in text.lines() {
            let mut parts = line.split(':');
            let trustee = parts.next().unwrap();
            let mask: u32 = parts.next().unwrap().parse().unwrap();
            let matches = match trustee {
                "self" => self_sid.is_some_and(|sid| self.sids.iter().any(|s| s == sid.as_str())),
                sid => self.sids.iter().any(|s| s == sid),
            };
            if matches {
                granted |= mask;
            }
        }
        Ok(granted & desired)
    }

    fn inherit(&self, parent: &SecurityBlob) -> Result<SecurityBlob, PolicyError> {
        let text = std::str::from_utf8(parent.as_bytes()).unwrap();
        let kept: Vec<&str> = text
            .lines()
            .filter(|line| line.ends_with(":inherit"))
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

struct People;

impl Directory for People {
    fn restore(&self, snapshot: &[u8]) -> Result<Box<dyn Principal>, PipelineError> {
        let text = std::str::from_utf8(snapshot).unwrap();
        Ok(Box::new(Person::new(&text.split(',').collect::<Vec<_>>())))
    }

    fn display_name(&self, _: &Sid) -> Result<Option<DisplayName>, PipelineError> {
        Ok(None)
    }
}

#[derive(Default)]
struct Recorder(RefCell<Vec<Event>>);

impl Audit for Recorder {
    fn record(&self, event: Event) {
        self.0.borrow_mut().push(event);
    }
}

fn ca() -> (PrivateKey, Vec<u8>) {
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
    (key, certificate)
}

fn snapshot(certificate: &[u8]) -> Snapshot {
    let root = sd(&["self:1:inherit", &format!("{ADMINISTRATORS}:7:inherit")]);
    let mut radius = Values::new();
    radius.insert("Owner", RegData::Sz(RADIUS.into()));
    let mut authority = Values::new();
    authority.insert("Name", RegData::Sz("Home Issuing CA".into()));
    authority.insert("Certificate", RegData::Binary(certificate.to_vec()));
    authority.insert("Key", RegData::Sz("service:issuing".into()));
    authority.insert(
        "CaSecurity",
        RegData::Binary(
            sd(&[
                &format!("{AUTHENTICATED_USERS}:2"),
                &format!("{ADMINISTRATORS}:15"),
            ])
            .as_bytes()
            .to_vec(),
        ),
    );
    authority.insert("Templates", RegData::MultiSz(vec![SERVER.to_uppercase()]));
    Snapshot {
        settings: Values::new(),
        templates: vec![(
            SERVER.into(),
            server_template(&sd(&[&format!("{AUTHENTICATED_USERS}:1")])),
        )],
        dns: vec![
            (Vec::new(), name_root(&root)),
            (vec!["home".into(), "radius".into()], radius),
        ],
        principals: vec![(Vec::new(), name_root(&root))],
        authorities: vec![("issuing".into(), authority)],
    }
}

fn default_security() -> SecurityBlob {
    sd(&[&format!("{ADMINISTRATORS}:15")])
}

fn state(key: PrivateKey, certificate: &[u8]) -> State {
    let loaded = load(&snapshot(certificate), &default_security()).unwrap();
    let mut keys: HashMap<String, OpenKey> = HashMap::new();
    keys.insert("issuing".into(), Box::new(key));
    State {
        store: Ok(Store::memory().unwrap()),
        loaded: Ok(loaded),
        keys,
        source: None,
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

fn call(
    state: &mut State,
    request: Request,
    caller: &Person,
) -> Result<Reply, pkid_core::WireError> {
    handle(state, request, caller, &People, &Recorder::default(), NOW)
}

#[test]
fn configuration_loads_from_the_registry_layout() {
    let (_, certificate) = ca();
    let loaded = load(&snapshot(&certificate), &default_security()).unwrap();
    let authority = loaded.authority("issuing").unwrap();
    assert_eq!(authority.name, "Home Issuing CA");
    assert_eq!(authority.key.to_string(), "service:issuing");
    // Template GUIDs are matched case-insensitively.
    assert_eq!(authority.templates, vec![SERVER.to_string()]);
    assert!(loaded.configuration.sid_extension);
}

#[test]
fn a_ca_without_security_gets_the_default() {
    let (_, certificate) = ca();
    let mut snapshot = snapshot(&certificate);
    let mut authority = snapshot.authorities[0].1.clone();
    let mut stripped = Values::new();
    for (name, data) in authority.iter() {
        if !name.eq_ignore_ascii_case("CaSecurity") {
            stripped.insert(name, data.clone());
        }
    }
    authority = stripped;
    snapshot.authorities[0].1 = authority;
    let loaded = load(&snapshot, &default_security()).unwrap();
    assert_eq!(
        loaded.authority("issuing").unwrap().security,
        default_security()
    );
}

#[test]
fn invalid_configuration_is_refused_whole() {
    let (_, certificate) = ca();
    let mut missing_root = snapshot(&certificate);
    missing_root.dns.remove(0);
    assert!(load(&missing_root, &default_security()).is_err());

    let mut unknown_template = snapshot(&certificate);
    unknown_template.authorities[0].1.insert(
        "Templates",
        RegData::MultiSz(vec!["no-such-template".into()]),
    );
    let error = load(&unknown_template, &default_security()).err().unwrap();
    assert!(error.0.contains("no-such-template"), "{error}");

    let mut bad_key = snapshot(&certificate);
    bad_key.authorities[0]
        .1
        .insert("Key", RegData::Sz("not a reference".into()));
    assert!(load(&bad_key, &default_security()).is_err());

    let mut extension_off = snapshot(&certificate);
    extension_off
        .settings
        .insert("SidSecurityExtension", RegData::Dword(0));
    assert!(
        !load(&extension_off, &default_security())
            .unwrap()
            .configuration
            .sid_extension
    );
}

#[test]
fn requests_are_issued_and_audited() {
    let (key, certificate) = ca();
    let mut state = state(key, &certificate);
    let radius = Person::new(&[RADIUS, AUTHENTICATED_USERS]);
    let audit = Recorder::default();
    let reply = handle(
        &mut state,
        Request::Submit {
            ca: "issuing".into(),
            template: SERVER.to_uppercase(),
            csr: csr(&["radius.home"]),
        },
        &radius,
        &People,
        &audit,
        NOW,
    )
    .unwrap();
    let Reply::Submission(submission) = reply else {
        panic!("expected a submission reply");
    };
    assert!(matches!(submission.outcome, Outcome::Issued(_)));
    assert_eq!(
        audit.0.borrow().as_slice(),
        &[Event::Submitted {
            ca: "issuing".into(),
            request: submission.request,
            requester: Sid::new(RADIUS).unwrap(),
            outcome: "issued",
        }]
    );

    let Reply::Certificate(certificate) = call(
        &mut state,
        Request::CertificateFor {
            ca: "issuing".into(),
            request: submission.request,
        },
        &radius,
    )
    .unwrap() else {
        panic!("expected a certificate");
    };
    assert_eq!(certificate.owner.as_deref(), Some(RADIUS));
}

#[test]
fn authorities_list_only_cas_the_caller_has_rights_at() {
    let (key, certificate) = ca();
    let mut state = state(key, &certificate);
    let user = Person::new(&[JACK, AUTHENTICATED_USERS]);
    let Reply::Authorities(listed) = call(&mut state, Request::Authorities, &user).unwrap() else {
        panic!("expected authorities");
    };
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].templates[0].name, "Server");
    assert!(listed[0].key_available);

    let stranger = Person::new(&["S-1-5-7"]);
    let Reply::Authorities(listed) = call(&mut state, Request::Authorities, &stranger).unwrap()
    else {
        panic!("expected authorities");
    };
    assert!(listed.is_empty());
}

#[test]
fn failures_map_to_wire_codes() {
    let (key, certificate) = ca();
    let mut state = state(key, &certificate);
    let user = Person::new(&[JACK, AUTHENTICATED_USERS]);
    let admin = Person::new(&[JACK, ADMINISTRATORS, AUTHENTICATED_USERS]);
    let code = |state: &mut State, request: Request, caller: &Person| {
        call(state, request, caller).unwrap_err().code
    };
    assert_eq!(
        code(
            &mut state,
            Request::Requests {
                ca: "elsewhere".into(),
                query: RequestQuery::default()
            },
            &user
        ),
        ErrorCode::NotFound
    );
    assert_eq!(
        code(
            &mut state,
            Request::Approve {
                ca: "issuing".into(),
                request: 1
            },
            &user
        ),
        ErrorCode::AccessDenied
    );
    assert_eq!(
        code(
            &mut state,
            Request::Revoke {
                ca: "issuing".into(),
                serial: vec![0x01],
                reason: 7
            },
            &admin
        ),
        ErrorCode::BadRequest
    );
    assert_eq!(
        code(
            &mut state,
            Request::Submit {
                ca: "issuing".into(),
                template: "unknown".into(),
                csr: csr(&["radius.home"])
            },
            &user
        ),
        ErrorCode::NotFound
    );

    state.keys.clear();
    assert_eq!(
        code(
            &mut state,
            Request::Submit {
                ca: "issuing".into(),
                template: SERVER.into(),
                csr: csr(&["printer.home"])
            },
            &admin
        ),
        ErrorCode::KeyUnavailable
    );
}

#[test]
fn an_invalid_configuration_or_database_makes_pkid_unavailable() {
    let (key, certificate) = ca();
    let user = Person::new(&[JACK, AUTHENTICATED_USERS]);
    let mut broken = state(key, &certificate);
    broken.loaded = Err("Templates\\x: LifetimeDays is missing".into());
    let error = call(&mut broken, Request::Authorities, &user).unwrap_err();
    assert_eq!(error.code, ErrorCode::Unavailable);
    assert!(error.message.contains("LifetimeDays"));

    let (key, certificate) = ca();
    let mut no_database = state(key, &certificate);
    no_database.store = Err("not provisioned".into());
    assert_eq!(
        call(&mut no_database, Request::Authorities, &user)
            .unwrap_err()
            .code,
        ErrorCode::Unavailable
    );
}
