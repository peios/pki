//! pkid's configuration and request handling, with a model of KACS access
//! checks, an in-memory Registry and in-memory key storage in place of the
//! kernel.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use peios_crypto::{KeyAlgorithm, PrivateKey, Secret};
use pki_core::{
    create_root, CaProfile, CaSubject, DisplayName, IssuingCa, SerialNumber, Sid, Validity,
};
use pki_keys::{
    describe_sealed_key, KeyFileProvider, KeyOptions, KeyProvider, KeyProviders, KeyStore,
    ServiceKeyProvider,
};
use pki_pipeline::{Directory, PipelineError, Principal};
use pki_policy::defaults::{name_root, server_template};
use pki_policy::{AccessChecker, PolicyError, RegData, SecurityBlob, Values};
use pki_store::{RequestFilter, Store};
use pkid::config::AuthorityConfig;
use pkid::config::{load, Defaults, Snapshot, Source};
use pkid::crl::{self, Publication, Publisher};
use pkid::dispatch::{apply, handle, Audit, Configurator, Event, Services, State};
use pkid_core::{
    ErrorCode, Issuer, KeySpec, Outcome, Passphrase, Reply, Request, RequestQuery, WireError,
};
use time::macros::datetime;
use time::OffsetDateTime;

const RADIUS: &str = "S-1-5-80-1-2-3";
const JACK: &str = "S-1-5-21-1-2-3-1001";
const ALEX: &str = "S-1-5-21-1-2-3-1002";
const ADMINISTRATORS: &str = "S-1-5-32-544";
const AUTHENTICATED_USERS: &str = "S-1-5-11";
const SERVER: &str = "0e5b5a3c-2f4d-4c1a-8e9b-111111111111";
const NOW: OffsetDateTime = datetime!(2027-01-01 12:00 UTC);
const PASSPHRASE: &str = "correct horse battery staple";

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

    fn validate(&self, security: &SecurityBlob) -> Result<(), PolicyError> {
        // The model's stand-in for a descriptor without an access list.
        if security.as_bytes().is_empty() {
            return Err(PolicyError::InvalidConfiguration("no access list".into()));
        }
        Ok(())
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

impl pki_policy::Accounts for People {
    fn account(&self, _: &str) -> Result<Option<Sid>, String> {
        Ok(None)
    }
}

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

/// A CA's identifier and a CRL published for it.
type Published = (String, Vec<u8>);

/// Every CRL published, by CA.
#[derive(Clone, Default)]
struct Shelf(Arc<Mutex<Vec<Published>>>);

impl Publisher for Shelf {
    fn publish(&self, ca: &AuthorityConfig, crl: &[u8]) -> Result<(), String> {
        self.0.lock().unwrap().push((ca.id.clone(), crl.to_vec()));
        Ok(())
    }
}

/// The Registry, in memory. Writes fail while `failing` is set.
struct Registry(RefCell<Snapshot>, Cell<bool>);

impl Configurator for Registry {
    fn write_authority(&self, id: &str, values: &Values, remove: &[&str]) -> Result<(), String> {
        if self.1.get() {
            return Err("the Registry refused the write".into());
        }
        let mut snapshot = self.0.borrow_mut();
        let index = match snapshot.authorities.iter().position(|(key, _)| key == id) {
            Some(index) => index,
            None => {
                snapshot.authorities.push((id.to_string(), Values::new()));
                snapshot.authorities.len() - 1
            }
        };
        let existing = &snapshot.authorities[index].1;
        let mut merged = Values::new();
        for (name, data) in existing.iter() {
            let removed = remove.iter().any(|gone| gone.eq_ignore_ascii_case(name));
            if !removed {
                merged.insert(name, data.clone());
            }
        }
        for (name, data) in values.iter() {
            merged.insert(name, data.clone());
        }
        snapshot.authorities[index].1 = merged;
        Ok(())
    }

    fn read(&self) -> Source {
        Ok(self.0.borrow().clone())
    }
}

/// Key storage in memory, standing in for pkid's key directory.
#[derive(Default, Clone)]
struct MemoryStore(Arc<Mutex<HashMap<String, Vec<u8>>>>);

impl KeyStore for MemoryStore {
    fn create(&self, name: &str, contents: &[u8]) -> io::Result<()> {
        let mut keys = self.0.lock().unwrap();
        if keys.contains_key(name) {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        keys.insert(name.to_string(), contents.to_vec());
        Ok(())
    }

    fn read(&self, name: &str) -> io::Result<Secret> {
        let keys = self.0.lock().unwrap();
        let contents = keys.get(name).ok_or(io::ErrorKind::NotFound)?;
        Ok(Secret::from(contents.as_slice()))
    }

    fn delete(&self, name: &str) -> io::Result<()> {
        let mut keys = self.0.lock().unwrap();
        keys.remove(name)
            .map(|_| ())
            .ok_or(io::ErrorKind::NotFound.into())
    }
}

fn defaults() -> Defaults {
    Defaults {
        ca_security: sd(&[&format!("{ADMINISTRATORS}:15")]),
        manage_security: sd(&[&format!("{ADMINISTRATORS}:8")]),
    }
}

/// A fresh, empty directory for one test's key files.
fn directory(test: &str) -> PathBuf {
    let directory = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(test);
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

fn ca_certificate(key: &PrivateKey) -> Vec<u8> {
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
        path_length: Some(1),
        name_constraints: None,
        extended_key_usages: None,
        crl_distribution_points: Vec::new(),
    };
    create_root(key, &profile, &SerialNumber::random().unwrap())
        .unwrap()
        .der()
        .to_vec()
}

/// The configuration: one Server template, the default name roots with
/// radius.home owned by radiusd, and an issuing CA.
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
    authority.insert(
        "CrlDistributionPoints",
        RegData::MultiSz(vec!["http://pki.home/issuing.crl".into()]),
    );
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

struct World {
    state: State,
    registry: Registry,
    providers: KeyProviders,
    keys: MemoryStore,
    audit: Recorder,
    defaults: Defaults,
    shelf: Shelf,
    publishers: Vec<Box<dyn Publisher>>,
}

impl World {
    fn new() -> Self {
        let keys = MemoryStore::default();
        let service = ServiceKeyProvider::new(keys.clone());
        let key = PrivateKey::generate(KeyAlgorithm::EcdsaP256).unwrap();
        service
            .import(
                "issuing",
                &key,
                &KeyOptions {
                    exportable: true,
                    passphrase: None,
                },
            )
            .unwrap();
        let mut providers = KeyProviders::new();
        providers.add(Box::new(KeyFileProvider::new())).unwrap();
        providers.add(Box::new(service)).unwrap();
        let mut world = Self {
            state: State {
                store: Ok(Store::memory().unwrap()),
                loaded: Err("not loaded yet".into()),
                keys: HashMap::new(),
                source: None,
                publication: Publication::default(),
            },
            registry: Registry(
                RefCell::new(snapshot(&ca_certificate(&key))),
                Cell::new(false),
            ),
            providers,
            keys,
            audit: Recorder::default(),
            defaults: defaults(),
            shelf: Shelf::default(),
            publishers: Vec::new(),
        };
        world.publishers.push(Box::new(world.shelf.clone()));
        let source = world.registry.read();
        let services = Services {
            directory: &People,
            audit: &world.audit,
            configurator: &world.registry,
            providers: &world.providers,
            defaults: &world.defaults,
            publishers: &world.publishers,
        };
        apply(&mut world.state, source, &services);
        assert!(world.state.loaded.is_ok());
        world
    }

    /// Runs pkid's CRL schedule at `now`.
    fn maintain(&mut self, now: OffsetDateTime) {
        let services = Services {
            directory: &People,
            audit: &self.audit,
            configurator: &self.registry,
            providers: &self.providers,
            defaults: &self.defaults,
            publishers: &self.publishers,
        };
        crl::maintain(&mut self.state, &services, now);
    }

    fn published(&self) -> Vec<Published> {
        self.shelf.0.lock().unwrap().clone()
    }

    fn call(&mut self, request: Request, caller: &Person) -> Result<Reply, WireError> {
        let services = Services {
            directory: &People,
            audit: &self.audit,
            configurator: &self.registry,
            providers: &self.providers,
            defaults: &self.defaults,
            publishers: &self.publishers,
        };
        handle(&mut self.state, request, caller, &services, NOW)
    }

    fn code(&mut self, request: Request, caller: &Person) -> ErrorCode {
        self.call(request, caller).unwrap_err().code
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

#[test]
fn configuration_loads_from_the_registry_layout() {
    let world = World::new();
    let loaded = world.state.loaded.as_ref().unwrap();
    let authority = loaded.authority("issuing").unwrap();
    assert_eq!(authority.name, "Home Issuing CA");
    assert_eq!(authority.key.to_string(), "service:issuing");
    // Template GUIDs are matched case-insensitively.
    assert_eq!(authority.templates, vec![SERVER.to_string()]);
    assert!(loaded.configuration.sid_extension);
    assert!(world.state.keys.contains_key("issuing"));
    assert_eq!(
        world.audit.0.borrow().as_slice(),
        &[Event::ConfigurationLoaded { error: None }]
    );
}

#[test]
fn an_unchanged_registry_is_not_loaded_again() {
    let mut world = World::new();
    let services = Services {
        directory: &People,
        audit: &world.audit,
        configurator: &world.registry,
        providers: &world.providers,
        defaults: &world.defaults,
        publishers: &world.publishers,
    };
    apply(&mut world.state, world.registry.read(), &services);
    assert_eq!(world.audit.0.borrow().len(), 1);
}

#[test]
fn a_ca_without_security_gets_the_default() {
    let key = PrivateKey::generate(KeyAlgorithm::EcdsaP256).unwrap();
    let mut snapshot = snapshot(&ca_certificate(&key));
    let mut stripped = Values::new();
    for (name, data) in snapshot.authorities[0].1.iter() {
        if !name.eq_ignore_ascii_case("CaSecurity") {
            stripped.insert(name, data.clone());
        }
    }
    snapshot.authorities[0].1 = stripped;
    let loaded = load(&snapshot, &defaults()).unwrap();
    assert_eq!(
        loaded.authority("issuing").unwrap().security,
        defaults().ca_security
    );
}

#[test]
fn invalid_configuration_is_refused_whole() {
    let key = PrivateKey::generate(KeyAlgorithm::EcdsaP256).unwrap();
    let certificate = ca_certificate(&key);
    let mut missing_root = snapshot(&certificate);
    missing_root.dns.remove(0);
    assert!(load(&missing_root, &defaults()).is_err());

    let mut unknown_template = snapshot(&certificate);
    unknown_template.authorities[0].1.insert(
        "Templates",
        RegData::MultiSz(vec!["no-such-template".into()]),
    );
    let error = load(&unknown_template, &defaults()).err().unwrap();
    assert!(error.0.contains("no-such-template"), "{error}");

    let mut bad_key = snapshot(&certificate);
    bad_key.authorities[0]
        .1
        .insert("Key", RegData::Sz("not a reference".into()));
    assert!(load(&bad_key, &defaults()).is_err());

    let mut extension_off = snapshot(&certificate);
    extension_off
        .settings
        .insert("SidSecurityExtension", RegData::Dword(0));
    assert!(
        !load(&extension_off, &defaults())
            .unwrap()
            .configuration
            .sid_extension
    );
}

#[test]
fn requests_are_issued_and_audited() {
    let mut world = World::new();
    let radius = Person::user(RADIUS);
    let reply = world
        .call(
            Request::Submit {
                ca: "issuing".into(),
                template: SERVER.to_uppercase(),
                csr: csr(&["radius.home"]),
            },
            &radius,
        )
        .unwrap();
    let Reply::Submission(submission) = reply else {
        panic!("expected a submission reply");
    };
    assert!(matches!(submission.outcome, Outcome::Issued(_)));
    assert_eq!(
        world.audit.0.borrow().last(),
        Some(&Event::Submitted {
            ca: "issuing".into(),
            request: submission.request,
            requester: Sid::new(RADIUS).unwrap(),
            outcome: "issued",
        })
    );

    let Reply::Certificate(certificate) = world
        .call(
            Request::CertificateFor {
                ca: "issuing".into(),
                request: submission.request,
            },
            &radius,
        )
        .unwrap()
    else {
        panic!("expected a certificate");
    };
    assert_eq!(certificate.owner.as_deref(), Some(RADIUS));
}

#[test]
fn authorities_list_only_cas_the_caller_has_rights_at() {
    let mut world = World::new();
    let Reply::Authorities(listed) = world
        .call(Request::Authorities, &Person::user(JACK))
        .unwrap()
    else {
        panic!("expected authorities");
    };
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].templates[0].name, "Server");
    assert_eq!(listed[0].key, "service:issuing");
    assert!(listed[0].key_available);

    let Reply::Authorities(listed) = world
        .call(Request::Authorities, &Person::new(&["S-1-5-7"]))
        .unwrap()
    else {
        panic!("expected authorities");
    };
    assert!(listed.is_empty());
}

#[test]
fn authorities_say_what_the_caller_may_do() {
    let mut world = World::new();
    let listed = |world: &mut World, caller: &Person| match world.call(Request::Authorities, caller)
    {
        Ok(Reply::Authorities(listed)) => listed,
        other => panic!("expected authorities, got {other:?}"),
    };
    let user = &listed(&mut world, &Person::user(JACK))[0];
    assert_eq!(user.granted, 0x2);
    assert!(user.templates[0].enroll);
    assert!(!user.security.is_empty());
    assert_eq!(listed(&mut world, &Person::admin(ALEX))[0].granted, 0xf);

    // A service may use the CA without being able to enrol from the
    // template, which grants only authenticated users.
    let service = Person::new(&[RADIUS, "S-1-5-6"]);
    let ca = "issuing".to_string();
    world
        .call(
            Request::SetAuthoritySecurity {
                ca: ca.clone(),
                security: sd(&["S-1-5-6:2", &format!("{ADMINISTRATORS}:15")])
                    .as_bytes()
                    .to_vec(),
            },
            &Person::admin(ALEX),
        )
        .unwrap();
    let seen = &listed(&mut world, &service)[0];
    assert_eq!(seen.granted, 0x2);
    assert!(!seen.templates[0].enroll);
}

#[test]
fn only_managers_may_create_authorities() {
    let mut world = World::new();
    let access = |world: &mut World, caller: &Person| match world.call(Request::Access, caller) {
        Ok(Reply::Access(access)) => access.create,
        other => panic!("expected access, got {other:?}"),
    };
    assert!(access(&mut world, &Person::admin(ALEX)));
    assert!(!access(&mut world, &Person::user(JACK)));
}

#[test]
fn managers_change_who_may_use_a_ca() {
    let mut world = World::new();
    let security = sd(&[&format!("{JACK}:1"), &format!("{ADMINISTRATORS}:15")])
        .as_bytes()
        .to_vec();
    let change = |security: Vec<u8>| Request::SetAuthoritySecurity {
        ca: "issuing".into(),
        security,
    };
    assert_eq!(
        world.code(change(security.clone()), &Person::user(JACK)),
        ErrorCode::AccessDenied
    );
    assert_eq!(
        world.code(change(Vec::new()), &Person::admin(ALEX)),
        ErrorCode::BadRequest
    );

    let changed = authority(world.call(change(security.clone()), &Person::admin(ALEX)));
    assert_eq!(changed.security, security);
    assert_eq!(changed.granted, 0xf);
    assert!(matches!(
        world.audit.0.borrow().last(),
        Some(Event::Managed {
            action: "secured",
            ..
        })
    ));
    let Reply::Authorities(listed) = world
        .call(Request::Authorities, &Person::user(JACK))
        .unwrap()
    else {
        panic!("expected authorities");
    };
    assert_eq!(listed[0].granted, 0x1);
}

#[test]
fn failures_map_to_wire_codes() {
    let mut world = World::new();
    let user = Person::user(JACK);
    let admin = Person::admin(JACK);
    let requests = Request::Requests {
        ca: "elsewhere".into(),
        query: RequestQuery::default(),
    };
    assert_eq!(world.code(requests, &user), ErrorCode::NotFound);
    let approve = Request::Approve {
        ca: "issuing".into(),
        request: 1,
    };
    assert_eq!(world.code(approve, &user), ErrorCode::AccessDenied);
    let revoke = Request::Revoke {
        ca: "issuing".into(),
        serial: vec![0x01],
        reason: 7,
    };
    assert_eq!(world.code(revoke, &admin), ErrorCode::BadRequest);
    let unknown_template = Request::Submit {
        ca: "issuing".into(),
        template: "unknown".into(),
        csr: csr(&["radius.home"]),
    };
    assert_eq!(world.code(unknown_template, &user), ErrorCode::NotFound);

    world.state.keys.clear();
    let submit = Request::Submit {
        ca: "issuing".into(),
        template: SERVER.into(),
        csr: csr(&["printer.home"]),
    };
    assert_eq!(world.code(submit, &admin), ErrorCode::KeyUnavailable);
}

#[test]
fn an_invalid_configuration_or_database_makes_pkid_unavailable() {
    let user = Person::user(JACK);
    let mut broken = World::new();
    broken.state.loaded = Err("Templates\\x: LifetimeDays is missing".into());
    let error = broken.call(Request::Authorities, &user).unwrap_err();
    assert_eq!(error.code, ErrorCode::Unavailable);
    assert!(error.message.contains("LifetimeDays"));

    let mut no_database = World::new();
    no_database.state.store = Err("not provisioned".into());
    assert_eq!(
        no_database.code(Request::Authorities, &user),
        ErrorCode::Unavailable
    );
}

fn service_key(algorithm: &str) -> KeySpec {
    KeySpec {
        provider: "service".into(),
        locator: None,
        algorithm: Some(algorithm.into()),
        exportable: true,
        passphrase: None,
    }
}

fn create(name: &str, key: KeySpec, issuer: Issuer, path_length: Option<u8>) -> Request {
    Request::CreateAuthority {
        name: name.into(),
        key,
        issuer,
        lifetime_days: 1825,
        path_length,
        templates: Vec::new(),
        crl_distribution_points: Vec::new(),
    }
}

fn authority(reply: Result<Reply, WireError>) -> pkid_core::AuthorityInfo {
    match reply {
        Ok(Reply::Authority(authority)) => authority,
        other => panic!("expected a CA, got {other:?}"),
    }
}

#[test]
fn administrators_create_roots_with_service_keys() {
    let mut world = World::new();
    let admin = Person::admin(ALEX);
    let root = authority(world.call(
        create(
            "Home Root CA",
            service_key("ecdsa-p384"),
            Issuer::SelfSigned,
            Some(1),
        ),
        &admin,
    ));
    assert_eq!(root.name, "Home Root CA");
    assert_eq!(root.key, format!("service:{}", root.id));
    assert!(root.certificate.is_some());
    assert!(root.request.is_none());
    assert!(root.key_available);
    // The new CA is configured before the reply, so it can be used at once.
    let loaded = world.state.loaded.as_ref().unwrap();
    assert!(loaded.authority(&root.id).is_some());
    assert_eq!(
        world.audit.0.borrow().last(),
        Some(&Event::Managed {
            ca: root.id.clone(),
            action: "created",
            operator: Sid::new(ALEX).unwrap(),
        })
    );
}

#[test]
fn creating_cas_needs_manage_ca_on_the_service() {
    let mut world = World::new();
    let request = create(
        "Rogue Root",
        service_key("ecdsa-p256"),
        Issuer::SelfSigned,
        None,
    );
    assert_eq!(
        world.code(request, &Person::user(JACK)),
        ErrorCode::AccessDenied
    );
    assert_eq!(
        world.state.loaded.as_ref().unwrap().authorities.len(),
        1,
        "nothing was created"
    );
}

#[test]
fn subordinates_of_local_cas_are_signed_and_recorded() {
    let mut world = World::new();
    let admin = Person::admin(ALEX);
    let lab = authority(world.call(
        create(
            "Lab CA",
            service_key("ecdsa-p256"),
            Issuer::Authority {
                ca: "issuing".into(),
                passphrase: None,
            },
            Some(0),
        ),
        &admin,
    ));
    let certificate = lab.certificate.unwrap();
    let issuing = world
        .state
        .loaded
        .as_ref()
        .unwrap()
        .authority("issuing")
        .unwrap();
    let parent_certificate = issuing.certificate.clone().unwrap();
    let parent_key = world.state.keys.get("issuing").unwrap();
    IssuingCa::new(&parent_certificate, parent_key.as_ref()).unwrap();
    let lab_key = world.state.keys.get(&lab.id).unwrap();
    IssuingCa::new(&certificate, lab_key.as_ref()).unwrap();

    let store = world.state.store.as_ref().unwrap();
    let recorded = store
        .requests(&RequestFilter {
            ca: Some("issuing".into()),
            ..RequestFilter::default()
        })
        .unwrap();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].template, "subordinate-ca");
    assert_eq!(recorded[0].names, vec!["Lab CA".to_string()]);
}

#[test]
fn offline_subordinates_await_their_certificate() {
    let mut world = World::new();
    let admin = Person::admin(ALEX);
    let lab = authority(world.call(
        create(
            "Lab CA",
            service_key("ecdsa-p256"),
            Issuer::Offline,
            Some(0),
        ),
        &admin,
    ));
    assert!(lab.certificate.is_none());
    let request = lab.request.clone().unwrap();

    // It takes no requests until installed.
    let submit = Request::Submit {
        ca: lab.id.clone(),
        template: SERVER.into(),
        csr: csr(&["printer.home"]),
    };
    assert_eq!(world.code(submit, &admin), ErrorCode::Unavailable);

    // The wrong certificate is refused.
    let issuing_certificate = world
        .state
        .loaded
        .as_ref()
        .unwrap()
        .authority("issuing")
        .unwrap()
        .certificate
        .clone()
        .unwrap();
    let wrong = Request::InstallAuthority {
        ca: lab.id.clone(),
        certificate: issuing_certificate,
    };
    assert_eq!(world.code(wrong, &admin), ErrorCode::BadRequest);

    // A CA elsewhere, here the issuing CA, signs its request.
    let Reply::Signed(certificate) = world
        .call(
            Request::SignSubordinate {
                ca: "issuing".into(),
                csr: request,
                name: "Lab CA".into(),
                lifetime_days: 1825,
                path_length: Some(0),
                passphrase: None,
            },
            &admin,
        )
        .unwrap()
    else {
        panic!("expected a signed certificate");
    };
    let installed = authority(world.call(
        Request::InstallAuthority {
            ca: lab.id.clone(),
            certificate: certificate.clone(),
        },
        &admin,
    ));
    assert_eq!(installed.certificate, Some(certificate));
    assert!(installed.request.is_none());
    let again = Request::InstallAuthority {
        ca: lab.id,
        certificate: Vec::new(),
    };
    assert_eq!(world.code(again, &admin), ErrorCode::Conflict);
}

#[test]
fn file_keys_sign_only_with_their_passphrase() {
    let mut world = World::new();
    let admin = Person::admin(ALEX);
    let path = directory("file-root").join("root.key");
    let root = authority(world.call(
        create(
            "Offline Root",
            KeySpec {
                provider: "file".into(),
                locator: Some(path.to_str().unwrap().into()),
                algorithm: Some("ecdsa-p384".into()),
                exportable: true,
                passphrase: Some(Passphrase::new(PASSPHRASE.as_bytes().to_vec())),
            },
            Issuer::SelfSigned,
            Some(1),
        ),
        &admin,
    ));
    assert!(path.exists());
    assert!(!root.key_available, "a sealed key is never kept open");

    let unlocked = |passphrase: Option<&str>| {
        create(
            "Issuing CA 2",
            service_key("ecdsa-p256"),
            Issuer::Authority {
                ca: root.id.clone(),
                passphrase: passphrase.map(|text| Passphrase::new(text.as_bytes().to_vec())),
            },
            Some(0),
        )
    };
    assert_eq!(
        world.code(unlocked(None), &admin),
        ErrorCode::KeyUnavailable
    );
    assert_eq!(
        world.code(unlocked(Some("not the passphrase")), &admin),
        ErrorCode::BadRequest
    );
    let issuing = authority(world.call(unlocked(Some(PASSPHRASE)), &admin));
    assert!(issuing.certificate.is_some());
}

#[test]
fn a_failed_creation_leaves_no_key_behind() {
    let mut world = World::new();
    let admin = Person::admin(ALEX);
    world.registry.1.set(true);
    let mut key = service_key("ecdsa-p256");
    key.exportable = false;
    let request = create("Doomed CA", key, Issuer::SelfSigned, None);
    assert_eq!(world.code(request, &admin), ErrorCode::Internal);
    let stored: Vec<String> = world.keys.0.lock().unwrap().keys().cloned().collect();
    assert_eq!(stored, vec!["issuing".to_string()]);

    let path = directory("doomed-root").join("root.key");
    let request = create(
        "Doomed Root",
        KeySpec {
            provider: "file".into(),
            locator: Some(path.to_str().unwrap().into()),
            algorithm: Some("ecdsa-p256".into()),
            exportable: true,
            passphrase: Some(Passphrase::new(PASSPHRASE.as_bytes().to_vec())),
        },
        Issuer::SelfSigned,
        None,
    );
    assert_eq!(world.code(request, &admin), ErrorCode::Internal);
    assert!(!path.exists());
}

#[test]
fn key_files_cant_be_made_non_exportable() {
    let mut world = World::new();
    let path = directory("non-exportable-root").join("root.key");
    let request = create(
        "Root",
        KeySpec {
            provider: "file".into(),
            locator: Some(path.to_str().unwrap().into()),
            algorithm: Some("ecdsa-p256".into()),
            exportable: false,
            passphrase: Some(Passphrase::new(PASSPHRASE.as_bytes().to_vec())),
        },
        Issuer::SelfSigned,
        None,
    );
    assert_eq!(
        world.code(request, &Person::admin(ALEX)),
        ErrorCode::BadRequest
    );
    assert!(!path.exists());
}

#[test]
fn weak_passphrases_are_refused_for_new_key_files() {
    let mut world = World::new();
    let path = directory("weak-root").join("root.key");
    let request = create(
        "Weak Root",
        KeySpec {
            provider: "file".into(),
            locator: Some(path.to_str().unwrap().into()),
            algorithm: Some("ecdsa-p256".into()),
            exportable: true,
            passphrase: Some(Passphrase::new(b"short".to_vec())),
        },
        Issuer::SelfSigned,
        None,
    );
    assert_eq!(
        world.code(request, &Person::admin(ALEX)),
        ErrorCode::BadRequest
    );
    assert!(!path.exists());
}

#[test]
fn keys_export_sealed_and_import_as_a_new_ca() {
    let mut world = World::new();
    let admin = Person::admin(ALEX);
    let Reply::SealedKey(sealed) = world
        .call(
            Request::ExportKey {
                ca: "issuing".into(),
                current: None,
                passphrase: Passphrase::new(b"a long backup passphrase".to_vec()),
            },
            &admin,
        )
        .unwrap()
    else {
        panic!("expected a sealed key");
    };
    assert!(describe_sealed_key(&sealed).is_ok());
    let user_export = Request::ExportKey {
        ca: "issuing".into(),
        current: None,
        passphrase: Passphrase::new(b"a long backup passphrase".to_vec()),
    };
    assert_eq!(
        world.code(user_export, &Person::user(JACK)),
        ErrorCode::AccessDenied
    );

    let certificate = world
        .state
        .loaded
        .as_ref()
        .unwrap()
        .authority("issuing")
        .unwrap()
        .certificate
        .clone()
        .unwrap();
    let restored = authority(world.call(
        Request::ImportAuthority {
            name: "Restored Issuing CA".into(),
            certificate: certificate.clone(),
            sealed_key: sealed.clone(),
            passphrase: Passphrase::new(b"a long backup passphrase".to_vec()),
            key: KeySpec {
                provider: "service".into(),
                locator: None,
                algorithm: None,
                exportable: false,
                passphrase: None,
            },
            templates: vec![SERVER.into()],
            crl_distribution_points: Vec::new(),
        },
        &admin,
    ));
    assert_eq!(restored.certificate, Some(certificate));
    assert!(restored.key_available);

    let wrong = Request::ImportAuthority {
        name: "Wrong".into(),
        certificate: Vec::new(),
        sealed_key: sealed,
        passphrase: Passphrase::new(b"not the backup passphrase".to_vec()),
        key: KeySpec {
            provider: "service".into(),
            locator: None,
            algorithm: None,
            exportable: true,
            passphrase: None,
        },
        templates: Vec::new(),
        crl_distribution_points: Vec::new(),
    };
    assert_eq!(world.code(wrong, &admin), ErrorCode::BadRequest);
}

#[test]
fn cas_are_reconfigured_by_their_managers() {
    let mut world = World::new();
    let admin = Person::admin(ALEX);
    let configured = authority(world.call(
        Request::ConfigureAuthority {
            ca: "issuing".into(),
            templates: Some(Vec::new()),
            crl_distribution_points: Some(vec!["http://pki.home/issuing.crl".into()]),
            crl_lifetime_days: None,
        },
        &admin,
    ));
    assert!(configured.templates.is_empty());
    let issuing = world
        .state
        .loaded
        .as_ref()
        .unwrap()
        .authority("issuing")
        .unwrap();
    assert_eq!(
        issuing.crl_distribution_points,
        vec!["http://pki.home/issuing.crl".to_string()]
    );

    let unknown = Request::ConfigureAuthority {
        ca: "issuing".into(),
        templates: Some(vec!["no-such-template".into()]),
        crl_distribution_points: None,
        crl_lifetime_days: None,
    };
    assert_eq!(world.code(unknown, &admin), ErrorCode::BadRequest);
    let by_user = Request::ConfigureAuthority {
        ca: "issuing".into(),
        templates: None,
        crl_distribution_points: None,
        crl_lifetime_days: None,
    };
    assert_eq!(
        world.code(by_user, &Person::user(JACK)),
        ErrorCode::AccessDenied
    );
}

// CRLs.

fn issue_to_radius(world: &mut World) -> Vec<u8> {
    let reply = world
        .call(
            Request::Submit {
                ca: "issuing".into(),
                template: SERVER.into(),
                csr: csr(&["radius.home"]),
            },
            &Person::user(RADIUS),
        )
        .unwrap();
    let Reply::Submission(submission) = reply else {
        panic!("expected a submission");
    };
    let Reply::Certificate(certificate) = world
        .call(
            Request::CertificateFor {
                ca: "issuing".into(),
                request: submission.request,
            },
            &Person::admin(ALEX),
        )
        .unwrap()
    else {
        panic!("expected a certificate");
    };
    certificate.serial
}

fn crl_numbers(world: &World) -> Vec<u64> {
    world
        .audit
        .0
        .borrow()
        .iter()
        .filter_map(|event| match event {
            Event::CrlPublished { number, .. } => Some(*number),
            _ => None,
        })
        .collect()
}

#[test]
fn the_schedule_signs_a_crl_and_renews_it_at_half_its_life() {
    let mut world = World::new();
    world.maintain(NOW);
    assert_eq!(crl_numbers(&world), [1]);
    assert_eq!(world.published().len(), 1);
    assert_eq!(world.published()[0].0, "issuing");
    // Nothing more is due until half way through its seven days.
    world.maintain(NOW + time::Duration::days(3));
    assert_eq!(crl_numbers(&world), [1]);
    world.maintain(NOW + time::Duration::hours(84));
    assert_eq!(crl_numbers(&world), [1, 2]);
    // A CA that renews its own CRL isn't warned about while it does.
    assert!(!world
        .audit
        .0
        .borrow()
        .iter()
        .any(|event| matches!(event, Event::CrlExpiring { .. })));
}

#[test]
fn a_revocation_is_published_at_once() {
    use x509_parser::prelude::{CertificateRevocationList, FromDer};
    let mut world = World::new();
    world.maintain(NOW);
    let serial = issue_to_radius(&mut world);
    world
        .call(
            Request::Revoke {
                ca: "issuing".into(),
                serial: serial.clone(),
                reason: 1,
            },
            &Person::admin(ALEX),
        )
        .unwrap();
    assert_eq!(crl_numbers(&world), [1, 2]);
    let published = world.published();
    let (_, list) = CertificateRevocationList::from_der(&published[1].1).unwrap();
    let listed: Vec<_> = list
        .iter_revoked_certificates()
        .map(|revoked| revoked.raw_serial().to_vec())
        .collect();
    assert_eq!(listed, [serial]);
    let Reply::Authorities(authorities) = world
        .call(Request::Authorities, &Person::admin(ALEX))
        .unwrap()
    else {
        panic!("expected authorities");
    };
    let crl = authorities[0].crl.clone().unwrap();
    assert_eq!(crl.number, 2);
    assert_eq!(authorities[0].crl_lifetime_days, 7);
    assert_eq!(crl.next_update - crl.this_update, 7 * 86_400);
}

#[test]
fn a_revocation_brings_one_crl_not_two() {
    let mut world = World::new();
    world.maintain(NOW);
    let serial = issue_to_radius(&mut world);
    world
        .call(
            Request::Revoke {
                ca: "issuing".into(),
                serial,
                reason: 1,
            },
            &Person::admin(ALEX),
        )
        .unwrap();
    // The schedule's next round finds nothing newer than the CRL the
    // revocation brought.
    world.maintain(NOW + time::Duration::minutes(1));
    assert_eq!(crl_numbers(&world), [1, 2]);
}

#[test]
fn a_new_distribution_point_is_published_without_a_new_crl() {
    let mut world = World::new();
    world.maintain(NOW);
    assert_eq!(world.published().len(), 1);
    world
        .call(
            Request::ConfigureAuthority {
                ca: "issuing".into(),
                templates: None,
                crl_distribution_points: Some(vec!["http://pki.home/new/issuing.crl".into()]),
                crl_lifetime_days: None,
            },
            &Person::admin(ALEX),
        )
        .unwrap();
    world.maintain(NOW + time::Duration::minutes(1));
    // The same CRL, handed to the publishers again for the new address.
    assert_eq!(crl_numbers(&world), [1]);
    let published = world.published();
    assert_eq!(published.len(), 2);
    assert_eq!(published[0].1, published[1].1);
}

#[test]
fn officers_publish_a_crl_on_request() {
    let mut world = World::new();
    let publish = || Request::PublishCrl {
        ca: "issuing".into(),
        passphrase: None,
    };
    assert_eq!(
        world.code(publish(), &Person::user(JACK)),
        ErrorCode::AccessDenied
    );
    let Reply::Crl(crl) = world.call(publish(), &Person::admin(ALEX)).unwrap() else {
        panic!("expected a CRL");
    };
    assert_eq!(crl.number, 1);
    assert!(world.audit.0.borrow().iter().any(|event| matches!(
        event,
        Event::CrlPublished { officer: Some(officer), .. } if officer.as_str() == ALEX
    )));
}

#[test]
fn a_crl_lifetime_is_set_per_ca() {
    let mut world = World::new();
    let set = |days| Request::ConfigureAuthority {
        ca: "issuing".into(),
        templates: None,
        crl_distribution_points: None,
        crl_lifetime_days: Some(days),
    };
    assert_eq!(
        world.code(set(0), &Person::admin(ALEX)),
        ErrorCode::BadRequest
    );
    let reply = world.call(set(14), &Person::admin(ALEX));
    assert_eq!(authority(reply).crl_lifetime_days, 14);
    world.maintain(NOW);
    let Reply::Authorities(authorities) = world
        .call(Request::Authorities, &Person::admin(ALEX))
        .unwrap()
    else {
        panic!("expected authorities");
    };
    let crl = authorities[0].crl.clone().unwrap();
    assert_eq!(crl.next_update - crl.this_update, 14 * 86_400);
}

#[test]
fn a_ca_that_cannot_renew_its_crl_is_warned_about() {
    let mut world = World::new();
    world.maintain(NOW);
    // Without its key, as with a sealed one, pkid can't renew the CRL, so
    // it warns from 30 days before expiry: here, at once.
    world.state.keys.clear();
    world.maintain(NOW + time::Duration::days(5));
    world.maintain(NOW + time::Duration::days(5) + time::Duration::hours(1));
    let warnings: Vec<_> = world
        .audit
        .0
        .borrow()
        .iter()
        .filter(|event| matches!(event, Event::CrlExpiring { .. }))
        .cloned()
        .collect();
    // Once a day at most.
    assert_eq!(warnings.len(), 1, "{warnings:?}");
}

#[test]
fn principal_domains_are_read_and_checked() {
    let key = PrivateKey::generate(KeyAlgorithm::EcdsaP256).unwrap();
    let mut snapshot = snapshot(&ca_certificate(&key));
    snapshot.settings.insert(
        "PrincipalDomains",
        RegData::MultiSz(vec!["Home".into(), "lab.home".into()]),
    );
    let loaded = load(&snapshot, &defaults()).unwrap();
    let domains: Vec<&str> = loaded
        .configuration
        .names
        .principal_domains
        .iter()
        .map(|domain| domain.as_str())
        .collect();
    assert_eq!(domains, ["home", "lab.home"]);
    for bad in ["*.home", "not a domain"] {
        snapshot
            .settings
            .insert("PrincipalDomains", RegData::MultiSz(vec![bad.into()]));
        assert!(load(&snapshot, &defaults()).is_err(), "{bad}");
    }
}
