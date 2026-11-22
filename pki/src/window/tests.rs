//! The window's pages, in each state of authority the window has to show
//! well: built from what `look` would have read, without pkid.
//!
//! With PKI_PREVIEW set to a directory holding Fenestra's tokens.css, every
//! page is also written there as a static HTML file with the theme, to look
//! at in a browser.

use std::collections::{BTreeMap, HashMap};
use std::sync::OnceLock;

use gxwi::{Facts, Fields, Live};
use peios::security::sddl;
use peios_crypto::{KeyAlgorithm, PrivateKey, Signer};
use pki_core::{
    create_root, AltName, CaProfile, CaSubject, CommonName, DnsName, ExtendedKeyUsage,
    ExtendedKeyUsages, IssuingCa, KeyUsage, LeafProfile, LeafSubject, SerialNumber,
    SubjectPublicKey, Validity,
};
use pki_management::Snapshot;
use pki_policy::{RegData, Values};
use pkid_core::{
    AuthorityInfo, CertificateInfo, CrlInfo, RequestInfo, RequestStatus, RevocationInfo,
    TemplateInfo,
};
use time::{Duration, OffsetDateTime};

use super::doing::Asking;
use super::held::Held;
use super::seen::{Change, May, Person, Pkid, Seen, Trouble};
use super::service::{Run, Service};
use super::{Listing, Page, Window};

const ALICE: &str = "S-1-5-21-1-2-3-1001";
const BOB: &str = "S-1-5-21-1-2-3-1002";
const ADMIN: &str = "S-1-5-21-1-2-3-500";
const SERVER: &str = "aaaaaaaa-0000-4000-8000-000000000001";
const DEVICE: &str = "aaaaaaaa-0000-4000-8000-000000000002";

fn sd(text: &str) -> Vec<u8> {
    sddl::parse(text).unwrap().as_bytes().to_vec()
}

fn at(time: OffsetDateTime) -> i64 {
    time.unix_timestamp()
}

/// A root, an issuing CA under it, and certificates the issuing CA issued.
struct Pki {
    root: Vec<u8>,
    issuing: Vec<u8>,
    certificates: Vec<CertificateInfo>,
}

fn pki() -> &'static Pki {
    static PKI: OnceLock<Pki> = OnceLock::new();
    PKI.get_or_init(|| {
        let now = OffsetDateTime::now_utc();
        let ca = |name: &str, from: OffsetDateTime, years: i64| CaProfile {
            subject: CaSubject {
                common_name: name.into(),
                attributes: Vec::new(),
            },
            validity: Validity::new(from, from + Duration::days(365 * years)).unwrap(),
            path_length: Some(0),
            name_constraints: None,
            extended_key_usages: None,
            crl_distribution_points: Vec::new(),
        };
        let root_key = PrivateKey::generate(KeyAlgorithm::EcdsaP384).unwrap();
        let start = now - Duration::days(400);
        let mut root_profile = ca("Lab Root", start, 20);
        root_profile.path_length = Some(1);
        let root = create_root(&root_key, &root_profile, &SerialNumber::random().unwrap())
            .unwrap()
            .der()
            .to_vec();
        let issuing_key = PrivateKey::generate(KeyAlgorithm::EcdsaP256).unwrap();
        let issuing = IssuingCa::new(&root, &root_key)
            .unwrap()
            .issue_ca(
                &SubjectPublicKey::from_der(issuing_key.public_key().spki()).unwrap(),
                &ca("Lab Issuing", start, 5),
                &SerialNumber::random().unwrap(),
            )
            .unwrap()
            .der()
            .to_vec();
        let signer = IssuingCa::new(&issuing, &issuing_key).unwrap();
        let leaf =
            |request: i64, names: &[&str], from: OffsetDateTime, days: i64, owner: Option<&str>| {
                let key = PrivateKey::generate(KeyAlgorithm::EcdsaP256).unwrap();
                let alt_names: Vec<AltName> = names
                    .iter()
                    .map(|name| AltName::Dns(DnsName::new(name).unwrap()))
                    .collect();
                let profile = LeafProfile {
                    subject: LeafSubject {
                        common_name: alt_names.first().cloned().map(CommonName::Name),
                        attributes: Vec::new(),
                    },
                    alt_names,
                    key_usages: vec![KeyUsage::DigitalSignature],
                    extended_key_usages: ExtendedKeyUsages::new(vec![ExtendedKeyUsage::ServerAuth])
                        .unwrap(),
                    validity: Validity::new(from, from + Duration::days(days)).unwrap(),
                    owner_sid: None,
                    crl_distribution_points: Vec::new(),
                };
                let serial = SerialNumber::random().unwrap();
                let certificate = signer
                    .issue(
                        &SubjectPublicKey::from_der(key.public_key().spki()).unwrap(),
                        &profile,
                        &serial,
                    )
                    .unwrap();
                CertificateInfo {
                    serial: serial.as_bytes().to_vec(),
                    request,
                    der: certificate.der().to_vec(),
                    not_before: at(from),
                    not_after: at(from + Duration::days(days)),
                    owner: owner.map(str::to_owned),
                    revocation: None,
                }
            };
        let mut certificates = vec![
            leaf(
                1,
                &["radius.lab.home"],
                now - Duration::days(200),
                365,
                None,
            ),
            leaf(
                2,
                &["www.lab.home", "lab.home"],
                now - Duration::days(355),
                365,
                None,
            ),
            leaf(
                3,
                &["printer.lab.home"],
                now - Duration::days(290),
                90,
                None,
            ),
            leaf(
                4,
                &["nas.lab.home"],
                now - Duration::days(30),
                365,
                Some(BOB),
            ),
        ];
        certificates[3].revocation = Some(RevocationInfo {
            revoked: at(now - Duration::days(2)),
            reason: 1,
            revoker: ADMIN.into(),
        });
        Pki {
            root,
            issuing,
            certificates,
        }
    })
}

fn now() -> i64 {
    super::words::now()
}

fn authority(id: &str, name: &str, certificate: &[u8], key: &str, granted: u32) -> AuthorityInfo {
    let sealed = key.starts_with("file:");
    AuthorityInfo {
        id: id.into(),
        name: name.into(),
        certificate: Some(certificate.to_vec()),
        request: None,
        key: key.into(),
        granted,
        security: sd("O:SYG:SYD:(A;;0x2;;;AU)(A;;0xf;;;BA)(A;;0xf;;;SY)"),
        templates: if sealed {
            Vec::new()
        } else {
            vec![
                TemplateInfo {
                    id: SERVER.into(),
                    name: "Server".into(),
                    enroll: true,
                },
                TemplateInfo {
                    id: DEVICE.into(),
                    name: "Device".into(),
                    enroll: granted & 0x8 != 0,
                },
            ]
        },
        key_available: !sealed,
        crl_lifetime_days: if sealed { 180 } else { 7 },
        crl: Some(if sealed {
            CrlInfo {
                number: 3,
                this_update: now() - 160 * 86_400,
                next_update: now() + 20 * 86_400,
            }
        } else {
            CrlInfo {
                number: 41,
                this_update: now() - 2 * 86_400,
                next_update: now() + 5 * 86_400,
            }
        }),
    }
}

fn template(name: &str, purposes: &[&str], approval: bool, enroll: &str) -> Values {
    let mut values = Values::new();
    let multi = |items: &[&str]| RegData::MultiSz(items.iter().map(|s| s.to_string()).collect());
    values.insert("Name", RegData::Sz(name.into()));
    values.insert("Purposes", multi(purposes));
    values.insert(
        "KeyUsages",
        multi(&["digital-signature", "key-encipherment"]),
    );
    values.insert("LifetimeDays", RegData::Dword(365));
    values.insert("RenewalWindowDays", RegData::Dword(30));
    values.insert("KeyAlgorithms", multi(&["ecdsa-p256", "rsa-2048"]));
    values.insert("NameTypes", multi(&["dns"]));
    values.insert(
        "Issuance",
        RegData::Sz(if approval { "approval" } else { "immediate" }.into()),
    );
    values.insert("EnrollSecurity", RegData::Binary(sd(enroll)));
    values
}

fn node(security: Option<&str>, owner: Option<&str>) -> Values {
    let mut values = Values::new();
    if let Some(security) = security {
        values.insert("RequestSecurity", RegData::Binary(sd(security)));
    }
    if let Some(owner) = owner {
        values.insert("Owner", RegData::Sz(owner.into()));
    }
    values
}

fn config() -> Snapshot {
    let mut settings = Values::new();
    settings.insert("PrincipalDomains", RegData::MultiSz(vec!["home".into()]));
    let mut issuing = Values::new();
    issuing.insert(
        "CrlDistributionPoints",
        RegData::MultiSz(vec!["http://ca.lab.home/crl/issuing.crl".into()]),
    );
    Snapshot {
        settings,
        templates: vec![
            (
                SERVER.into(),
                template(
                    "Server",
                    &["server-auth"],
                    false,
                    "O:SYG:SYD:(A;;0x1;;;AU)(A;;0x3;;;BA)(A;;0x3;;;SY)",
                ),
            ),
            (
                DEVICE.into(),
                template(
                    "Device",
                    &["client-auth"],
                    true,
                    "O:SYG:SYD:(A;;0x3;;;BA)(A;;0x3;;;SY)",
                ),
            ),
        ],
        dns: vec![
            (
                Vec::new(),
                node(Some(pki_policy::DEFAULT_NAME_ROOT_SDDL), None),
            ),
            (vec!["home".into()], node(None, None)),
            (
                vec!["home".into(), "lab".into()],
                node(
                    Some("O:SYG:SYD:(A;CI;0x1;;;PS)(A;CI;0x7;;;BA)(A;CI;0x7;;;SY)(A;CI;0x1;;;AU)"),
                    None,
                ),
            ),
            (
                vec!["home".into(), "lab".into(), "radius".into()],
                node(None, Some(BOB)),
            ),
        ],
        principals: vec![
            (
                Vec::new(),
                node(Some(pki_policy::DEFAULT_NAME_ROOT_SDDL), None),
            ),
            (vec!["home".into()], node(None, None)),
        ],
        authorities: vec![("issuing".into(), issuing)],
    }
}

fn may(all: bool) -> May {
    let change = Change {
        edit: all,
        delete: all,
        add: all,
    };
    let mut names = BTreeMap::new();
    for key in [
        "Machine\\Software\\Pki\\Names\\Dns",
        "Machine\\Software\\Pki\\Names\\Dns\\home",
        "Machine\\Software\\Pki\\Names\\Dns\\home\\lab",
        "Machine\\Software\\Pki\\Names\\Dns\\home\\lab\\radius",
        "Machine\\Software\\Pki\\Names\\Principals",
        "Machine\\Software\\Pki\\Names\\Principals\\home",
    ] {
        names.insert(key.to_string(), change);
    }
    May {
        setup: all,
        settings: all,
        http: all,
        add_template: all,
        templates: [(SERVER.to_string(), change), (DEVICE.to_string(), change)].into(),
        names,
    }
}

fn request(
    id: i64,
    names: &[&str],
    requester: &str,
    status: RequestStatus,
    days_ago: i64,
) -> RequestInfo {
    RequestInfo {
        id,
        template: SERVER.into(),
        names: names.iter().map(|s| s.to_string()).collect(),
        requester: requester.into(),
        submitted: now() - days_ago * 86_400,
        status,
        reasons: if status == RequestStatus::Pending {
            vec!["lab.home requires approval for this requester".into()]
        } else {
            Vec::new()
        },
        decided: (status != RequestStatus::Pending).then(|| now() - days_ago * 86_400 + 3_600),
        decider: (status != RequestStatus::Pending).then(|| ADMIN.into()),
    }
}

fn requests() -> Vec<RequestInfo> {
    vec![
        request(7, &["camera.lab.home"], ALICE, RequestStatus::Pending, 0),
        request(6, &["alice.lab.home"], ADMIN, RequestStatus::Pending, 1),
        request(5, &["laptop.lab.home"], BOB, RequestStatus::Denied, 3),
        request(4, &["nas.lab.home"], BOB, RequestStatus::Issued, 30),
        request(3, &["printer.lab.home"], ADMIN, RequestStatus::Issued, 290),
        request(
            2,
            &["www.lab.home", "lab.home"],
            ADMIN,
            RequestStatus::Issued,
            355,
        ),
        request(1, &["radius.lab.home"], ADMIN, RequestStatus::Issued, 200),
    ]
}

fn running() -> Service {
    Service::Known {
        state: Run::Running,
        granted: vec!["query_status".into(), "start".into(), "stop".into()],
    }
}

/// What an administrator sees: every right everywhere.
fn admin() -> Window {
    let pki = pki();
    let seen = Seen {
        pkid: Ok(Pkid {
            authorities: vec![
                authority(
                    "root",
                    "Lab Root",
                    &pki.root,
                    "file:/media/root/lab-root.key",
                    0xf,
                ),
                authority(
                    "issuing",
                    "Lab Issuing",
                    &pki.issuing,
                    "service:issuing",
                    0xf,
                ),
            ],
            create: true,
        }),
        config: Ok(config()),
        set_up: true,
        may: may(true),
        pkid_service: running(),
        httpd_service: running(),
        waiting: [(
            "issuing".to_string(),
            requests().into_iter().filter(super::waiting).collect(),
        )]
        .into(),
        http_port: Some(80),
        held: Vec::new(),
        ready: Vec::new(),
    };
    let mut window = Window::new(seen, Some(ADMIN.into()));
    window.people = HashMap::from([
        (
            ALICE.to_string(),
            Person {
                account: "home\\alice".into(),
                display: Some("Alice Liddell".into()),
            },
        ),
        (
            BOB.to_string(),
            Person {
                account: "home\\bob".into(),
                display: Some("Bob Marley".into()),
            },
        ),
        (
            ADMIN.to_string(),
            Person {
                account: "home\\admin".into(),
                display: Some("Ada Admin".into()),
            },
        ),
    ]);
    window.listing = Listing {
        ca: "issuing".into(),
        requests: Some(Ok(requests())),
        certificates: Some(Ok(pki.certificates.clone())),
    };
    window
}

/// What Alice sees: she may request at the issuing CA, and nothing else.
fn alice() -> Window {
    let mut window = admin();
    window.me = Some(ALICE.into());
    let pkid = window.seen.pkid.as_mut().unwrap();
    pkid.create = false;
    pkid.authorities.retain(|a| a.id == "issuing");
    pkid.authorities[0].granted = 0x2;
    pkid.authorities[0].templates[1].enroll = false;
    window.seen.may = may(false);
    window.seen.pkid_service = Service::Known {
        state: Run::Running,
        granted: vec!["query_status".into()],
    };
    window.seen.httpd_service = window.seen.pkid_service.clone();
    let mine = |r: &RequestInfo| r.requester == ALICE;
    window.seen.waiting.get_mut("issuing").unwrap().retain(mine);
    window.listing.requests = Some(Ok(requests().into_iter().filter(mine).collect()));
    window.listing.certificates = Some(Ok(Vec::new()));
    window
}

/// An officer who may approve and revoke, but not manage.
fn officer() -> Window {
    let mut window = admin();
    for authority in &mut window.seen.pkid.as_mut().unwrap().authorities {
        authority.granted = 0x7;
    }
    window.seen.pkid.as_mut().unwrap().create = false;
    window.seen.may = may(false);
    window
}

/// A page as opening it leaves its fields, then with `set` typed.
fn filled(
    window: Window,
    name: &'static str,
    set: &[(&str, &str)],
) -> (&'static str, Window, Fields) {
    let mut fields = Fields::default();
    window.fill(&mut fields);
    for (field, value) in set {
        fields.set(field, value);
    }
    if set.iter().any(|(field, _)| *field == "new-kind") {
        super::manage::fill_new(&mut fields);
    }
    (name, window, fields)
}

fn asking(mut window: Window, question: Asking) -> Window {
    window.asking = Some(question);
    window
}

/// Alice, with a request she made in the window held, then issued.
fn ready(mut window: Window) -> Window {
    let held = Held {
        ca: "issuing".into(),
        request: 9,
        out: "/home/alice/camera.p12".into(),
        key: "/home/alice/camera.p12.key".into(),
    };
    window.seen.held = vec![held.clone()];
    window.seen.ready = vec![(held, "camera.lab.home".into())];
    let mut issued = request(9, &["camera.lab.home"], ALICE, RequestStatus::Issued, 1);
    issued.reasons.clear();
    if let Some(Ok(requests)) = &mut window.listing.requests {
        requests.insert(0, issued);
    }
    window
}

fn render(window: &Window, fields: &Fields) -> String {
    window.render(&Facts { views: 1, fields })
}

fn at_page(mut window: Window, page: Page) -> Window {
    window.page = page;
    window
}

/// Every page and state worth looking at, by file name.
fn pages() -> Vec<(&'static str, Window, Fields)> {
    let none = Fields::default;
    let mut down = admin();
    down.seen.pkid = Err(Trouble::Down);
    down.seen.pkid_service = Service::Known {
        state: Run::Stopped,
        granted: vec!["query_status".into(), "start".into(), "stop".into()],
    };
    let mut invalid = admin();
    invalid.seen.pkid = Err(Trouble::Invalid(
        "Templates\\aaaaaaaa-0000-4000-8000-000000000001: LifetimeDays must be 1 to 7305".into(),
    ));
    let mut unset = admin();
    unset.seen.set_up = false;
    unset.seen.pkid = Err(Trouble::Down);
    let mut unset_user = alice();
    unset_user.seen.set_up = false;
    unset_user.seen.may.setup = false;
    unset_user.seen.pkid = Err(Trouble::Down);
    let mut awaiting = admin();
    {
        let authorities = &mut awaiting.seen.pkid.as_mut().unwrap().authorities;
        authorities[1].certificate = None;
        authorities[1].request = Some(vec![0x30]);
        authorities[1].crl = None;
    }
    let mut empty = alice();
    empty.seen.pkid.as_mut().unwrap().authorities.clear();
    let mut enrol_fields = Fields::default();
    enrol_fields.set("enrol-dns", "camera.lab.home");
    let mut own = Fields::default();
    own.set("enrol-key", "own");
    let mut all_certificates = Fields::default();
    all_certificates.set("show-certificates", "all");
    let mut all_requests = Fields::default();
    all_requests.set("show", "all");
    let serial = |index: usize| pki().certificates[index].serial.clone();
    let mut pages = vec![
        ("overview", admin(), none()),
        ("overview-officer", officer(), none()),
        ("overview-alice", alice(), none()),
        ("overview-down", down, none()),
        ("overview-invalid", invalid, none()),
        ("setup", unset, none()),
        ("setup-user", unset_user, none()),
        ("overview-no-authorities", empty, none()),
        ("requests", at_page(admin(), Page::Requests), none()),
        (
            "requests-all",
            at_page(admin(), Page::Requests),
            all_requests,
        ),
        ("requests-alice", at_page(alice(), Page::Requests), none()),
        (
            "request-waiting",
            at_page(
                admin(),
                Page::Request {
                    ca: "issuing".into(),
                    id: 7,
                },
            ),
            none(),
        ),
        (
            "request-own",
            at_page(
                admin(),
                Page::Request {
                    ca: "issuing".into(),
                    id: 6,
                },
            ),
            none(),
        ),
        (
            "request-alice",
            at_page(
                alice(),
                Page::Request {
                    ca: "issuing".into(),
                    id: 7,
                },
            ),
            none(),
        ),
        (
            "request-issued",
            at_page(
                admin(),
                Page::Request {
                    ca: "issuing".into(),
                    id: 4,
                },
            ),
            none(),
        ),
        (
            "certificates",
            at_page(admin(), Page::Certificates),
            all_certificates,
        ),
        (
            "certificates-alice",
            at_page(alice(), Page::Certificates),
            none(),
        ),
        (
            "certificate",
            at_page(
                admin(),
                Page::Certificate {
                    ca: "issuing".into(),
                    serial: serial(0),
                },
            ),
            none(),
        ),
        (
            "certificate-revoked",
            at_page(
                admin(),
                Page::Certificate {
                    ca: "issuing".into(),
                    serial: serial(3),
                },
            ),
            none(),
        ),
        filled(
            at_page(admin(), Page::Authority("root".into())),
            "authority-root",
            &[],
        ),
        filled(
            at_page(admin(), Page::Authority("issuing".into())),
            "authority-issuing",
            &[],
        ),
        (
            "authority-officer",
            at_page(officer(), Page::Authority("issuing".into())),
            none(),
        ),
        (
            "authority-alice",
            at_page(alice(), Page::Authority("issuing".into())),
            none(),
        ),
        (
            "authority-awaiting",
            at_page(awaiting, Page::Authority("issuing".into())),
            none(),
        ),
        ("enrol", at_page(alice(), Page::Enrol), enrol_fields),
        ("enrol-own", at_page(alice(), Page::Enrol), own),
        (
            "request-deny",
            asking(
                at_page(
                    admin(),
                    Page::Request {
                        ca: "issuing".into(),
                        id: 7,
                    },
                ),
                Asking::Deny {
                    ca: "issuing".into(),
                    id: 7,
                },
            ),
            none(),
        ),
        (
            "certificate-revoke",
            asking(
                at_page(
                    admin(),
                    Page::Certificate {
                        ca: "issuing".into(),
                        serial: serial(0),
                    },
                ),
                Asking::Revoke {
                    ca: "issuing".into(),
                    serial: crate::show::hex(&serial(0)),
                },
            ),
            none(),
        ),
        (
            "authority-publish",
            asking(
                at_page(admin(), Page::Authority("root".into())),
                Asking::Publish { ca: "root".into() },
            ),
            none(),
        ),
        ("overview-ready", ready(alice()), none()),
        (
            "request-ready",
            asking(
                at_page(
                    ready(alice()),
                    Page::Request {
                        ca: "issuing".into(),
                        id: 9,
                    },
                ),
                Asking::Collect {
                    ca: "issuing".into(),
                    id: 9,
                },
            ),
            none(),
        ),
        filled(
            at_page(admin(), Page::Template(SERVER.into())),
            "template-edit",
            &[],
        ),
        filled(
            asking(at_page(admin(), Page::Templates), Asking::NewTemplate),
            "template-new",
            &[],
        ),
        filled(
            asking(
                at_page(admin(), Page::Template(DEVICE.into())),
                Asking::DeleteTemplate { id: DEVICE.into() },
            ),
            "template-delete",
            &[],
        ),
        filled(
            asking(at_page(admin(), Page::Names), Asking::AddName),
            "names-add",
            &[],
        ),
        filled(
            asking(
                at_page(admin(), Page::Name("radius.lab.home".into())),
                Asking::Owner {
                    name: "radius.lab.home".into(),
                },
            ),
            "name-owner",
            &[],
        ),
        filled(
            asking(
                at_page(admin(), Page::Name("lab.home".into())),
                Asking::Inherit {
                    name: "lab.home".into(),
                },
            ),
            "name-inherit",
            &[],
        ),
        filled(at_page(admin(), Page::NewAuthority), "new-authority", &[]),
        filled(
            at_page(admin(), Page::NewAuthority),
            "new-authority-under",
            &[("new-kind", "under"), ("new-keep", "file")],
        ),
        filled(
            at_page(admin(), Page::NewAuthority),
            "new-authority-import",
            &[("new-kind", "import")],
        ),
        filled(
            at_page(officer(), Page::NewAuthority),
            "new-authority-refused",
            &[],
        ),
        filled(at_page(admin(), Page::Sign("root".into())), "sign", &[]),
        filled(
            at_page(admin(), Page::ExportKey("issuing".into())),
            "export-key",
            &[],
        ),
        ("templates", at_page(admin(), Page::Templates), none()),
        ("templates-alice", at_page(alice(), Page::Templates), none()),
        (
            "template",
            at_page(admin(), Page::Template(SERVER.into())),
            none(),
        ),
        ("names", at_page(admin(), Page::Names), none()),
        ("names-alice", at_page(alice(), Page::Names), none()),
        (
            "name-broad",
            at_page(admin(), Page::Name("lab.home".into())),
            none(),
        ),
        (
            "name-owned",
            at_page(alice(), Page::Name("radius.lab.home".into())),
            none(),
        ),
    ];
    // The fields the window keeps in step with a page, as opening it would.
    for (_, window, fields) in &mut pages {
        window.sync(fields);
    }
    pages
}

#[test]
fn every_page_renders() {
    for (name, window, fields) in pages() {
        let html = render(&window, &fields);
        assert!(html.contains("st-page"), "{name}");
    }
}

#[test]
fn what_alice_may_not_do_is_not_offered() {
    let page = |page: Page| render(&at_page(alice(), page), &Fields::default());
    let overview = page(Page::Overview);
    assert!(!overview.contains("Lab Root"), "pkid hid the root from her");
    assert!(overview.contains("aren't listed"));
    assert!(
        !overview.contains(r#"fx-click="service""#),
        "she may not stop services"
    );
    let requests = page(Page::Requests);
    assert!(requests.contains("Showing only your own requests"));
    assert!(!requests.contains(r#"fx-click="approve""#));
    let authority = page(Page::Authority("issuing".into()));
    assert!(authority.contains("Your Access"));
    assert!(authority.contains("Changing this needs Manage CA permission"));
    assert!(!authority.contains("Export Key"));
    assert!(!authority.contains(r#"fx-click="publish""#));
    assert!(page(Page::Templates).contains("you don't have permission to change templates"));
    let enrol = page(Page::Enrol);
    assert!(
        enrol.contains("Server") && !enrol.contains(">Device<"),
        "only templates she may enrol in"
    );
}

#[test]
fn only_authorities_with_a_template_to_request_from_are_offered() {
    let mut window = at_page(admin(), Page::Enrol);
    let page = render(&window, &Fields::default());
    assert!(
        !page.contains(r#"<option value="root">"#),
        "the root takes no requests"
    );
    assert!(page.contains("Lab Issuing") || page.contains(r#"name="enrol-template""#));
    for authority in &mut window.seen.pkid.as_mut().unwrap().authorities {
        for template in &mut authority.templates {
            template.enroll = false;
        }
    }
    let page = render(&window, &Fields::default());
    assert!(page.contains("No authority offers a template you have permission"));
    assert!(!render(&at_page(window, Page::Overview), &Fields::default()).contains("st-nav-enrol"));
}

#[test]
fn an_officer_cannot_approve_their_own_request() {
    let own = render(
        &at_page(
            admin(),
            Page::Request {
                ca: "issuing".into(),
                id: 6,
            },
        ),
        &Fields::default(),
    );
    assert!(own.contains("can't approve or deny your own request"));
    assert!(own.contains(r#"fx-click="approve" fx-value-ca="issuing" fx-value-id="6" disabled"#));
    let queue = render(&at_page(admin(), Page::Requests), &Fields::default());
    assert!(queue.contains(r#"fx-click="approve" fx-value-ca="issuing" fx-value-id="7""#));
    assert!(!queue.contains(r#"fx-click="approve" fx-value-ca="issuing" fx-value-id="6""#));
}

#[test]
fn trouble_is_said_where_it_matters() {
    for (name, window, fields) in pages() {
        let html = render(&window, &fields);
        match name {
            "overview-down" => assert!(html.contains("Not Running")),
            "overview-invalid" => {
                assert!(html.contains("LifetimeDays must be 1 to 7305"));
                assert!(html.contains("The Server template is invalid"));
                assert!(html.contains(&format!(r#"fx-click="template" fx-value-id="{SERVER}""#)));
            }
            "overview-alice" => {
                assert!(!html.contains("without approval"), "she can't change it");
                assert!(!html.contains("http-port-save"));
                assert!(html.contains("Who Can Add Authorities") && html.contains("View…"));
            }
            "overview" => {
                assert!(html.contains("Authenticated Users may request lab.home without approval"));
                assert!(html.contains("http-port-save"));
                assert!(html.contains("Administrators and SYSTEM"));
            }
            "setup" => assert!(
                html.contains(r#"fx-click="setup""#)
                    && !html.contains(r#"fx-click="setup" disabled"#)
            ),
            "setup-user" => assert!(
                html.contains("Ask an administrator to set it up")
                    && html.contains(r#"fx-click="setup" disabled"#)
            ),
            "overview-no-authorities" => {
                assert!(html.contains("no authorities you have access to"))
            }
            "name-broad" => assert!(html.contains("without approval")),
            "request-ready" => {
                assert!(html.contains(r#"name="passphrase""#));
                assert!(html.contains("collect-confirm"));
            }
            "template-edit" => assert!(html.contains(r#"fx-submit="template-save""#)),
            "templates-alice" => assert!(!html.contains("new-template")),
            "names-alice" => assert!(!html.contains("add-name") && !html.contains("domains-save")),
            "name-owner" => assert!(html.contains("owner-confirm") && html.contains("owner-none")),
            "new-authority-refused" => assert!(html.contains("permission to add authorities")),
            "new-authority-under" => {
                assert!(html.contains("new-issuer") && html.contains("new-key-file"))
            }
            "authority-issuing" => assert!(html.contains(r#"fx-submit="issuing""#)),
            "authority-officer" => assert!(!html.contains(r#"fx-submit="issuing""#)),
            "overview-ready" => {
                assert!(html.contains("Your certificate for camera.lab.home is ready"))
            }
            "certificate-revoke" => {
                assert!(html.contains("revoke-confirm") && html.contains("Key Compromise"))
            }
            _ => {}
        }
    }
}

/// `html` with the values `fields` holds put into its inputs, selects and
/// switches, as the live page shows them; static HTML has no fields.
fn with_fields(html: &str, fields: &Fields) -> String {
    let mut out = String::new();
    let mut rest = html;
    while let Some(start) = rest.find('<') {
        out.push_str(&rest[..start]);
        rest = &rest[start..];
        let end = rest.find('>').map_or(rest.len(), |at| at + 1);
        let tag = &rest[..end];
        let name = tag
            .split_once(" name=\"")
            .and_then(|(_, after)| after.split_once('"'))
            .map(|(name, _)| name.to_owned());
        match name {
            Some(name) if tag.starts_with("<input") => {
                let value = fields.get(&name);
                let open = &tag[..tag.len() - 1];
                if tag.contains("type=\"checkbox\"") {
                    out.push_str(open);
                    if value == "on" {
                        out.push_str(" checked");
                    }
                    out.push('>');
                } else {
                    out.push_str(&format!("{open} value=\"{}\">", gxwi::escape(value)));
                }
                rest = &rest[end..];
            }
            Some(name) if tag.starts_with("<select") => {
                let close = rest.find("</select>").map_or(rest.len(), |at| at + 9);
                let chosen = format!("<option value=\"{}\"", gxwi::escape(fields.get(&name)));
                out.push_str(&rest[..close].replacen(&chosen, &format!("{chosen} selected"), 1));
                rest = &rest[close..];
            }
            _ => {
                out.push_str(tag);
                rest = &rest[end..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// With PKI_PREVIEW set, write each page with the theme for a browser.
#[test]
fn previews() {
    let Some(dir) = std::env::var_os("PKI_PREVIEW") else {
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    let tokens = std::fs::read_to_string(dir.join("tokens.css")).unwrap_or_default();
    for (name, window, fields) in pages() {
        let html = format!(
            "<!doctype html><html><head><meta charset=utf-8><style>{tokens}\n{}\n{}\nbody{{margin:0;background:var(--bg-base);color:var(--text-body);font-family:system-ui,sans-serif;height:100vh}}</style></head><body>{}</body></html>",
            gxwi::settings::STYLE,
            include_str!("window.css"),
            with_fields(&render(&window, &fields), &fields)
        );
        std::fs::write(dir.join(format!("{name}.html")), html).unwrap();
    }
}

#[test]
fn sentences_read_as_sentences() {
    use super::service::sentence;
    assert_eq!(sentence("access denied"), "Access denied.");
    assert_eq!(
        sentence("lab.home may not be requested"),
        "lab.home may not be requested."
    );
    assert_eq!(
        sentence("configuration: access check failed: Function not implemented (os error 38)"),
        "Configuration: access check failed: Function not implemented."
    );
}
