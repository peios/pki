//! pki's parsing, help and commands, against a stand-in for pkid.

use std::cell::RefCell;
use std::ffi::OsString;
use std::io;
use std::path::PathBuf;

use pki_management::provision::Seeded;
use pki_management::Snapshot;
use pki_policy::{RegData, SecurityBlob, Values};
use pkid_client::ClientError;
use pkid_core::{
    AuthorityInfo, ErrorCode, Issuer, KeySpec, Reply, Request, TemplateInfo, WireError,
};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::failure::Kind;
use crate::host::Host;
use crate::{cli, parse, run, Stop};

const PASSPHRASE: &str = "correct horse battery staple";

/// Answers pkid requests for a test.
type Responder = Box<dyn Fn(&Request) -> Reply>;

/// pkid, the Registry and the terminal, as a test sets them up.
#[derive(Default)]
struct Fake {
    authorities: Vec<AuthorityInfo>,
    snapshot: Snapshot,
    /// Each Registry change, in order.
    writes: RefCell<Vec<Write>>,
    warnings: RefCell<Vec<String>>,
    /// Answers requests in place of `reply`, for as many as come.
    respond: Option<Responder>,
    /// What pkid replies to anything but a listing.
    reply: RefCell<Option<Result<Reply, ClientError>>>,
    /// The answers to prompts, in order.
    answers: RefCell<Vec<&'static str>>,
    prompts: RefCell<Vec<String>>,
    sent: RefCell<Vec<Request>>,
}

impl Fake {
    fn replying(self, reply: Reply) -> Self {
        *self.reply.borrow_mut() = Some(Ok(reply));
        self
    }

    fn answering(self, answers: &[&'static str]) -> Self {
        *self.answers.borrow_mut() = answers.to_vec();
        self
    }

    /// The one request that wasn't a listing.
    fn sent(&self) -> Request {
        let sent: Vec<Request> = self
            .sent
            .borrow()
            .iter()
            .filter(|request| !matches!(request, Request::Authorities))
            .cloned()
            .collect();
        assert_eq!(sent.len(), 1, "{sent:?}");
        sent.into_iter().next().unwrap()
    }
}

impl Host for Fake {
    fn call(&self, request: &Request) -> Result<Reply, ClientError> {
        self.sent.borrow_mut().push(request.clone());
        if let Request::Authorities = request {
            return Ok(Reply::Authorities(self.authorities.clone()));
        }
        if let Some(respond) = &self.respond {
            return Ok(respond(request));
        }
        self.reply
            .borrow_mut()
            .take()
            .expect("the test says what pkid replies")
    }

    fn setup(&self) -> io::Result<Seeded> {
        Err(io::Error::from(io::ErrorKind::PermissionDenied))
    }

    fn prompt(&self, question: &str) -> io::Result<Zeroizing<String>> {
        self.prompts.borrow_mut().push(question.to_owned());
        let mut answers = self.answers.borrow_mut();
        if answers.is_empty() {
            return Err(io::Error::new(io::ErrorKind::NotFound, "no terminal"));
        }
        Ok(Zeroizing::new(answers.remove(0).to_owned()))
    }

    fn snapshot(&self) -> io::Result<Snapshot> {
        Ok(self.snapshot.clone())
    }

    fn change(&self, path: &str, set: &Values, remove: &[&str]) -> io::Result<()> {
        self.writes.borrow_mut().push(Write::Change(
            path.into(),
            set.clone(),
            remove.iter().map(|r| r.to_string()).collect(),
        ));
        Ok(())
    }

    fn put(&self, path: &str, set: &Values, remove: &[&str]) -> io::Result<()> {
        self.writes.borrow_mut().push(Write::Put(
            path.into(),
            set.clone(),
            remove.iter().map(|r| r.to_string()).collect(),
        ));
        Ok(())
    }

    fn create(&self, path: &str, set: &Values) -> io::Result<()> {
        self.writes
            .borrow_mut()
            .push(Write::Create(path.into(), set.clone()));
        Ok(())
    }

    fn delete(&self, path: &str) -> io::Result<()> {
        self.writes.borrow_mut().push(Write::Delete(path.into()));
        Ok(())
    }

    fn new_guid(&self) -> io::Result<String> {
        Ok("bbbbbbbb-0000-4000-8000-000000000009".into())
    }

    fn warn(&self, warning: &str) {
        self.warnings.borrow_mut().push(warning.to_owned());
    }
}

/// A Registry change a command made.
#[derive(Debug, Clone, PartialEq)]
enum Write {
    Change(String, Values, Vec<String>),
    Put(String, Values, Vec<String>),
    Create(String, Values),
    Delete(String),
}

fn binary_sd(text: &str) -> SecurityBlob {
    SecurityBlob::new(
        peios::security::sddl::parse(text)
            .unwrap()
            .as_bytes()
            .to_vec(),
    )
}

/// The configuration `pki setup` seeds, with the Issuing CA issuing from
/// Server, and a few names.
fn seeded() -> Snapshot {
    let enroll = binary_sd(pki_policy::DEFAULT_TEMPLATE_ENROLL_SDDL);
    let root = pki_policy::defaults::name_root(&binary_sd(pki_policy::DEFAULT_NAME_ROOT_SDDL));
    let mut issuing = Values::new();
    issuing.insert("Name", RegData::Sz("Issuing".into()));
    issuing.insert(
        "Templates",
        RegData::MultiSz(vec!["aaaaaaaa-0000-4000-8000-000000000001".into()]),
    );
    let mut lab = Values::new();
    lab.insert("Owner", RegData::Sz("S-1-5-21-1-2-3-1001".into()));
    Snapshot {
        settings: Values::new(),
        templates: vec![
            (
                "aaaaaaaa-0000-4000-8000-000000000001".into(),
                pki_policy::defaults::server_template(&enroll),
            ),
            (
                "aaaaaaaa-0000-4000-8000-000000000002".into(),
                pki_policy::defaults::device_template(&enroll),
            ),
        ],
        dns: vec![
            (Vec::new(), root.clone()),
            (vec!["home".into()], Values::new()),
            (vec!["home".into(), "lab".into()], lab),
        ],
        principals: vec![(Vec::new(), root)],
        authorities: vec![("22222222-2222-4222-8222-222222222222".into(), issuing)],
    }
}

fn authority(id: &str, name: &str, key: &str) -> AuthorityInfo {
    AuthorityInfo {
        id: id.into(),
        name: name.into(),
        certificate: Some(vec![0x30, 0x00]),
        request: None,
        key: key.into(),
        templates: vec![TemplateInfo {
            id: "t-server".into(),
            name: "Server".into(),
        }],
        key_available: !key.starts_with("file:"),
    }
}

fn fake() -> Fake {
    Fake {
        authorities: vec![
            authority(
                "11111111-1111-4111-8111-111111111111",
                "Root",
                "file:/media/root.key",
            ),
            authority(
                "22222222-2222-4222-8222-222222222222",
                "Issuing",
                "service:2222",
            ),
            authority(
                "33333333-3333-4333-8333-333333333333",
                "Twin",
                "service:3333",
            ),
            authority(
                "44444444-4444-4444-8444-444444444444",
                "twin",
                "service:4444",
            ),
        ],
        snapshot: seeded(),
        ..Fake::default()
    }
}

fn args(line: &str) -> Vec<OsString> {
    std::iter::once("pki")
        .chain(line.split_whitespace())
        .map(OsString::from)
        .collect()
}

fn usage_error(line: &str) -> String {
    match parse(&args(line)) {
        Err(Stop::Fail(failure)) => {
            assert_eq!(failure.kind, Kind::Usage, "{line}");
            failure.message
        }
        other => panic!("{line}: {other:?}"),
    }
}

fn printed(line: &str) -> (String, bool) {
    match parse(&args(line)) {
        Err(Stop::Print { text, error }) => (text, error),
        other => panic!("{line}: {other:?}"),
    }
}

fn running(host: &Fake, line: &str) -> Result<crate::show::Output, crate::failure::Failure> {
    let cli = parse(&args(line)).unwrap_or_else(|stop| panic!("{line}: {stop:?}"));
    run::run(host, cli.command)
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pki-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    let _ = std::fs::remove_file(&path);
    path
}

// Help and usage.

#[test]
fn the_command_tree_is_well_formed() {
    cli::command().debug_assert();
}

#[test]
fn help_follows_the_layout() {
    let (text, error) = printed("--help");
    assert!(!error);
    assert!(
        text.starts_with(
            "Manage the Peios certificate authority\n\nUsage: pki [options] <command>\n"
        ),
        "{text}"
    );
    assert!(text.contains("\nCommands:\n"), "{text}");
    assert!(text.contains("\nOptions:\n"), "{text}");
    assert!(text.contains("  -h, --help"), "{text}");
    assert!(text.contains("  -V, --version"), "{text}");
    assert!(text.ends_with("\nSee pki(8).\n"), "{text}");
}

#[test]
fn every_help_fits_80_columns_with_lowercase_placeholders() {
    fn walk(command: &clap::Command, path: Vec<String>) {
        let mut line = path.join(" ");
        line.push_str(" --help");
        let (text, _) = printed(&line);
        for row in text.lines() {
            assert!(row.chars().count() <= 80, "{line}: {row}");
        }
        assert!(!text.contains("[OPTIONS]"), "{line}");
        for (index, _) in text.match_indices('<') {
            let rest = &text[index + 1..];
            let name: String = rest.chars().take_while(|c| *c != '>').collect();
            assert_eq!(name, name.to_lowercase(), "{line}: <{name}>");
        }
        assert!(text.ends_with("See pki(8).\n"), "{line}");
        for sub in command.get_subcommands() {
            let mut path = path.clone();
            path.push(sub.get_name().to_owned());
            walk(sub, path);
        }
    }
    walk(&cli::command(), Vec::new());
}

#[test]
fn help_for_a_command_matches_its_help_option() {
    assert_eq!(printed("help ca create"), printed("ca create --help"));
    assert_eq!(printed("help"), printed("--help"));
    assert!(printed("help ca create").0.contains("Usage: pki ca create"));
    assert_eq!(usage_error("help nonsense"), "unknown command 'nonsense'");
}

#[test]
fn a_group_without_its_command_prints_help_to_stderr() {
    let (text, error) = printed("");
    assert!(error && text.contains("Usage: pki"), "{text}");
    let (text, error) = printed("ca");
    assert!(error && text.contains("Usage: pki ca"), "{text}");
}

#[test]
fn version_names_the_program() {
    let (text, error) = printed("-V");
    assert!(!error);
    assert_eq!(text, format!("pki {}\n", env!("CARGO_PKG_VERSION")));
}

#[test]
fn usage_errors_are_in_house_style() {
    assert_eq!(usage_error("--jsno"), "unknown option '--jsno'");
    assert_eq!(usage_error("stauts"), "unknown command 'stauts'");
    assert_eq!(usage_error("ca show"), "missing <ca>");
    assert_eq!(
        usage_error("ca create Root"),
        "missing --root, --issuer or --offline"
    );
    assert_eq!(
        usage_error("ca create Root --root --algorithm dsa"),
        "--algorithm <algorithm>: 'dsa' is not one of ecdsa-p256, ecdsa-p384, rsa-2048, rsa-3072, rsa-4096"
    );
    assert_eq!(
        usage_error("ca create Root --root --lifetime soon"),
        "--lifetime <days>: 'soon' is not valid"
    );
    assert!(usage_error("ca create Root --root --issuer Other").contains("cannot be used with"));
    assert!(usage_error("ca create Root --root --passphrase-file p").starts_with("missing "));
    assert!(
        usage_error("ca set Root --no-templates --template Server").contains("cannot be used with")
    );
    for message in [usage_error("--jsno"), usage_error("ca show")] {
        assert!(!message.starts_with("error"), "{message}");
        assert!(!message.ends_with('.'), "{message}");
    }
}

#[test]
fn json_is_accepted_anywhere() {
    assert!(parse(&args("-j ca list")).unwrap().json);
    assert!(parse(&args("ca list --json")).unwrap().json);
}

// Commands.

#[test]
fn cas_are_named_by_id_or_unique_name() {
    let host = fake().replying(Reply::Done);
    let output = running(&host, "ca show root").unwrap();
    assert_eq!(output.json["id"], "11111111-1111-4111-8111-111111111111");
    let output = running(&host, "ca show 22222222-2222-4222-8222-222222222222").unwrap();
    assert_eq!(output.json["name"], "Issuing");

    let failure = running(&host, "ca show twin").unwrap_err();
    assert_eq!(failure.kind, Kind::Usage);
    assert!(failure.hint.unwrap().contains("33333333"));
    let failure = running(&host, "ca show nobody").unwrap_err();
    assert_eq!(failure.kind, Kind::NotFound);
    assert_eq!(failure.message, "no CA 'nobody'");
}

#[test]
fn a_root_with_a_service_key() {
    let host = fake().replying(Reply::Authority(authority(
        "new",
        "Lab Root",
        "service:new",
    )));
    let output = running(
        &host,
        "ca create Lab --root --template server --crl http://crl/",
    )
    .unwrap();
    assert_eq!(output.json["created"]["id"], "new");
    let Request::CreateAuthority {
        name,
        key,
        issuer,
        lifetime_days,
        templates,
        crl_distribution_points,
        ..
    } = host.sent()
    else {
        panic!()
    };
    assert_eq!(name, "Lab");
    assert_eq!(issuer, Issuer::SelfSigned);
    assert_eq!(lifetime_days, cli::ROOT_LIFETIME_DAYS);
    assert_eq!(templates, ["aaaaaaaa-0000-4000-8000-000000000001"]);
    assert_eq!(crl_distribution_points, ["http://crl/"]);
    assert_eq!(
        key,
        KeySpec {
            provider: "service".into(),
            locator: None,
            algorithm: Some("ecdsa-p384".into()),
            exportable: false,
            passphrase: None,
        }
    );
    assert!(host.prompts.borrow().is_empty());
}

#[test]
fn a_file_key_asks_for_its_passphrase_twice() {
    let host = fake()
        .replying(Reply::Authority(authority(
            "new",
            "Lab Root",
            "file:/media/lab.key",
        )))
        .answering(&[PASSPHRASE, PASSPHRASE]);
    running(&host, "ca create Lab --root --key-file /media/lab.key").unwrap();
    let Request::CreateAuthority { key, .. } = host.sent() else {
        panic!()
    };
    assert_eq!(key.provider, "file");
    assert_eq!(key.locator.as_deref(), Some("/media/lab.key"));
    // pkid refuses a key file that isn't exportable.
    assert!(key.exportable);
    assert_eq!(key.passphrase.unwrap().expose(), PASSPHRASE.as_bytes());
    assert_eq!(host.prompts.borrow().len(), 2);
}

#[test]
fn a_new_passphrase_must_match_and_be_long_enough() {
    let host = fake().answering(&[PASSPHRASE, "something else entirely"]);
    let failure = running(&host, "ca create Lab --root --key-file /media/lab.key").unwrap_err();
    assert_eq!(failure.message, "the passphrases do not match");

    let host = fake().answering(&["short", "short"]);
    let failure = running(&host, "ca create Lab --root --key-file /media/lab.key").unwrap_err();
    assert!(
        failure.message.starts_with("the passphrase is too weak"),
        "{failure:?}"
    );
    // Nothing reached pkid.
    assert!(host
        .sent
        .borrow()
        .iter()
        .all(|r| matches!(r, Request::Authorities)));
}

#[test]
fn passphrase_files_replace_prompts() {
    let file = scratch("passphrase");
    std::fs::write(&file, format!("{PASSPHRASE}\n")).unwrap();
    let host = fake().replying(Reply::Authority(authority("sub", "Sub", "service:sub")));
    running(
        &host,
        &format!(
            "ca create Sub --issuer root --issuer-passphrase-file {}",
            file.display()
        ),
    )
    .unwrap();
    let Request::CreateAuthority {
        issuer,
        lifetime_days,
        ..
    } = host.sent()
    else {
        panic!()
    };
    let Issuer::Authority { ca, passphrase } = issuer else {
        panic!()
    };
    assert_eq!(ca, "11111111-1111-4111-8111-111111111111");
    assert_eq!(passphrase.unwrap().expose(), PASSPHRASE.as_bytes());
    assert_eq!(lifetime_days, cli::SUBORDINATE_LIFETIME_DAYS);
    assert!(host.prompts.borrow().is_empty());
    std::fs::remove_file(file).unwrap();
}

#[test]
fn a_service_key_issuer_needs_no_passphrase() {
    let host = fake().replying(Reply::Authority(authority("sub", "Sub", "service:sub")));
    running(&host, "ca create Sub --issuer Issuing").unwrap();
    let Request::CreateAuthority { issuer, .. } = host.sent() else {
        panic!()
    };
    assert_eq!(
        issuer,
        Issuer::Authority {
            ca: "22222222-2222-4222-8222-222222222222".into(),
            passphrase: None
        }
    );
}

#[test]
fn an_offline_ca_writes_its_request() {
    let path = scratch("offline.csr");
    let mut created = authority("off", "Offline", "service:off");
    created.certificate = None;
    created.request = Some(vec![0x30, 0x03, 0x02, 0x01, 0x07]);
    let host = fake().replying(Reply::Authority(created));
    let output = running(
        &host,
        &format!("ca create Offline --offline {}", path.display()),
    )
    .unwrap();
    let written = std::fs::read_to_string(&path).unwrap();
    assert!(
        written.starts_with("-----BEGIN CERTIFICATE REQUEST-----\n"),
        "{written}"
    );
    assert!(
        output.text.contains("pki ca install off"),
        "{}",
        output.text
    );
    std::fs::remove_file(path).unwrap();
}

#[test]
fn a_refused_create_leaves_no_request_file() {
    let path = scratch("refused.csr");
    let host = fake();
    *host.reply.borrow_mut() = Some(Err(ClientError::Refused(WireError::new(
        ErrorCode::AccessDenied,
        "access denied",
    ))));
    let failure = running(
        &host,
        &format!("ca create Offline --offline {}", path.display()),
    )
    .unwrap_err();
    assert_eq!(failure.kind, Kind::Denied);
    assert_eq!(failure.message, "create Offline: access denied");
    assert!(!path.exists());
}

#[test]
fn unknown_templates_fail_before_pkid_is_asked() {
    let host = fake();
    let failure = running(&host, "ca create Lab --root --template Mail").unwrap_err();
    assert_eq!(failure.kind, Kind::NotFound);
    assert_eq!(failure.message, "no template 'Mail'");
    assert!(host.sent.borrow().is_empty());
}

#[test]
fn nothing_is_asked_for_before_what_can_fail_without_pkid() {
    let host = fake().answering(&[PASSPHRASE, PASSPHRASE, PASSPHRASE]);
    let failure = running(
        &host,
        "ca create Sub --issuer Root --key-file /media/sub.key --template Mail",
    )
    .unwrap_err();
    assert_eq!(failure.message, "no template 'Mail'");
    assert!(host.prompts.borrow().is_empty());
}

#[test]
fn set_replaces_only_what_it_names() {
    let host = fake().replying(Reply::Authority(authority(
        "22222222-2222-4222-8222-222222222222",
        "Issuing",
        "service:2222",
    )));
    running(&host, "ca set Issuing --template Device --template Server").unwrap();
    assert_eq!(
        host.sent(),
        Request::ConfigureAuthority {
            ca: "22222222-2222-4222-8222-222222222222".into(),
            templates: Some(vec![
                "aaaaaaaa-0000-4000-8000-000000000002".into(),
                "aaaaaaaa-0000-4000-8000-000000000001".into(),
            ]),
            crl_distribution_points: None,
        }
    );

    let host = fake().replying(Reply::Authority(authority("x", "Issuing", "service:x")));
    running(&host, "ca set Issuing --no-crls").unwrap();
    let Request::ConfigureAuthority {
        templates,
        crl_distribution_points,
        ..
    } = host.sent()
    else {
        panic!()
    };
    assert_eq!(templates, None);
    assert_eq!(crl_distribution_points, Some(Vec::new()));

    let failure = running(&fake(), "ca set Issuing").unwrap_err();
    assert_eq!(failure.kind, Kind::Usage);
}

#[test]
fn export_asks_for_both_passphrases_of_a_file_key() {
    let path = scratch("exported.key");
    let host = fake()
        .replying(Reply::SealedKey(b"PEIOSKEY...".to_vec()))
        .answering(&["the current passphrase", PASSPHRASE, PASSPHRASE]);
    running(&host, &format!("ca export-key Root {}", path.display())).unwrap();
    let Request::ExportKey {
        current,
        passphrase,
        ..
    } = host.sent()
    else {
        panic!()
    };
    assert_eq!(current.unwrap().expose(), b"the current passphrase");
    assert_eq!(passphrase.expose(), PASSPHRASE.as_bytes());
    assert_eq!(std::fs::read(&path).unwrap(), b"PEIOSKEY...");
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    std::fs::remove_file(path).unwrap();
}

#[test]
fn sign_prints_the_certificate_without_an_out_file() {
    let request = scratch("sub.csr");
    std::fs::write(
        &request,
        crate::files::pem(crate::files::REQUEST, &[0x30, 0x00]),
    )
    .unwrap();
    let host = fake().replying(Reply::Signed(vec![0x30, 0x01, 0x00]));
    let output = running(
        &host,
        &format!("ca sign Issuing {} --name Branch", request.display()),
    )
    .unwrap();
    assert!(output.text.starts_with("-----BEGIN CERTIFICATE-----\n"));
    let Request::SignSubordinate {
        csr,
        name,
        lifetime_days,
        ..
    } = host.sent()
    else {
        panic!()
    };
    assert_eq!(csr, [0x30, 0x00]);
    assert_eq!(name, "Branch");
    assert_eq!(lifetime_days, cli::SUBORDINATE_LIFETIME_DAYS);
    std::fs::remove_file(request).unwrap();
}

#[test]
fn setup_explains_who_may_run_it() {
    let failure = running(&fake(), "setup").unwrap_err();
    assert_eq!(failure.kind, Kind::Denied);
    assert_eq!(
        failure.hint.as_deref(),
        Some("Run pki setup as an administrator.")
    );
}

#[test]
fn listing_shows_each_ca() {
    let output = running(&fake(), "ca list").unwrap();
    assert!(output.text.starts_with("NAME"), "{}", output.text);
    assert_eq!(output.text.lines().count(), 5);
    assert_eq!(output.json["authorities"].as_array().unwrap().len(), 4);
}

// Requests and certificates.

fn submission(outcome: pkid_core::Outcome, reasons: &[&str]) -> Reply {
    Reply::Submission(pkid_core::SubmissionInfo {
        request: 42,
        outcome,
        reasons: reasons.iter().map(|r| r.to_string()).collect(),
    })
}

fn request_file() -> PathBuf {
    let path = scratch("leaf.csr");
    std::fs::write(
        &path,
        crate::files::pem(crate::files::REQUEST, &[0x30, 0x00]),
    )
    .unwrap();
    path
}

#[test]
fn submit_names_the_template_among_those_the_ca_offers() {
    let csr = request_file();
    let host = fake().replying(submission(
        pkid_core::Outcome::Issued(vec![0x30, 0x00]),
        &[],
    ));
    let output = running(
        &host,
        &format!("request submit Issuing server {}", csr.display()),
    )
    .unwrap();
    assert!(output.text.starts_with("-----BEGIN CERTIFICATE-----\n"));
    assert_eq!(output.json["status"], "issued");
    let Request::Submit {
        ca,
        template,
        csr: sent,
    } = host.sent()
    else {
        panic!()
    };
    assert_eq!(ca, "22222222-2222-4222-8222-222222222222");
    assert_eq!(template, "t-server");
    assert_eq!(sent, [0x30, 0x00]);

    let failure = running(
        &fake(),
        &format!("request submit Issuing Device {}", csr.display()),
    )
    .unwrap_err();
    assert_eq!(failure.kind, Kind::NotFound);
    assert_eq!(failure.message, "CA Issuing offers no template 'Device'");
}

#[test]
fn a_held_request_says_how_to_collect_its_certificate() {
    let csr = request_file();
    let out = scratch("held.pem");
    let host = fake().replying(submission(
        pkid_core::Outcome::Pending,
        &["approval required"],
    ));
    let output = running(
        &host,
        &format!(
            "request submit Issuing Server {} --out {}",
            csr.display(),
            out.display()
        ),
    )
    .unwrap();
    assert!(output
        .text
        .starts_with("Request 42 awaits approval: approval required.\n"));
    assert!(output
        .text
        .contains("pki cert get 22222222-2222-4222-8222-222222222222 42"));
    // Nothing was issued, so nothing is left at the output path.
    assert!(!out.exists());
}

#[test]
fn a_refused_request_fails_with_its_reasons() {
    let csr = request_file();
    let host = fake().replying(submission(
        pkid_core::Outcome::Denied,
        &["name not allowed"],
    ));
    let failure = running(
        &host,
        &format!("request submit Issuing Server {}", csr.display()),
    )
    .unwrap_err();
    assert_eq!(failure.kind, Kind::Failed);
    assert!(
        failure
            .message
            .ends_with("request 42 was denied: name not allowed"),
        "{failure:?}"
    );
}

#[test]
fn approving_your_own_request_is_access_denied() {
    let host = fake();
    *host.reply.borrow_mut() = Some(Err(ClientError::Refused(WireError::new(
        ErrorCode::SelfApproval,
        "an officer may not approve their own request",
    ))));
    let failure = running(&host, "request approve Issuing 42").unwrap_err();
    assert_eq!(failure.kind.status(), 3);
    assert_eq!(
        failure.message,
        "approve 42: an officer may not approve their own request"
    );
}

#[test]
fn deny_records_its_reason() {
    let host = fake().replying(Reply::Done);
    running(&host, "request deny Issuing 42 --reason duplicate").unwrap();
    assert_eq!(
        host.sent(),
        Request::Deny {
            ca: "22222222-2222-4222-8222-222222222222".into(),
            request: 42,
            reason: Some("duplicate".into()),
        }
    );
}

#[test]
fn request_listings_filter_by_status() {
    let host = fake().replying(Reply::Requests(vec![pkid_core::RequestInfo {
        id: 7,
        template: "t-server".into(),
        names: vec!["www.example.org".into()],
        requester: "S-1-5-21-1-2-3-1001".into(),
        submitted: 0,
        status: pkid_core::RequestStatus::Pending,
        reasons: Vec::new(),
        decided: None,
        decider: None,
    }]));
    let output = running(&host, "request list Issuing --status pending").unwrap();
    assert!(
        output.text.contains("7   pending  Server"),
        "{}",
        output.text
    );
    let Request::Requests { query, .. } = host.sent() else {
        panic!()
    };
    assert_eq!(query.status, Some(pkid_core::RequestStatus::Pending));
    assert_eq!(query.after, None);
}

#[test]
fn revoke_sends_the_rfc_5280_code() {
    let host = fake().replying(Reply::Done);
    let output = running(&host, "cert revoke Issuing 0A:1b --reason key-compromise").unwrap();
    assert_eq!(output.text, "Revoked certificate 0a1b.\n");
    assert_eq!(
        host.sent(),
        Request::Revoke {
            ca: "22222222-2222-4222-8222-222222222222".into(),
            serial: vec![0x0a, 0x1b],
            reason: 1,
        }
    );
    let host = fake().replying(Reply::Done);
    running(&host, "cert revoke Issuing 0a1b").unwrap();
    let Request::Revoke { reason, .. } = host.sent() else {
        panic!()
    };
    assert_eq!(reason, 0);

    assert!(
        usage_error("cert revoke Issuing 0a1b --reason certificate-hold")
            .starts_with("--reason <reason>: 'certificate-hold' is not one of unspecified, ")
    );
    let failure = running(&fake(), "cert revoke Issuing nonsense").unwrap_err();
    assert_eq!(failure.kind, Kind::Usage);
}

#[test]
fn get_writes_the_certificate_issued_for_a_request() {
    let out = scratch("got.pem");
    let host = fake().replying(Reply::Certificate(pkid_core::CertificateInfo {
        serial: vec![0x01],
        request: 42,
        der: vec![0x30, 0x00],
        not_before: 0,
        not_after: 1,
        owner: None,
        revocation: None,
    }));
    let output = running(&host, &format!("cert get Issuing 42 -o {}", out.display())).unwrap();
    assert_eq!(output.json["status"], "expired");
    assert!(std::fs::read_to_string(&out)
        .unwrap()
        .starts_with("-----BEGIN CERTIFICATE-----"));
    std::fs::remove_file(out).unwrap();
}

// Templates and names.

const SERVER: &str = "aaaaaaaa-0000-4000-8000-000000000001";
const DEVICE: &str = "aaaaaaaa-0000-4000-8000-000000000002";

fn writes(host: &Fake) -> Vec<Write> {
    host.writes.borrow().clone()
}

fn template_key(id: &str) -> String {
    format!("Machine\\Software\\Pki\\Templates\\{id}")
}

#[test]
fn templates_list_with_the_cas_that_use_them() {
    let output = running(&fake(), "template list").unwrap();
    assert!(output.text.contains("Server"), "{}", output.text);
    assert_eq!(output.json["templates"][0]["used_by"][0], "Issuing");
    assert_eq!(
        output.json["templates"][1]["used_by"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
}

#[test]
fn a_template_is_checked_by_policy_before_it_is_written() {
    let host = fake();
    // The Server template's renewal window is 30 days, which a 30-day
    // lifetime doesn't leave room for.
    let failure = running(&host, "template create Short --from Server --lifetime 30").unwrap_err();
    assert_eq!(failure.kind, Kind::Usage);
    assert!(failure.message.contains("RenewalWindowDays"), "{failure:?}");
    let failure = running(
        &host,
        "template create Odd --from Server --purpose anything",
    )
    .unwrap_err();
    assert_eq!(failure.kind, Kind::Usage);
    assert!(writes(&host).is_empty());

    let failure = running(&host, "template create Bare --purpose server-auth").unwrap_err();
    assert_eq!(failure.kind, Kind::Usage);
    assert!(failure.message.contains("--from"), "{failure:?}");

    let failure = running(&host, "template create server --from Device").unwrap_err();
    assert_eq!(failure.kind, Kind::Exists);
}

#[test]
fn a_new_template_starts_from_another() {
    let host = fake();
    running(
        &host,
        "template create Web --from Server --lifetime 60 --issuance approval",
    )
    .unwrap();
    let written = writes(&host);
    let [Write::Create(path, values)] = written.as_slice() else {
        panic!("{written:?}")
    };
    assert_eq!(*path, template_key("bbbbbbbb-0000-4000-8000-000000000009"));
    assert_eq!(values.sz("Name").unwrap(), Some("Web"));
    assert_eq!(values.dword("LifetimeDays").unwrap(), Some(60));
    assert_eq!(values.sz("Issuance").unwrap(), Some("approval"));
    assert_eq!(values.multi_sz("Purposes").unwrap(), ["server-auth"]);
    assert!(pki_policy::Template::from_values(values).is_ok());
}

#[test]
fn a_new_template_without_a_source_takes_the_shipped_choices() {
    let host = fake();
    running(
        &host,
        "template create Mail --purpose email-protection --name-type email --lifetime 365",
    )
    .unwrap();
    let written = writes(&host);
    let [Write::Create(_, values)] = written.as_slice() else {
        panic!()
    };
    assert_eq!(values.multi_sz("KeyUsages").unwrap(), ["digital-signature"]);
    assert!(values.binary("EnrollSecurity").unwrap().is_some());
}

#[test]
fn set_writes_only_what_changes() {
    let host = fake();
    running(&host, "template set server --issuance approval --name Web").unwrap();
    let written = writes(&host);
    let [Write::Change(path, values, removed)] = written.as_slice() else {
        panic!()
    };
    assert_eq!(*path, template_key(SERVER));
    assert_eq!(values.iter().count(), 2);
    assert!(removed.is_empty());
    let failure = running(&fake(), "template set Server").unwrap_err();
    assert_eq!(failure.kind, Kind::Usage);
}

#[test]
fn a_template_in_use_is_not_deleted() {
    let host = fake();
    let failure = running(&host, "template delete Server").unwrap_err();
    assert!(
        failure.message.contains("CA Issuing issues from it"),
        "{failure:?}"
    );
    assert!(writes(&host).is_empty());
    running(&host, "template delete Device").unwrap();
    assert_eq!(writes(&host), [Write::Delete(template_key(DEVICE))]);
}

#[test]
fn a_name_shows_where_its_descriptor_comes_from() {
    let output = running(&fake(), "name show radius.lab.home").unwrap();
    assert!(output.text.contains("inherited from ."), "{}", output.text);
    assert!(output.text.contains(";BA)"), "{}", output.text);
    assert_eq!(output.json["owner"], Value::Null);
    let output = running(&fake(), "name show lab.home").unwrap();
    assert_eq!(output.json["owner"], "S-1-5-21-1-2-3-1001");
}

#[test]
fn a_names_descriptor_keeps_what_it_inherits() {
    let host = fake();
    let output = running(&host, "name set-security lab.home D:(A;CI;0x2;;;AU)").unwrap();
    let written = writes(&host);
    let [Write::Put(path, values, _)] = written.as_slice() else {
        panic!()
    };
    assert_eq!(*path, "Machine\\Software\\Pki\\Names\\Dns\\home\\lab");
    let written =
        peios::security::sddl::format(values.binary("RequestSecurity").unwrap().unwrap()).unwrap();
    // An owner and group, as every shipped descriptor has, though none was
    // given.
    assert!(written.starts_with("O:SYG:SY"), "{written}");
    // Its own entry, and the root's, which a bare value would have dropped.
    assert!(written.contains(";AU)"), "{written}");
    assert!(
        written.contains(";BA)") && written.contains(";PS)"),
        "{written}"
    );
    assert!(output.text.contains("its own"), "{}", output.text);
    assert!(host.warnings.borrow().is_empty());
}

#[test]
fn broad_grants_and_owners_are_warned_of() {
    let host = fake();
    running(&host, "name set-security lab.home D:(A;CI;0x1;;;AU)").unwrap();
    let warnings = host.warnings.borrow().clone();
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(
        warnings[0].starts_with("Authenticated Users may now request"),
        "{warnings:?}"
    );

    let host = fake();
    running(&host, "name set-owner jack@home S-1-5-32-545").unwrap();
    assert!(host.warnings.borrow()[0].starts_with("Users owns this name"));
    let written = writes(&host);
    let [Write::Put(path, values, _)] = written.as_slice() else {
        panic!()
    };
    assert_eq!(
        *path,
        "Machine\\Software\\Pki\\Names\\Principals\\home\\@jack"
    );
    assert_eq!(values.sz("Owner").unwrap(), Some("S-1-5-32-545"));
}

#[test]
fn a_root_descriptor_that_drops_administrators_is_warned_of() {
    let host = fake();
    running(&host, "name set-security . D:(A;CI;0x2;;;AU)").unwrap();
    let warnings = host.warnings.borrow().clone();
    assert_eq!(warnings.len(), 2, "{warnings:?}");
    assert!(
        warnings[0].starts_with("Administrators can't request"),
        "{warnings:?}"
    );
    // Below the root, the root's grants are kept, so there is nothing to
    // warn of.
    let host = fake();
    running(&host, "name set-security lab.home D:(A;CI;0x2;;;AU)").unwrap();
    assert!(host.warnings.borrow().is_empty());
}

#[test]
fn names_are_removed_leaf_first_and_roots_never() {
    let host = fake();
    let failure = running(&host, "name remove home").unwrap_err();
    assert!(
        failure.message.contains("names are listed below it"),
        "{failure:?}"
    );
    running(&host, "name remove lab.home").unwrap();
    assert_eq!(
        writes(&host),
        [Write::Delete(
            "Machine\\Software\\Pki\\Names\\Dns\\home\\lab".into()
        )]
    );
    assert_eq!(
        running(&fake(), "name remove .").unwrap_err().kind,
        Kind::Usage
    );
    assert_eq!(
        running(&fake(), "name set-security . --inherit")
            .unwrap_err()
            .kind,
        Kind::Usage
    );
}

#[test]
fn names_that_exist_or_cannot_exist_are_refused() {
    assert_eq!(
        running(&fake(), "name add lab.home").unwrap_err().kind,
        Kind::Exists
    );
    assert_eq!(
        running(&fake(), "name add *.lab.home").unwrap_err().kind,
        Kind::Usage
    );
    assert_eq!(
        running(&fake(), "name add www.lab.home --owner nobody")
            .unwrap_err()
            .kind,
        Kind::Usage
    );
    let host = fake();
    running(&host, "name add www.lab.home --owner S-1-5-21-1-2-3-1002").unwrap();
    assert!(matches!(writes(&host).as_slice(), [Write::Create(..)]));
}

// Enrolment.

/// A root CA that issues whatever it is asked, as pkid would once policy
/// allowed it.
struct TestCa {
    key: pki_keys::PrivateKey,
    root: Vec<u8>,
}

impl TestCa {
    fn new() -> Self {
        let key = pki_keys::PrivateKey::generate(pki_keys::KeyAlgorithm::EcdsaP256).unwrap();
        let now = time::OffsetDateTime::now_utc();
        let profile = pki_core::CaProfile {
            subject: pki_core::CaSubject {
                common_name: "Test Root".into(),
                attributes: Vec::new(),
            },
            validity: pki_core::Validity::new(
                now - time::Duration::days(1),
                now + time::Duration::days(3650),
            )
            .unwrap(),
            path_length: Some(0),
            name_constraints: None,
            extended_key_usages: None,
            crl_distribution_points: Vec::new(),
        };
        let root =
            pki_core::create_root(&key, &profile, &pki_core::SerialNumber::random().unwrap())
                .unwrap()
                .der()
                .to_vec();
        Self { key, root }
    }

    fn issue(&self, csr: &[u8]) -> Vec<u8> {
        let request = pki_core::CertificateRequest::from_der(csr).unwrap();
        let now = time::OffsetDateTime::now_utc();
        let profile = pki_core::LeafProfile {
            subject: pki_core::LeafSubject {
                common_name: None,
                attributes: Vec::new(),
            },
            alt_names: request.names().to_vec(),
            key_usages: vec![pki_core::KeyUsage::DigitalSignature],
            extended_key_usages: pki_core::ExtendedKeyUsages::new(vec![
                pki_core::ExtendedKeyUsage::ClientAuth,
            ])
            .unwrap(),
            validity: pki_core::Validity::new(now, now + time::Duration::days(30)).unwrap(),
            owner_sid: None,
            crl_distribution_points: Vec::new(),
        };
        pki_core::IssuingCa::new(&self.root, &self.key)
            .unwrap()
            .issue(
                request.subject_key(),
                &profile,
                &pki_core::SerialNumber::random().unwrap(),
            )
            .unwrap()
            .der()
            .to_vec()
    }
}

/// The stand-in, with Issuing's certificate the test root's.
fn enrolling(ca: &std::rc::Rc<TestCa>, outcome: &'static str) -> Fake {
    let mut host = fake();
    host.authorities[1].certificate = Some(ca.root.clone());
    let ca = ca.clone();
    host.respond = Some(Box::new(move |request| match request {
        Request::Submit { csr, .. } => Reply::Submission(pkid_core::SubmissionInfo {
            request: 42,
            outcome: match outcome {
                "issued" => pkid_core::Outcome::Issued(ca.issue(csr)),
                _ => pkid_core::Outcome::Pending,
            },
            reasons: Vec::new(),
        }),
        other => panic!("{other:?}"),
    }));
    host
}

fn passphrase_file() -> PathBuf {
    let path = scratch("enroll-passphrase");
    std::fs::write(&path, format!("{PASSPHRASE}\n")).unwrap();
    path
}

#[test]
fn enrolment_writes_the_key_and_chain_as_pkcs12() {
    let ca = std::rc::Rc::new(TestCa::new());
    let host = enrolling(&ca, "issued");
    let out = scratch("device.p12");
    let line = format!(
        "enroll Issuing Server --upn jack@home --email jack@home --out {} --passphrase-file {}",
        out.display(),
        passphrase_file().display()
    );
    let output = running(&host, &line).unwrap();
    assert_eq!(output.json["status"], "issued");
    let file = std::fs::read(&out).unwrap();
    assert_eq!(file[0], 0x30);
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&out).unwrap().permissions().mode() & 0o777,
        0o600
    );
    // The key went nowhere but the file: pkid saw only a request.
    let Request::Submit { csr, .. } = host.sent() else {
        panic!()
    };
    let request = pki_core::CertificateRequest::from_der(&csr).unwrap();
    assert_eq!(request.names().len(), 2);
    assert!(!crate::enroll::tests_pending_path(&out).exists());
    std::fs::remove_file(out).unwrap();
}

#[test]
fn a_held_enrolment_keeps_its_key_sealed_until_collected() {
    let ca = std::rc::Rc::new(TestCa::new());
    let host = enrolling(&ca, "pending");
    let out = scratch("held.p12");
    let key_path = crate::enroll::tests_pending_path(&out);
    let _ = std::fs::remove_file(&key_path);
    let passphrase = passphrase_file();
    let output = running(
        &host,
        &format!(
            "enroll Issuing Server --dns www.lab.home --out {} --passphrase-file {}",
            out.display(),
            passphrase.display()
        ),
    )
    .unwrap();
    assert_eq!(output.json["status"], "pending");
    assert!(!out.exists());
    assert!(
        output.text.contains("--request 42 --key"),
        "{}",
        output.text
    );
    let sealed = std::fs::read(&key_path).unwrap();
    assert_eq!(&sealed[..8], b"PEIOSKEY");

    // While it is still held, nothing is asked for.
    let mut host = enrolling(&ca, "pending");
    *host.reply.borrow_mut() = Some(Err(ClientError::Refused(WireError::new(
        ErrorCode::NotFound,
        "request 42 has no certificate",
    ))));
    host.respond = None;
    let line = format!(
        "enroll Issuing --request 42 --key {} --out {}",
        key_path.display(),
        out.display()
    );
    assert_eq!(running(&host, &line).unwrap_err().kind, Kind::NotFound);
    assert!(host.prompts.borrow().is_empty());
    assert!(!out.exists());

    // Once approved, the certificate is collected with the sealed key.
    let key = pki_keys::open_sealed_key(&sealed, &pki_keys::Passphrase::new(PASSPHRASE)).unwrap();
    let names = [pki_core::AltName::Dns(
        pki_core::DnsName::new("www.lab.home").unwrap(),
    )];
    let certificate = ca.issue(&pki_core::leaf_request(&key, &names).unwrap());
    let mut host = enrolling(&ca, "pending");
    host.respond = Some(Box::new(move |request| match request {
        Request::CertificateFor { request: 42, .. } => {
            Reply::Certificate(pkid_core::CertificateInfo {
                serial: vec![1],
                request: 42,
                der: certificate.clone(),
                not_before: 0,
                not_after: 0,
                owner: None,
                revocation: None,
            })
        }
        other => panic!("{other:?}"),
    }));
    let line = format!(
        "enroll Issuing --request 42 --key {} --out {} --passphrase-file {}",
        key_path.display(),
        out.display(),
        passphrase.display()
    );
    running(&host, &line).unwrap();
    assert_eq!(std::fs::read(&out).unwrap()[0], 0x30);

    // A certificate for another key is refused, and leaves nothing behind.
    let other = TestCa::new();
    let stranger = pki_keys::PrivateKey::generate(pki_keys::KeyAlgorithm::EcdsaP256).unwrap();
    let wrong = other.issue(&pki_core::leaf_request(&stranger, &names).unwrap());
    let mut host = enrolling(&ca, "pending");
    host.respond = Some(Box::new(move |_| {
        Reply::Certificate(pkid_core::CertificateInfo {
            serial: vec![2],
            request: 42,
            der: wrong.clone(),
            not_before: 0,
            not_after: 0,
            owner: None,
            revocation: None,
        })
    }));
    let again = scratch("held-again.p12");
    let line = format!(
        "enroll Issuing --request 42 --key {} --out {} --passphrase-file {}",
        key_path.display(),
        again.display(),
        passphrase.display()
    );
    let failure = running(&host, &line).unwrap_err();
    assert!(failure.hint.is_some(), "{failure:?}");
    assert!(!again.exists());
    for path in [out, key_path] {
        std::fs::remove_file(path).unwrap();
    }
}

#[test]
fn enrolment_needs_a_name_and_collecting_needs_the_key() {
    let out = scratch("unnamed.p12");
    let failure = running(
        &fake(),
        &format!("enroll Issuing Server --out {}", out.display()),
    )
    .unwrap_err();
    assert_eq!(
        failure.message,
        "give at least one of --dns, --email or --upn"
    );
    assert!(usage_error(&format!(
        "enroll Issuing --request 4 --out {}",
        out.display()
    ))
    .starts_with("missing "));
    assert!(usage_error(&format!(
        "enroll Issuing Server --request 4 --key k --out {}",
        out.display()
    ))
    .contains("cannot be used with"));
}
