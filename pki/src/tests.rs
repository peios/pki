//! pki's parsing, help and commands, against a stand-in for pkid.

use std::cell::RefCell;
use std::ffi::OsString;
use std::io;
use std::path::PathBuf;

use pki_management::provision::Seeded;
use pkid_client::ClientError;
use pkid_core::{
    AuthorityInfo, ErrorCode, Issuer, KeySpec, Reply, Request, TemplateInfo, WireError,
};
use zeroize::Zeroizing;

use crate::failure::Kind;
use crate::host::{Host, TemplateName};
use crate::{cli, parse, run, Stop};

const PASSPHRASE: &str = "correct horse battery staple";

/// pkid, the Registry and the terminal, as a test sets them up.
#[derive(Default)]
struct Fake {
    authorities: Vec<AuthorityInfo>,
    templates: Vec<TemplateName>,
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
        self.reply
            .borrow_mut()
            .take()
            .expect("the test says what pkid replies")
    }

    fn templates(&self) -> io::Result<Vec<TemplateName>> {
        Ok(self.templates.clone())
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
        templates: vec![
            TemplateName {
                id: "aaaaaaaa-0000-4000-8000-000000000001".into(),
                name: "Server".into(),
            },
            TemplateName {
                id: "aaaaaaaa-0000-4000-8000-000000000002".into(),
                name: "Device".into(),
            },
        ],
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
