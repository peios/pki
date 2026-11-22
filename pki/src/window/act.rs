//! The changes the window makes. Each is a `pki` command, run as the
//! terminal runs it, through a host whose prompts are answered from what
//! the person typed into the window. So the window and the command line
//! can't differ about what a change does or checks.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::io;
use std::path::PathBuf;

use pki_management::provision::Seeded;
use pki_management::Snapshot;
use pki_policy::Values;
use pkid_client::ClientError;
use pkid_core::{Reply, Request};
use serde_json::Value;
use zeroize::Zeroizing;

use super::service::sentence;
use crate::cli::{
    Ca, Cert, Command, Create, Enroll, Import, Issuer, Issuing, Keeping, NameCommand,
    RequestCommand, Set, TemplateCommand, TemplateFields,
};
use crate::failure::{Failure, Kind};
use crate::host::Host;

/// A host that is another, but for its prompts, which it answers from
/// `answers` in order, and its warnings, which it keeps for the window.
pub struct Answering<'a> {
    inner: &'a dyn Host,
    answers: RefCell<VecDeque<Zeroizing<String>>>,
    warnings: RefCell<Vec<String>>,
}

impl<'a> Answering<'a> {
    pub fn new(inner: &'a dyn Host, answers: Vec<Zeroizing<String>>) -> Self {
        Self {
            inner,
            answers: RefCell::new(answers.into()),
            warnings: RefCell::new(Vec::new()),
        }
    }

    /// The answers no prompt took.
    pub fn unasked(&self) -> usize {
        self.answers.borrow().len()
    }

    pub fn warnings(&self) -> Vec<String> {
        self.warnings.borrow().clone()
    }
}

impl Host for Answering<'_> {
    fn call(&self, request: &Request) -> Result<Reply, ClientError> {
        self.inner.call(request)
    }

    fn setup(&self) -> io::Result<Seeded> {
        self.inner.setup()
    }

    /// The next answer. A prompt the window didn't expect has none, and
    /// fails as a prompt with no terminal does.
    fn prompt(&self, _question: &str) -> io::Result<Zeroizing<String>> {
        self.answers
            .borrow_mut()
            .pop_front()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "nothing was typed for it"))
    }

    fn snapshot(&self) -> io::Result<Snapshot> {
        self.inner.snapshot()
    }

    fn change(&self, path: &str, set: &Values, remove: &[&str]) -> io::Result<()> {
        self.inner.change(path, set, remove)
    }

    fn put(&self, path: &str, set: &Values, remove: &[&str]) -> io::Result<()> {
        self.inner.put(path, set, remove)
    }

    fn create(&self, path: &str, set: &Values) -> io::Result<()> {
        self.inner.create(path, set)
    }

    fn delete(&self, path: &str) -> io::Result<()> {
        self.inner.delete(path)
    }

    fn new_guid(&self) -> io::Result<String> {
        self.inner.new_guid()
    }

    fn warn(&self, warning: &str) {
        self.warnings.borrow_mut().push(warning.to_owned());
    }
}

/// What came of a command: its JSON, and anything it warned of.
pub struct Ran {
    pub json: Value,
    pub warnings: Vec<String>,
}

/// The commands' own words for what they were doing, which come first in
/// a failure's message.
const CONTEXTS: [&str; 22] = [
    "approve ",
    "deny ",
    "revoke ",
    "publish-crl ",
    "enroll ",
    "submit ",
    "get ",
    "setup",
    "set-security ",
    "set ",
    "sign ",
    "install ",
    "export-key ",
    "create ",
    "import ",
    "list CAs",
    "delete ",
    "add ",
    "remove ",
    "set-owner ",
    "domains",
    "reading the configuration",
];

/// A command's failure, said as the window says things. `doing` is what
/// the person was doing, as in "approve request #42".
pub fn failed(doing: &str, failure: &Failure) -> String {
    let mut message = failure.message.as_str();
    if let Some((context, rest)) = message.split_once(": ") {
        if CONTEXTS.iter().any(|known| context.starts_with(known)) {
            message = rest;
        }
    }
    match failure.kind {
        Kind::Denied
            if message == "access denied"
                || message.to_ascii_lowercase().contains("permission denied") =>
        {
            format!("You don't have permission to {doing}.")
        }
        _ => {
            let mut said = sentence(message);
            if let Some(hint) = &failure.hint {
                said.push(' ');
                said.push_str(hint);
            }
            said
        }
    }
}

/// Runs `command` as the terminal would, answering its prompts with
/// `answers`, all of which it must ask for.
pub fn run(
    host: &dyn Host,
    command: Command,
    answers: Vec<Zeroizing<String>>,
    doing: &str,
) -> Result<Ran, String> {
    let answering = Answering::new(host, answers);
    let output = crate::run::run(&answering, command).map_err(|failure| failed(doing, &failure))?;
    // A command that ran to the end asked for everything the window typed;
    // one that stopped early, refused, may not have.
    debug_assert_eq!(
        answering.unasked(),
        0,
        "{doing}: an answer went unasked for"
    );
    Ok(Ran {
        json: output.json,
        warnings: answering.warnings(),
    })
}

pub fn approve(host: &dyn Host, ca: &str, request: i64) -> Result<String, String> {
    let ran = run(
        host,
        Command::Request(RequestCommand::Approve {
            ca: ca.to_owned(),
            request,
            out: None,
        }),
        Vec::new(),
        &format!("approve request #{request}"),
    )?;
    Ok(match ran.json["status"].as_str() {
        Some("issued") => format!("Request #{request} approved. Its certificate was issued."),
        _ => format!("Request #{request} approved."),
    })
}

pub fn deny(host: &dyn Host, ca: &str, request: i64, reason: &str) -> Result<String, String> {
    let reason = reason.trim();
    run(
        host,
        Command::Request(RequestCommand::Deny {
            ca: ca.to_owned(),
            request,
            reason: (!reason.is_empty()).then(|| reason.to_owned()),
        }),
        Vec::new(),
        &format!("deny request #{request}"),
    )?;
    Ok(format!("Request #{request} denied."))
}

pub fn revoke(host: &dyn Host, ca: &str, serial: &str, reason: &str) -> Result<String, String> {
    let ran = run(
        host,
        Command::Cert(Cert::Revoke {
            ca: ca.to_owned(),
            serial: serial.to_owned(),
            reason: reason.to_owned(),
        }),
        Vec::new(),
        "revoke certificates",
    )?;
    Ok(if ran.json["crl_published"].as_bool() == Some(false) {
        "Certificate revoked. Publish a new revocation list so that software learns of it."
            .to_string()
    } else {
        "Certificate revoked. A new revocation list was published.".to_string()
    })
}

/// Publishes a CA's revocation list, with its key's passphrase if it is
/// sealed.
pub fn publish(
    host: &dyn Host,
    ca: &str,
    passphrase: Option<Zeroizing<String>>,
) -> Result<String, String> {
    let ran = run(
        host,
        Command::Ca(crate::cli::Ca::PublishCrl {
            ca: ca.to_owned(),
            passphrase_file: None,
        }),
        passphrase.into_iter().collect(),
        "publish its revocation list",
    )?;
    Ok(format!(
        "Revocation list {} published.",
        ran.json["number"].as_u64().unwrap_or_default()
    ))
}

pub fn setup(host: &dyn Host) -> Result<String, String> {
    let ran = run(
        host,
        Command::Setup,
        Vec::new(),
        "set up the certificate authority",
    )?;
    let mut said = "Certificate authority set up.".to_string();
    for warning in ran.warnings {
        said.push(' ');
        said.push_str(&sentence(&warning));
    }
    Ok(said)
}

/// What the person asked for on the Request a Certificate form.
#[derive(Debug, Clone)]
pub struct Enrolment {
    pub ca: String,
    pub template: String,
    pub dns: Vec<String>,
    pub emails: Vec<String>,
    pub upns: Vec<String>,
    pub algorithm: String,
    pub out: PathBuf,
}

/// What came of requesting a certificate with a key made here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Enrolled {
    /// Issued, and saved with its key at the path asked for.
    Saved,
    /// Held for an officer, as request `request`, its key sealed in `key`.
    Held { request: i64, key: PathBuf },
}

pub fn enrol(
    host: &dyn Host,
    enrolment: &Enrolment,
    password: Zeroizing<String>,
) -> Result<Enrolled, String> {
    let command = Command::Enroll(Enroll {
        ca: enrolment.ca.clone(),
        template: Some(enrolment.template.clone()),
        dns: enrolment.dns.clone(),
        emails: enrolment.emails.clone(),
        upns: enrolment.upns.clone(),
        out: enrolment.out.clone(),
        algorithm: enrolment.algorithm.clone(),
        friendly_name: None,
        request: None,
        key: None,
        passphrase_file: None,
        replace: true,
    });
    // pki asks for a new passphrase twice; the window's Confirm Password
    // field has been checked against it already.
    let answers = vec![password.clone(), password];
    let ran = run(
        host,
        command,
        answers,
        "request certificates from this authority",
    )?;
    match ran.json["status"].as_str() {
        Some("pending") => Ok(Enrolled::Held {
            request: ran.json["request"].as_i64().unwrap_or_default(),
            key: PathBuf::from(ran.json["key_file"].as_str().unwrap_or_default()),
        }),
        _ => Ok(Enrolled::Saved),
    }
}

/// Saves the certificate a held request was issued, with the key kept for
/// it, as `pki enroll --request` does.
pub fn collect(
    host: &dyn Host,
    ca: &str,
    request: i64,
    key: PathBuf,
    out: PathBuf,
    password: Zeroizing<String>,
) -> Result<String, String> {
    let shown = out.display().to_string();
    run(
        host,
        Command::Enroll(Enroll {
            ca: ca.to_owned(),
            template: None,
            dns: Vec::new(),
            emails: Vec::new(),
            upns: Vec::new(),
            out,
            algorithm: "ecdsa-p256".into(),
            friendly_name: None,
            request: Some(request),
            key: Some(key),
            passphrase_file: None,
            replace: true,
        }),
        vec![password],
        "collect this certificate",
    )?;
    Ok(format!("Saved to {shown}."))
}

/// Submits a request made elsewhere. Returns the request's number and the
/// certificate in PEM, if it was issued at once.
pub fn submit(
    host: &dyn Host,
    ca: &str,
    template: &str,
    request: PathBuf,
) -> Result<(i64, Option<String>), String> {
    let ran = run(
        host,
        Command::Request(RequestCommand::Submit {
            ca: ca.to_owned(),
            template: template.to_owned(),
            request,
            out: None,
        }),
        Vec::new(),
        "request certificates from this authority",
    )?;
    let id = ran.json["request"].as_i64().unwrap_or_default();
    Ok((id, ran.json["certificate"].as_str().map(str::to_owned)))
}

/// Changes which templates a CA issues from, its revocation list
/// addresses and how long each list lasts.
pub fn configure(
    host: &dyn Host,
    ca: &str,
    templates: Vec<String>,
    crls: Vec<String>,
    crl_lifetime: Option<u32>,
) -> Result<String, String> {
    run(
        host,
        Command::Ca(Ca::Set(Set {
            ca: ca.to_owned(),
            no_templates: templates.is_empty(),
            templates,
            no_crls: crls.is_empty(),
            crls,
            crl_lifetime,
        })),
        Vec::new(),
        "change this authority",
    )?;
    Ok("Changes saved.".into())
}

/// Replaces who may do what at a CA. Says what deserves a warning.
pub fn set_security(host: &dyn Host, ca: &str, sddl: &str) -> Result<String, String> {
    let ran = run(
        host,
        Command::Ca(Ca::SetSecurity {
            ca: ca.to_owned(),
            sddl: sddl.to_owned(),
        }),
        Vec::new(),
        "change who may use this authority",
    )?;
    let mut said = "Permissions changed.".to_string();
    for warning in ran.warnings {
        said.push(' ');
        said.push_str(&sentence(&warning));
    }
    Ok(said)
}

/// A new path beside `path` for a command that won't replace a file, and
/// the file it is to become once written.
fn beside(path: &std::path::Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_owned();
    name.push(format!(".pki-new-{}", std::process::id()));
    path.with_file_name(name)
}

/// Moves what a command wrote at `written` over `path`, or removes it.
fn settle(written: &std::path::Path, path: &std::path::Path, worked: bool) -> Result<(), String> {
    if worked {
        std::fs::rename(written, path).map_err(|error| {
            let _ = std::fs::remove_file(written);
            sentence(&format!(
                "{}: {}",
                path.display(),
                crate::failure::os_message(&error)
            ))
        })
    } else {
        let _ = std::fs::remove_file(written);
        Ok(())
    }
}

/// Exports a CA's key, sealed under `passphrase`, to `out`.
pub fn export_key(
    host: &dyn Host,
    ca: &str,
    out: PathBuf,
    current: Option<Zeroizing<String>>,
    passphrase: Zeroizing<String>,
) -> Result<String, String> {
    let written = beside(&out);
    let _ = std::fs::remove_file(&written);
    let mut answers: Vec<Zeroizing<String>> = current.into_iter().collect();
    answers.push(passphrase.clone());
    answers.push(passphrase);
    let ran = run(
        host,
        Command::Ca(Ca::ExportKey {
            ca: ca.to_owned(),
            out: written.clone(),
            passphrase_file: None,
            new_passphrase_file: None,
        }),
        answers,
        "export this authority's key",
    );
    settle(&written, &out, ran.is_ok())?;
    ran.map(|_| format!("Key exported to {}.", out.display()))
}

/// Signs a subordinate authority's request with `ca`'s key. Returns the
/// certificate, in PEM.
pub fn sign(
    host: &dyn Host,
    ca: &str,
    request: PathBuf,
    name: &str,
    lifetime: u32,
    path_length: Option<u8>,
    passphrase: Option<Zeroizing<String>>,
) -> Result<String, String> {
    let ran = run(
        host,
        Command::Ca(Ca::Sign {
            ca: ca.to_owned(),
            request,
            name: name.to_owned(),
            lifetime,
            path_length,
            out: None,
            passphrase_file: None,
        }),
        passphrase.into_iter().collect(),
        "sign with this authority",
    )?;
    ran.json["certificate"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| "The Certificate Service sent no certificate.".to_string())
}

pub fn install(host: &dyn Host, ca: &str, certificate: PathBuf) -> Result<String, String> {
    run(
        host,
        Command::Ca(Ca::Install {
            ca: ca.to_owned(),
            certificate,
        }),
        Vec::new(),
        "install this authority's certificate",
    )?;
    Ok("Certificate installed. The authority can issue now.".into())
}

/// Where a new or imported authority's key is kept.
#[derive(Debug, Clone)]
pub enum Keep {
    /// In the Certificate Service's own store.
    Service { exportable: bool },
    /// In a file sealed under a passphrase.
    File {
        path: PathBuf,
        passphrase: Zeroizing<String>,
    },
}

impl Keep {
    fn keeping(&self) -> Keeping {
        match self {
            Keep::Service { exportable } => Keeping {
                key_file: None,
                exportable: *exportable,
            },
            Keep::File { path, .. } => Keeping {
                key_file: Some(path.clone()),
                exportable: false,
            },
        }
    }

    /// A new key file's passphrase, as pki asks for it: twice.
    fn answers(&self) -> Vec<Zeroizing<String>> {
        match self {
            Keep::Service { .. } => Vec::new(),
            Keep::File { passphrase, .. } => vec![passphrase.clone(), passphrase.clone()],
        }
    }
}

/// Who signs a new authority's certificate.
#[derive(Debug, Clone)]
pub enum Signer {
    Root,
    /// A CA here, with its key's passphrase if it is sealed.
    Authority {
        ca: String,
        passphrase: Option<Zeroizing<String>>,
    },
    /// A CA elsewhere: the authority waits for its certificate.
    Elsewhere,
}

/// A new authority, as the Add an Authority page describes it.
#[derive(Debug, Clone)]
pub struct NewAuthority {
    pub name: String,
    pub signer: Signer,
    pub keep: Keep,
    pub algorithm: String,
    pub lifetime: u32,
    pub path_length: Option<u8>,
    pub templates: Vec<String>,
    pub crls: Vec<String>,
}

pub fn create(host: &dyn Host, new: NewAuthority) -> Result<String, String> {
    // A request for a CA elsewhere is also kept with the authority, which
    // the window saves from its page; the file pki writes isn't needed.
    let offline = std::env::temp_dir().join(format!("pki-window-{}.csr", std::process::id()));
    let _ = std::fs::remove_file(&offline);
    let mut answers = Vec::new();
    let issuer = match &new.signer {
        Signer::Root => Issuer {
            root: true,
            issuer: None,
            offline: None,
        },
        Signer::Authority { ca, passphrase } => {
            answers.extend(passphrase.clone());
            Issuer {
                root: false,
                issuer: Some(ca.clone()),
                offline: None,
            }
        }
        Signer::Elsewhere => Issuer {
            root: false,
            issuer: None,
            offline: Some(offline.clone()),
        },
    };
    answers.extend(new.keep.answers());
    let ran = run(
        host,
        Command::Ca(Ca::Create(Create {
            name: new.name.clone(),
            issuer,
            keeping: new.keep.keeping(),
            algorithm: Some(new.algorithm.clone()),
            lifetime: Some(new.lifetime),
            path_length: new.path_length,
            issuing: Issuing {
                templates: new.templates.clone(),
                crls: new.crls.clone(),
            },
            passphrase_file: None,
            issuer_passphrase_file: None,
        })),
        answers,
        "create authorities",
    );
    let _ = std::fs::remove_file(&offline);
    ran?;
    Ok(match new.signer {
        Signer::Elsewhere => format!(
            "{} created. Save its request from its page, and install the certificate it's issued.",
            new.name
        ),
        _ => format!("{} created.", new.name),
    })
}

/// An authority taken up from its certificate and sealed key file.
#[derive(Debug, Clone)]
pub struct Imported {
    pub name: String,
    pub certificate: PathBuf,
    pub sealed_key: PathBuf,
    pub passphrase: Zeroizing<String>,
    pub keep: Keep,
    pub templates: Vec<String>,
    pub crls: Vec<String>,
}

pub fn import(host: &dyn Host, imported: Imported) -> Result<String, String> {
    let mut answers = vec![imported.passphrase.clone()];
    answers.extend(imported.keep.answers());
    run(
        host,
        Command::Ca(Ca::Import(Import {
            name: imported.name.clone(),
            certificate: imported.certificate.clone(),
            sealed_key: imported.sealed_key.clone(),
            keeping: imported.keep.keeping(),
            issuing: Issuing {
                templates: imported.templates.clone(),
                crls: imported.crls.clone(),
            },
            passphrase_file: None,
            new_passphrase_file: None,
        })),
        answers,
        "import authorities",
    )?;
    Ok(format!("{} imported.", imported.name))
}

/// A template's values, as its form gives them.
#[derive(Debug, Clone, Default)]
pub struct TemplateForm {
    pub name: String,
    pub purposes: Vec<String>,
    pub key_usages: Vec<String>,
    pub lifetime: u32,
    pub renewal_window: u32,
    pub key_algorithms: Vec<String>,
    pub name_types: Vec<String>,
    pub common_name: String,
    pub issuance: String,
}

pub fn change_template(host: &dyn Host, id: &str, form: TemplateForm) -> Result<String, String> {
    run(
        host,
        Command::Template(TemplateCommand::Set {
            template: id.to_owned(),
            name: Some(form.name.clone()),
            fields: TemplateFields {
                purposes: form.purposes,
                key_usages: form.key_usages,
                lifetime: Some(form.lifetime),
                renewal_window: Some(form.renewal_window),
                key_algorithms: form.key_algorithms,
                name_types: form.name_types,
                common_name: Some(form.common_name),
                issuance: Some(form.issuance),
                enroll_security: None,
            },
        }),
        Vec::new(),
        "change templates",
    )?;
    Ok(format!("{} saved.", form.name))
}

/// Makes a template named `name`, a copy of `from`. Returns its GUID.
pub fn new_template(host: &dyn Host, name: &str, from: &str) -> Result<String, String> {
    let ran = run(
        host,
        Command::Template(TemplateCommand::Create {
            name: name.to_owned(),
            from: Some(from.to_owned()),
            fields: TemplateFields::default(),
        }),
        Vec::new(),
        "add templates",
    )?;
    ran.json["created"]["id"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| "The template was made, but pki didn't say its GUID.".to_string())
}

pub fn delete_template(host: &dyn Host, id: &str, name: &str) -> Result<String, String> {
    run(
        host,
        Command::Template(TemplateCommand::Delete {
            template: id.to_owned(),
        }),
        Vec::new(),
        "delete templates",
    )?;
    Ok(format!("{name} deleted."))
}

pub fn template_security(host: &dyn Host, id: &str, sddl: &str) -> Result<String, String> {
    run(
        host,
        Command::Template(TemplateCommand::Set {
            template: id.to_owned(),
            name: None,
            fields: TemplateFields {
                enroll_security: Some(sddl.to_owned()),
                ..TemplateFields::default()
            },
        }),
        Vec::new(),
        "change who may request from this template",
    )?;
    Ok("Permissions changed.".into())
}

/// Each warning a name command gave, after what it did.
fn with_warnings(done: &str, warnings: Vec<String>) -> String {
    let mut said = done.to_owned();
    for warning in warnings {
        said.push(' ');
        said.push_str(&sentence(&warning));
    }
    said
}

pub fn add_name(host: &dyn Host, name: &str) -> Result<String, String> {
    let ran = run(
        host,
        Command::Name(NameCommand::Add {
            name: name.to_owned(),
            owner: None,
        }),
        Vec::new(),
        "add names",
    )?;
    Ok(with_warnings(&format!("{name} added."), ran.warnings))
}

pub fn remove_name(host: &dyn Host, name: &str) -> Result<String, String> {
    run(
        host,
        Command::Name(NameCommand::Remove {
            name: name.to_owned(),
        }),
        Vec::new(),
        "remove names",
    )?;
    Ok(format!("{name} removed."))
}

/// Sets who may request `name`, as SDDL, or with `None` lets it inherit.
pub fn name_security(host: &dyn Host, name: &str, sddl: Option<&str>) -> Result<String, String> {
    let ran = run(
        host,
        Command::Name(NameCommand::SetSecurity {
            name: name.to_owned(),
            sddl: sddl.map(str::to_owned),
            inherit: sddl.is_none(),
        }),
        Vec::new(),
        "change who may request this name",
    )?;
    let done = if sddl.is_some() {
        "Permissions changed."
    } else {
        "It inherits its permissions again."
    };
    Ok(with_warnings(done, ran.warnings))
}

/// Makes `owner`, a SID, the name's owner, or with `None` leaves it none.
pub fn set_owner(host: &dyn Host, name: &str, owner: Option<&str>) -> Result<String, String> {
    let ran = run(
        host,
        Command::Name(NameCommand::SetOwner {
            name: name.to_owned(),
            owner: owner.map(str::to_owned),
            none: owner.is_none(),
        }),
        Vec::new(),
        "change who owns this name",
    )?;
    let done = if owner.is_some() {
        "Owner changed."
    } else {
        "Owner removed."
    };
    Ok(with_warnings(done, ran.warnings))
}

pub fn set_domains(host: &dyn Host, domains: Vec<String>) -> Result<String, String> {
    let none = domains.is_empty();
    run(
        host,
        Command::Name(NameCommand::Domains { domains, none }),
        Vec::new(),
        "change the principal domains",
    )?;
    Ok("Principal domains saved.".into())
}
