//! What the window does when the person acts: the questions it asks first,
//! the files it asks for, and the changes it hands to `act` to make.
//!
//! Every passphrase and password field is cleared as soon as it is used,
//! when the person cancels, and whenever the page changes: a field's value
//! goes to every page showing the window, and stays in the process.

use std::path::{Path, PathBuf};

use gxwi::Fields;
use gxwi_file_dialog::{Filter, Mode, Request as Choose};
use zeroize::Zeroizing;

use super::act::{self, Enrolled, Enrolment};
use super::held::{self, Held};
use super::{enrol, Page, Window};
use crate::files::{self, Reserved};
use crate::host::Live;

/// A question open under the row it is about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Asking {
    /// Why a request is denied.
    Deny { ca: String, id: i64 },
    /// Why a certificate is revoked.
    Revoke { ca: String, serial: String },
    /// The passphrase of a CA's sealed key, to publish its revocation list.
    Publish { ca: String },
    /// The file's password, to save a held request's certificate.
    Collect { ca: String, id: i64 },
    /// Whether to delete a template.
    DeleteTemplate { id: String },
    /// The name and model of a new template.
    NewTemplate,
    /// A name to add to a tree.
    AddName,
    /// Whether to remove a name.
    RemoveName { name: String },
    /// Whether a name drops its own permissions to inherit again.
    Inherit { name: String },
    /// A name's new owner.
    Owner { name: String },
}

/// The fields that hold secrets.
pub const SECRETS: [&str; 11] = [
    "passphrase",
    "enrol-password",
    "enrol-confirm",
    "new-issuer-passphrase",
    "new-import-passphrase",
    "new-passphrase",
    "new-confirm",
    "sign-passphrase",
    "key-current",
    "key-new",
    "key-confirm",
];

/// Clears every secret the person typed.
pub fn forget(fields: &mut Fields) {
    for name in SECRETS {
        if !fields.get(name).is_empty() {
            fields.set(name, "");
        }
    }
}

/// Takes a secret out of its field, leaving the field empty.
fn take(fields: &mut Fields, name: &str) -> Zeroizing<String> {
    let secret = Zeroizing::new(fields.get(name).to_owned());
    fields.set(name, "");
    secret
}

/// Names typed into one field: separated by commas or spaces.
pub fn names(text: &str) -> Vec<String> {
    text.split([',', ' ', '\n', '\t'])
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .collect()
}

fn home() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_dir())
}

/// Writes `contents` to `path`, replacing what is there only once written.
fn save(path: &Path, contents: &[u8]) -> Result<(), String> {
    Reserved::replacing(path, false)
        .and_then(|file| file.write(contents))
        .map_err(|failure| act::failed("save the file", &failure))
}

impl Window {
    pub(super) fn ask(&mut self, asking: Asking, fields: &mut Fields) {
        forget(fields);
        fields.set("deny-reason", "");
        fields.set("revoke-reason", "unspecified");
        self.asking = Some(asking);
        self.said = None;
    }

    pub(super) fn cancel(&mut self, fields: &mut Fields) {
        forget(fields);
        self.asking = None;
    }

    pub(super) fn approve(&mut self, ca: String, id: i64, fields: &mut Fields) {
        let back = matches!(self.page, Page::Request { .. }).then_some(Page::Requests);
        self.launch(
            Box::new(move || act::approve(&Live::new(), &ca, id)),
            back,
            fields,
        );
    }

    pub(super) fn deny(&mut self, fields: &mut Fields) {
        let Some(Asking::Deny { ca, id }) = self.asking.take() else {
            return;
        };
        let reason = fields.get("deny-reason").to_owned();
        let back = matches!(self.page, Page::Request { .. }).then_some(Page::Requests);
        self.launch(
            Box::new(move || act::deny(&Live::new(), &ca, id, &reason)),
            back,
            fields,
        );
    }

    pub(super) fn revoke(&mut self, fields: &mut Fields) {
        let Some(Asking::Revoke { ca, serial }) = self.asking.take() else {
            return;
        };
        let reason = match fields.get("revoke-reason") {
            "" => "unspecified".to_owned(),
            chosen => chosen.to_owned(),
        };
        self.launch(
            Box::new(move || act::revoke(&Live::new(), &ca, &serial, &reason)),
            None,
            fields,
        );
    }

    /// Publishes a CA's revocation list: at once for a key pkid keeps, or
    /// once its passphrase is typed for a sealed one.
    pub(super) fn publish(&mut self, ca: String, fields: &mut Fields) {
        let sealed = self.seen.authority(&ca).is_some_and(crate::run::sealed);
        if sealed && self.asking != Some(Asking::Publish { ca: ca.clone() }) {
            self.ask(Asking::Publish { ca }, fields);
            return;
        }
        let passphrase = sealed.then(|| take(fields, "passphrase"));
        if passphrase.as_ref().is_some_and(|p| p.is_empty()) {
            self.said = Some(Err("Type the key's passphrase first.".into()));
            return;
        }
        self.asking = None;
        self.launch(
            Box::new(move || act::publish(&Live::new(), &ca, passphrase)),
            None,
            fields,
        );
    }

    pub(super) fn collect(&mut self, fields: &mut Fields) {
        let Some(Asking::Collect { ca, id }) = self.asking.clone() else {
            return;
        };
        let password = take(fields, "passphrase");
        if password.is_empty() {
            self.said = Some(Err("Type the file's password first.".into()));
            return;
        }
        let Some(held) = self
            .seen
            .held
            .iter()
            .find(|h| h.ca == ca && h.request == id)
            .cloned()
        else {
            return;
        };
        self.asking = None;
        self.launch(
            Box::new(move || {
                let said = act::collect(
                    &Live::new(),
                    &held.ca,
                    held.request,
                    held.key.clone(),
                    held.out.clone(),
                    password,
                )?;
                // Saved: the window no longer needs to remember it.
                let _ = held::forget(&held.ca, held.request);
                Ok(format!(
                    "{said} The key file {} is no longer needed once the file is imported.",
                    held.key.display()
                ))
            }),
            None,
            fields,
        );
    }

    /// Forgets a held request the window remembered, such as one denied.
    pub(super) fn forget_held(&mut self, ca: String, id: i64, fields: &mut Fields) {
        self.launch(
            Box::new(move || held::forget(&ca, id).map(|()| format!("Request #{id} forgotten."))),
            None,
            fields,
        );
    }

    pub(super) fn setup(&mut self, fields: &mut Fields) {
        self.launch(
            Box::new(|| act::setup(&Live::new())),
            Some(Page::Overview),
            fields,
        );
    }

    /// Requests a certificate as the form says.
    pub(super) fn enrol(&mut self, fields: &mut Fields) {
        let refuse = |w: &mut Window, fields: &mut Fields, why: &str| {
            forget(fields);
            w.said = Some(Err(why.to_owned()));
        };
        let Some(authority) = enrol::chosen_ca(self, fields).cloned() else {
            return;
        };
        let Some(template) = enrol::chosen_template(&authority, fields).cloned() else {
            return;
        };
        let out = fields.get("enrol-out").trim().to_owned();
        if out.is_empty() {
            return refuse(self, fields, "Choose where to save it first.");
        }
        let out = PathBuf::from(out);
        if !out.is_absolute() {
            return refuse(
                self,
                fields,
                "Give the full path of the file to save, such as /home/alice/www.p12.",
            );
        }
        if fields.get("enrol-key") == "own" {
            let csr = PathBuf::from(fields.get("enrol-csr").trim());
            if csr.as_os_str().is_empty() {
                return refuse(self, fields, "Choose the request file first.");
            }
            let ca = authority.id.clone();
            let id = template.id.clone();
            self.launch(
                Box::new(move || {
                    let (request, certificate) = act::submit(&Live::new(), &ca, &id, csr)?;
                    match certificate {
                        Some(pem) => {
                            save(&out, pem.as_bytes())?;
                            Ok(format!("Request #{request} issued. Saved to {}.", out.display()))
                        }
                        None => Ok(format!(
                            "Request #{request} is waiting for an officer. Export its certificate from Certificates once it is issued."
                        )),
                    }
                }),
                None,
                fields,
            );
            return;
        }
        let mut dns = Vec::new();
        let mut emails = Vec::new();
        let mut upns = Vec::new();
        dns.extend(names(fields.get("enrol-dns")));
        emails.extend(names(fields.get("enrol-email")));
        upns.extend(names(fields.get("enrol-upn")));
        if dns.is_empty() && emails.is_empty() && upns.is_empty() {
            return refuse(self, fields, "Give at least one name for the certificate.");
        }
        if fields.get("enrol-password").is_empty() {
            return refuse(self, fields, "Choose a password for the file.");
        }
        if fields.get("enrol-password").chars().count() < pki_keys::MIN_PASSPHRASE_CHARS {
            return refuse(
                self,
                fields,
                &format!(
                    "The password needs at least {} characters.",
                    pki_keys::MIN_PASSPHRASE_CHARS
                ),
            );
        }
        if fields.get("enrol-password") != fields.get("enrol-confirm") {
            return refuse(self, fields, "The passwords don't match.");
        }
        let password = take(fields, "enrol-password");
        fields.set("enrol-confirm", "");
        let algorithms = enrol::algorithms(enrol::template_values(self, &template.id));
        let algorithm = match fields.get("enrol-algorithm") {
            chosen if algorithms.iter().any(|(id, _)| id == chosen) => chosen.to_owned(),
            _ => algorithms
                .first()
                .map(|(id, _)| id.clone())
                .unwrap_or_else(|| "ecdsa-p256".into()),
        };
        let enrolment = Enrolment {
            ca: authority.id.clone(),
            template: template.id.clone(),
            dns,
            emails,
            upns,
            algorithm,
            out: out.clone(),
        };
        self.launch(
            Box::new(move || match act::enrol(&Live::new(), &enrolment, password)? {
                Enrolled::Saved => Ok(format!("Saved to {}.", out.display())),
                Enrolled::Held { request, key } => {
                    let remembered = held::remember(Held {
                        ca: enrolment.ca.clone(),
                        request,
                        out: out.clone(),
                        key: key.clone(),
                    });
                    let mut said = format!(
                        "Request #{request} is waiting for an officer. Its key is kept in {} until then.",
                        key.display()
                    );
                    match remembered {
                        Ok(()) => said.push_str(" Requests shows when it's ready to save."),
                        Err(_) => said.push_str(&format!(
                            " Save it later with: pki enroll {} --request {request} --key {} --out {}",
                            enrolment.ca,
                            key.display(),
                            out.display()
                        )),
                    }
                    Ok(said)
                }
            }),
            None,
            fields,
        );
    }

    /// Opens the file dialog, and hands what is chosen to `then`.
    fn choose(
        &mut self,
        request: Choose,
        then: impl FnOnce(&mut Window, &mut Fields, PathBuf) + Send + 'static,
    ) {
        if self.choosing {
            return;
        }
        let surface = self.surface.clone();
        let opened = gxwi_file_dialog::choose(&request, move |chosen| {
            let Some(surface) = surface.upgrade() else {
                return;
            };
            surface.update(|w, fields| {
                w.choosing = false;
                if let Some(path) = chosen {
                    then(w, fields, path);
                }
            });
        });
        match opened {
            Ok(()) => self.choosing = true,
            Err(error) => self.said = Some(Err(format!("The file dialog couldn't open: {error}."))),
        }
    }

    /// Chooses where the form saves the certificate.
    pub(super) fn choose_out(&mut self, fields: &Fields) {
        let own = fields.get("enrol-key") == "own";
        let typed = PathBuf::from(fields.get("enrol-out").trim());
        let names = names(fields.get("enrol-dns"));
        let suggested = names
            .first()
            .cloned()
            .unwrap_or_else(|| "certificate".into());
        let request = Choose {
            mode: Mode::Save,
            title: if own {
                "Save the Certificate".into()
            } else {
                "Save the Key and Certificate".into()
            },
            purpose: Some(if own {
                "The certificate is saved here once it is issued.".into()
            } else {
                "The key, its certificate and the authorities above it are saved here, protected by the password you choose.".into()
            }),
            folder: typed
                .parent()
                .map(Path::to_path_buf)
                .filter(|p| p.is_dir())
                .or_else(home),
            name: Some(if own {
                format!("{suggested}.pem")
            } else {
                format!("{suggested}.p12")
            }),
            filters: vec![if own {
                Filter {
                    name: "Certificates".into(),
                    extensions: vec!["pem".into(), "crt".into(), "cer".into()],
                }
            } else {
                Filter {
                    name: "PKCS #12 files".into(),
                    extensions: vec!["p12".into(), "pfx".into()],
                }
            }],
        };
        self.choose(request, |_, fields, path| {
            fields.set("enrol-out", &path.display().to_string());
        });
    }

    /// Chooses a request made elsewhere for the form.
    pub(super) fn choose_csr(&mut self) {
        let request = Choose {
            mode: Mode::Open,
            title: "Choose a Certificate Request".into(),
            purpose: Some("A request made by another program, in PEM or DER.".into()),
            folder: home(),
            name: None,
            filters: vec![Filter {
                name: "Certificate requests".into(),
                extensions: vec!["csr".into(), "req".into(), "pem".into()],
            }],
        };
        self.choose(request, |_, fields, path| {
            fields.set("enrol-csr", &path.display().to_string());
        });
    }

    /// Saves `der`, in PEM under `label`, where the person chooses.
    pub(super) fn export(&mut self, title: &str, name: &str, label: &'static str, der: Vec<u8>) {
        let request = Choose {
            mode: Mode::Save,
            title: title.into(),
            purpose: None,
            folder: home(),
            name: Some(name.into()),
            filters: vec![Filter {
                name: if label == files::REQUEST {
                    "Certificate requests".into()
                } else {
                    "Certificates".into()
                },
                extensions: vec!["pem".into(), "crt".into(), "csr".into()],
            }],
        };
        self.choose(request, move |w, _, path| {
            let pem = files::pem(label, &der);
            w.said =
                Some(save(&path, pem.as_bytes()).map(|()| format!("Saved to {}.", path.display())));
        });
    }
}

/// What a chooser button is for: how the dialog asks, and what it offers.
fn chooser(purpose: &str, typed: &str) -> Option<Choose> {
    let (mode, title, extensions, kind, name): (Mode, &str, &[&str], &str, Option<&str>) =
        match purpose {
            "open-certificate" => (
                Mode::Open,
                "Choose the Authority's Certificate",
                &["pem", "crt", "cer", "der"],
                "Certificates",
                None,
            ),
            "open-key" => (
                Mode::Open,
                "Choose the Sealed Key File",
                &["key"],
                "Sealed key files",
                None,
            ),
            "open-request" => (
                Mode::Open,
                "Choose the Subordinate's Request",
                &["csr", "req", "pem"],
                "Certificate requests",
                None,
            ),
            "save-key" => (
                Mode::Save,
                "Choose Where the Key Is Kept",
                &["key"],
                "Sealed key files",
                Some("authority.key"),
            ),
            "save-certificate" => (
                Mode::Save,
                "Save the Certificate",
                &["pem", "crt"],
                "Certificates",
                Some("subordinate.pem"),
            ),
            "save-export" => (
                Mode::Save,
                "Save the Key",
                &["key"],
                "Sealed key files",
                Some("authority.key"),
            ),
            _ => return None,
        };
    let typed = PathBuf::from(typed.trim());
    Some(Choose {
        mode,
        title: title.into(),
        purpose: None,
        folder: typed
            .parent()
            .map(Path::to_path_buf)
            .filter(|p| p.is_dir())
            .or_else(home),
        name: name.map(str::to_owned),
        filters: vec![Filter {
            name: kind.into(),
            extensions: extensions.iter().map(|e| e.to_string()).collect(),
        }],
    })
}

/// A whole number typed into a field, within `range`.
fn number(fields: &Fields, name: &str, range: std::ops::RangeInclusive<u32>) -> Option<u32> {
    fields
        .get(name)
        .trim()
        .parse()
        .ok()
        .filter(|n| range.contains(n))
}

/// A path typed into a field, if it is a full one.
fn full_path(fields: &Fields, name: &str) -> Option<PathBuf> {
    let path = PathBuf::from(fields.get(name).trim());
    path.is_absolute().then_some(path)
}

impl Window {
    /// Chooses a file for the field a Choose… button names.
    pub(super) fn choose_for(&mut self, field: String, purpose: &str, fields: &Fields) {
        let Some(request) = chooser(purpose, fields.get(&field)) else {
            return;
        };
        self.choose(request, move |_, fields, path| {
            fields.set(&field, &path.display().to_string());
        });
    }

    /// Saves what an authority issues, from the Issuing form.
    pub(super) fn issuing(&mut self, ca: String, fields: &mut Fields) {
        let templates = super::manage::ticked(self, fields, "iss-");
        let crls = super::manage::addresses(fields.get("iss-crls"));
        let Some(lifetime) = number(fields, "iss-lifetime", 1..=3650) else {
            self.said = Some(Err(
                "The revocation list lifetime is a number of days, from 1 to 3650.".into(),
            ));
            return;
        };
        // Opening the page again fills the form with what was saved.
        let page = Some(self.page.clone());
        self.launch(
            Box::new(move || act::configure(&Live::new(), &ca, templates, crls, Some(lifetime))),
            page,
            fields,
        );
    }

    /// Where a new or imported authority's key goes, from the form.
    fn keep(&self, fields: &mut Fields) -> Result<act::Keep, String> {
        if fields.get("new-keep") != "file" {
            return Ok(act::Keep::Service {
                exportable: fields.get("new-exportable") == "on",
            });
        }
        let Some(path) = full_path(fields, "new-key-file") else {
            return Err("Choose where the key file is kept, as a full path.".into());
        };
        let passphrase = take(fields, "new-passphrase");
        let confirm = take(fields, "new-confirm");
        if passphrase.chars().count() < pki_keys::MIN_PASSPHRASE_CHARS {
            return Err(format!(
                "The key's passphrase needs at least {} characters.",
                pki_keys::MIN_PASSPHRASE_CHARS
            ));
        }
        if *passphrase != *confirm {
            return Err("The passphrases don't match.".into());
        }
        Ok(act::Keep::File { path, passphrase })
    }

    /// Creates or imports an authority, from the Add an Authority form.
    pub(super) fn create(&mut self, fields: &mut Fields) {
        let name = fields.get("new-name").trim().to_owned();
        if name.is_empty() {
            forget(fields);
            self.said = Some(Err("Give the authority a name.".into()));
            return;
        }
        let templates = super::manage::ticked(self, fields, "new-tpl-");
        let crls = super::manage::addresses(fields.get("new-crls"));
        let kind = fields.get("new-kind").to_owned();
        let keep = match self.keep(fields) {
            Ok(keep) => keep,
            Err(why) => {
                forget(fields);
                self.said = Some(Err(why));
                return;
            }
        };
        let work: super::Work = if kind == "import" {
            let (Some(certificate), Some(sealed_key)) = (
                full_path(fields, "new-certificate"),
                full_path(fields, "new-sealed"),
            ) else {
                forget(fields);
                self.said = Some(Err("Choose the certificate and the sealed key file.".into()));
                return;
            };
            let passphrase = take(fields, "new-import-passphrase");
            let imported = act::Imported {
                name: name.clone(),
                certificate,
                sealed_key,
                passphrase,
                keep,
                templates,
                crls,
            };
            Box::new(move || act::import(&Live::new(), imported))
        } else {
            let signer = match kind.as_str() {
                "under" => {
                    let issuer = fields.get("new-issuer").to_owned();
                    let issuer = if issuer.is_empty() {
                        self.seen
                            .authorities()
                            .iter()
                            .find(|a| {
                                a.granted & crate::show::MANAGE != 0 && a.certificate.is_some()
                            })
                            .map(|a| a.id.clone())
                            .unwrap_or_default()
                    } else {
                        issuer
                    };
                    let sealed = self.seen.authority(&issuer).is_some_and(crate::run::sealed);
                    act::Signer::Authority {
                        ca: issuer,
                        passphrase: sealed.then(|| take(fields, "new-issuer-passphrase")),
                    }
                }
                "elsewhere" => act::Signer::Elsewhere,
                _ => act::Signer::Root,
            };
            let Some(lifetime) = number(fields, "new-lifetime", 1..=36_500) else {
                forget(fields);
                self.said = Some(Err("The lifetime is a number of days.".into()));
                return;
            };
            let new = act::NewAuthority {
                name: name.clone(),
                signer,
                keep,
                algorithm: match fields.get("new-algorithm") {
                    "" => crate::cli::ROOT_ALGORITHM.to_owned(),
                    chosen => chosen.to_owned(),
                },
                lifetime,
                path_length: fields.get("new-path").parse().ok(),
                templates,
                crls,
            };
            Box::new(move || act::create(&Live::new(), new))
        };
        forget(fields);
        self.launch(work, Some(Page::Overview), fields);
    }

    /// Signs a subordinate authority's request, and saves its certificate.
    pub(super) fn sign(&mut self, ca: String, fields: &mut Fields) {
        let refuse = |w: &mut Window, fields: &mut Fields, why: &str| {
            forget(fields);
            w.said = Some(Err(why.into()));
        };
        let (Some(request), Some(out)) = (
            full_path(fields, "sign-request"),
            full_path(fields, "sign-out"),
        ) else {
            return refuse(
                self,
                fields,
                "Choose the request, and where to save the certificate.",
            );
        };
        let name = fields.get("sign-name").trim().to_owned();
        if name.is_empty() {
            return refuse(self, fields, "Give the subordinate authority's name.");
        }
        let Some(lifetime) = number(fields, "sign-lifetime", 1..=36_500) else {
            return refuse(self, fields, "The lifetime is a number of days.");
        };
        let path_length = fields.get("sign-path").parse().ok();
        let sealed = self.seen.authority(&ca).is_some_and(crate::run::sealed);
        let passphrase = sealed.then(|| take(fields, "sign-passphrase"));
        self.launch(
            Box::new(move || {
                let pem = act::sign(
                    &Live::new(),
                    &ca,
                    request,
                    &name,
                    lifetime,
                    path_length,
                    passphrase,
                )?;
                save(&out, pem.as_bytes())?;
                Ok(format!(
                    "Signed. The certificate is saved to {}.",
                    out.display()
                ))
            }),
            None,
            fields,
        );
    }

    /// Exports an authority's key, from the Export Key form.
    pub(super) fn export_key(&mut self, ca: String, fields: &mut Fields) {
        let Some(out) = full_path(fields, "key-out") else {
            forget(fields);
            self.said = Some(Err("Choose where to save the key, as a full path.".into()));
            return;
        };
        let sealed = self.seen.authority(&ca).is_some_and(crate::run::sealed);
        let current = sealed.then(|| take(fields, "key-current"));
        let passphrase = take(fields, "key-new");
        let confirm = take(fields, "key-confirm");
        if passphrase.chars().count() < pki_keys::MIN_PASSPHRASE_CHARS {
            self.said = Some(Err(format!(
                "The new passphrase needs at least {} characters.",
                pki_keys::MIN_PASSPHRASE_CHARS
            )));
            return;
        }
        if *passphrase != *confirm {
            self.said = Some(Err("The passphrases don't match.".into()));
            return;
        }
        let back = Some(Page::Authority(ca.clone()));
        self.launch(
            Box::new(move || act::export_key(&Live::new(), &ca, out, current, passphrase)),
            back,
            fields,
        );
    }

    /// Installs the certificate an authority waits for, once chosen.
    pub(super) fn install(&mut self, ca: String) {
        let request = Choose {
            mode: Mode::Open,
            title: "Choose the Authority's Certificate".into(),
            purpose: Some(
                "The certificate issued for this authority's request, in PEM or DER.".into(),
            ),
            folder: home(),
            name: None,
            filters: vec![Filter {
                name: "Certificates".into(),
                extensions: vec!["pem".into(), "crt".into(), "cer".into(), "der".into()],
            }],
        };
        self.choose(request, move |w, fields, path| {
            w.launch(
                Box::new(move || act::install(&Live::new(), &ca, path)),
                None,
                fields,
            );
        });
    }
}

impl Window {
    pub(super) fn save_template(&mut self, fields: &mut Fields) {
        let Page::Template(id) = &self.page else {
            return;
        };
        let id = id.clone();
        let Some(values) = self
            .seen
            .config
            .as_ref()
            .ok()
            .and_then(|config| config.templates.iter().find(|(guid, _)| *guid == id))
            .map(|(_, values)| values.clone())
        else {
            return;
        };
        match super::templates::read(&values, fields) {
            Ok(form) => {
                let page = Some(self.page.clone());
                self.launch(
                    Box::new(move || act::change_template(&Live::new(), &id, form)),
                    page,
                    fields,
                )
            }
            Err(why) => self.said = Some(Err(why)),
        }
    }

    pub(super) fn new_template(&mut self, fields: &mut Fields) {
        let name = fields.get("new-template-name").trim().to_owned();
        if name.is_empty() {
            self.said = Some(Err("Give the template a name.".into()));
            return;
        }
        let from = match fields.get("new-template-from") {
            "" => self
                .seen
                .config
                .as_ref()
                .ok()
                .and_then(|config| config.templates.first())
                .map(|(id, _)| id.clone())
                .unwrap_or_default(),
            chosen => chosen.to_owned(),
        };
        self.asking = None;
        self.launch_then(
            Box::new(move || {
                let id = act::new_template(&Live::new(), &name, &from)?;
                Ok((format!("{name} added."), Some(Page::Template(id))))
            }),
            fields,
        );
    }

    pub(super) fn delete_template(&mut self, fields: &mut Fields) {
        let Some(Asking::DeleteTemplate { id }) = self.asking.take() else {
            return;
        };
        let name = self
            .seen
            .config
            .as_ref()
            .ok()
            .and_then(|config| config.templates.iter().find(|(guid, _)| *guid == id))
            .map(|(_, values)| super::templates::name(values))
            .unwrap_or_else(|| "The template".into());
        self.launch(
            Box::new(move || act::delete_template(&Live::new(), &id, &name)),
            Some(Page::Templates),
            fields,
        );
    }

    pub(super) fn add_name(&mut self, fields: &mut Fields) {
        let name = fields.get("add-name").trim().to_lowercase();
        if let Err(why) = pki_management::names::NamePath::parse(&name) {
            self.said = Some(Err(super::service::sentence(&why)));
            return;
        }
        self.asking = None;
        let page = Page::Name(name.clone());
        self.launch(
            Box::new(move || act::add_name(&Live::new(), &name)),
            Some(page),
            fields,
        );
    }

    pub(super) fn remove_name(&mut self, fields: &mut Fields) {
        let Some(Asking::RemoveName { name }) = self.asking.take() else {
            return;
        };
        self.launch(
            Box::new(move || act::remove_name(&Live::new(), &name)),
            Some(Page::Names),
            fields,
        );
    }

    pub(super) fn inherit(&mut self, fields: &mut Fields) {
        let Some(Asking::Inherit { name }) = self.asking.take() else {
            return;
        };
        self.launch(
            Box::new(move || act::name_security(&Live::new(), &name, None)),
            None,
            fields,
        );
    }

    /// Sets a name's owner from what was typed: an account's name, which
    /// authd turns into its SID, or a SID. `none` removes it.
    pub(super) fn set_owner(&mut self, none: bool, fields: &mut Fields) {
        let Some(Asking::Owner { name }) = self.asking.clone() else {
            return;
        };
        let typed = fields.get("owner").trim().to_owned();
        if !none && typed.is_empty() {
            self.said = Some(Err("Type the account that is to own it.".into()));
            return;
        }
        self.asking = None;
        self.launch(
            Box::new(move || {
                if none {
                    return act::set_owner(&Live::new(), &name, None);
                }
                let sid = if typed.parse::<peios::security::Sid>().is_ok() {
                    typed.clone()
                } else {
                    super::seen::account(&typed)
                        .map_err(|why| format!("Accounts can't be looked up now: {why}."))?
                        .ok_or_else(|| format!("There is no account called {typed}."))?
                };
                act::set_owner(&Live::new(), &name, Some(&sid))
            }),
            None,
            fields,
        );
    }

    pub(super) fn save_domains(&mut self, fields: &mut Fields) {
        let domains = names(fields.get("domains"));
        self.launch(
            Box::new(move || act::set_domains(&Live::new(), domains)),
            Some(Page::Names),
            fields,
        );
    }
}

impl Window {
    /// Has pki-httpd serve on the port typed, and restarts it if it runs
    /// and the person may.
    pub(super) fn save_http_port(&mut self, fields: &mut Fields) {
        let Some(port) = fields
            .get("http-port")
            .trim()
            .parse::<u16>()
            .ok()
            .filter(|p| *p > 0)
        else {
            self.said = Some(Err("The port is a number from 1 to 65535.".into()));
            return;
        };
        let restart = self.seen.httpd_service.running()
            && self
                .seen
                .httpd_service
                .allows(peinit::client::Command::Restart);
        self.launch(
            Box::new(move || {
                let mut said = act::set_http_port(&Live::new(), port)?;
                if restart {
                    match super::service::command(
                        super::service::HTTPD,
                        peinit::client::Command::Restart,
                    ) {
                        Ok(()) => said.push_str(" Revocation Publishing restarted."),
                        Err(why) => said
                            .push_str(&format!(" Restart Revocation Publishing to use it: {why}")),
                    }
                } else {
                    said.push_str(" Revocation Publishing uses it from its next start.");
                }
                Ok(said)
            }),
            Some(Page::Overview),
            fields,
        );
    }
}
