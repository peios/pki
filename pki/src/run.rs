//! Running pki's commands.

use std::path::Path;

use pki_keys::{KeyError, NewPassphrase};
use pki_management::provision::{Boot, Reservation};
use pki_management::security;
use pkid_core::{AuthorityInfo, Issuer, KeySpec, Passphrase, Reply, Request};
use serde_json::json;
use zeroize::Zeroizing;

use crate::cli::{self, Ca, Command};
use crate::failure::{Failure, Kind};
use crate::files::{self, Reserved};
use crate::host::Host;
use crate::secret;
use crate::show::{self, Output};
use crate::{config, enroll, issue};

pub fn run(host: &dyn Host, command: Command) -> Result<Output, Failure> {
    match command {
        Command::Setup(args) => setup(host, args.http_port),
        Command::Ca(command) => ca(host, command),
        Command::Request(command) => issue::request(host, command),
        Command::Cert(command) => issue::cert(host, command),
        Command::Enroll(enroll) => enroll::enroll(host, enroll),
        Command::Template(command) => config::template(host, command),
        Command::Name(command) => config::name(host, command),
        Command::Help { .. } => unreachable!("main prints help"),
    }
}

fn setup(host: &dyn Host, http_port: Option<u16>) -> Result<Output, Failure> {
    let refused = |error: std::io::Error| {
        let failure = Failure::io(&error).context("setup");
        if failure.kind == Kind::Denied {
            failure.hint("Run pki setup as an administrator.")
        } else {
            failure
        }
    };
    // The port first, so that setup reserves it.
    if let Some(port) = http_port {
        let mut values = pki_policy::Values::new();
        values.insert("Port", pki_policy::RegData::Dword(u32::from(port)));
        host.put(&format!("{}\\Http", pki_management::ROOT), &values, &[])
            .map_err(refused)?;
    }
    let seeded = host.setup().map_err(refused)?;
    let mut text = String::from("pkid's state directories are in place.\n");
    if !seeded.templates.is_empty() {
        text.push_str("Added the Server and Device templates.\n");
    }
    if seeded.name_roots {
        text.push_str("Added the roots of the name trees.\n");
    }
    if seeded.authorities_key {
        text.push_str("Let pkid record the CAs created through it.\n");
    }
    if seeded.http_key {
        text.push_str("Let pki-httpd read its settings.\n");
    }
    match seeded.port {
        Reservation::Added(port) => {
            text.push_str(&format!("Reserved TCP port {port} for pki-httpd.\n"));
        }
        Reservation::Present => {}
        Reservation::Taken(port) => host.warn(&format!(
            "TCP port {port} is reserved for another service, so pki-httpd can't serve CRLs on it; choose another with pki setup --http-port"
        )),
        Reservation::NoTable => host.warn(
            "this machine has no port reservation table, so pki-httpd may be unable to bind its port",
        ),
    }
    if let Some(port) = http_port {
        text.push_str(&format!(
            "pki-httpd serves revocation lists on port {port} from its next start.\n"
        ));
    }
    // pki's package defines pkid and pki-httpd to start at no time, so
    // that nothing runs until a machine is set up. A service setup has
    // just turned on is started now, since its boot trigger first fires
    // at the next boot; one that had Triggers is left as it is.
    let mut services = serde_json::Map::new();
    for service in pki_management::provision::SERVICES {
        let boot = host.start_at_boot(service).map_err(refused)?;
        let mut started = false;
        match boot {
            Boot::Added => {
                text.push_str(&format!("{service} starts at boot.\n"));
                match host.start(service) {
                    Ok(()) => {
                        text.push_str(&format!("Started {service}.\n"));
                        started = true;
                    }
                    Err(why) => host.warn(&format!(
                        "couldn't start {service}: {why}; start it with svctl start {service}"
                    )),
                }
            }
            Boot::Present => {}
            Boot::Undefined => host.warn(&format!(
                "this machine has no {service} service, so setup couldn't have it start at boot; install pki's package"
            )),
        }
        services.insert(
            service.to_owned(),
            json!({
                "boot": match boot {
                    Boot::Added => "added",
                    Boot::Present => "present",
                    Boot::Undefined => "undefined",
                },
                "started": started,
            }),
        );
    }
    Ok(Output {
        json: json!({
            "http_port": http_port,
            "templates_added": seeded.templates,
            "name_roots_added": seeded.name_roots,
            "authorities_key_added": seeded.authorities_key,
            "http_key_added": seeded.http_key,
            "services": services,
            "port_reservation": match seeded.port {
                Reservation::Added(port) => json!({"added": port}),
                Reservation::Present => json!("present"),
                Reservation::Taken(port) => json!({"taken": port}),
                Reservation::NoTable => json!("no-table"),
            },
        }),
        text,
    })
}

/// Sends `request`, naming `what` in any failure.
pub fn call(host: &dyn Host, request: &Request, what: &str) -> Result<Reply, Failure> {
    host.call(request)
        .map_err(|error| Failure::client(error).context(what))
}

pub fn unexpected(reply: &Reply, what: &str) -> Failure {
    Failure::failed(format!("pkid sent an unexpected reply: {reply:?}")).context(what)
}

fn manage(host: &dyn Host, request: &Request, what: &str) -> Result<AuthorityInfo, Failure> {
    match call(host, request, what)? {
        Reply::Authority(authority) => Ok(authority),
        other => Err(unexpected(&other, what)),
    }
}

fn authorities(host: &dyn Host) -> Result<Vec<AuthorityInfo>, Failure> {
    match call(host, &Request::Authorities, "list CAs")? {
        Reply::Authorities(authorities) => Ok(authorities),
        other => Err(unexpected(&other, "list CAs")),
    }
}

/// The CA `text` names: its ID, or a name no other CA has.
pub fn resolve_ca(host: &dyn Host, text: &str) -> Result<AuthorityInfo, Failure> {
    let all = authorities(host)?;
    if let Some(authority) = all.iter().find(|a| a.id.eq_ignore_ascii_case(text)) {
        return Ok(authority.clone());
    }
    let named: Vec<&AuthorityInfo> = all
        .iter()
        .filter(|a| a.name.to_lowercase() == text.to_lowercase())
        .collect();
    match named.as_slice() {
        [one] => Ok((*one).clone()),
        [] => Err(Failure::new(Kind::NotFound, format!("no CA '{text}'"))),
        several => Err(
            Failure::usage(format!("more than one CA is named '{text}'")).hint(format!(
                "Name the CA by its ID: {}.",
                several
                    .iter()
                    .map(|a| a.id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
        ),
    }
}

/// The GUIDs of the templates `names` names, by GUID or name.
fn resolve_templates(host: &dyn Host, names: &[String]) -> Result<Vec<String>, Failure> {
    if names.is_empty() {
        return Ok(Vec::new());
    }
    let snapshot = config::snapshot(host)?;
    names
        .iter()
        .map(|text| config::resolve_template(&snapshot, text).map(|(id, _)| id))
        .collect()
}

/// Whether using `authority`'s key takes a passphrase: a sealed file key
/// is never kept open, so every use does.
pub fn sealed(authority: &AuthorityInfo) -> bool {
    authority.key.starts_with("file:")
}

fn passphrase(text: Zeroizing<String>) -> Passphrase {
    Passphrase::new(text.as_bytes().to_vec())
}

/// A passphrase that opens something already sealed.
pub fn existing_passphrase(
    host: &dyn Host,
    file: Option<&Path>,
    question: &str,
) -> Result<Passphrase, Failure> {
    let text = match file {
        Some(path) => {
            secret::from_file(path).map_err(|error| Failure::io(&error).context(path.display()))?
        }
        None => host.prompt(question).map_err(|error| Failure::io(&error))?,
    };
    Ok(passphrase(text))
}

/// A passphrase to seal something under: asked twice on a terminal, and
/// checked here so that a weak one fails before pkid does any work.
pub fn new_passphrase(
    host: &dyn Host,
    file: Option<&Path>,
    question: &str,
) -> Result<Passphrase, Failure> {
    let text = match file {
        Some(path) => {
            secret::from_file(path).map_err(|error| Failure::io(&error).context(path.display()))?
        }
        None => {
            let first = host.prompt(question).map_err(|error| Failure::io(&error))?;
            let again = host
                .prompt("Enter it again: ")
                .map_err(|error| Failure::io(&error))?;
            if *first != *again {
                return Err(Failure::failed("the passphrases do not match"));
            }
            first
        }
    };
    match NewPassphrase::new(&text) {
        Ok(_) => Ok(passphrase(text)),
        Err(KeyError::WeakPassphrase(detail)) => Err(Failure::failed(format!(
            "the passphrase is too weak: {detail}"
        ))),
        Err(error) => Err(Failure::failed(error.to_string())),
    }
}

/// Where a new CA key goes: the absolute path of its file, if it is to be
/// kept in one. Worked out before any passphrase is asked for, as is
/// everything else a command can fail on without pkid.
fn key_file(keeping: &cli::Keeping) -> Result<Option<String>, Failure> {
    keeping.key_file.as_deref().map(files::absolute).transpose()
}

fn key_spec(
    keeping: &cli::Keeping,
    key_file: Option<String>,
    algorithm: Option<String>,
    passphrase: Option<Passphrase>,
) -> KeySpec {
    match key_file {
        // A sealed key file is itself an export, so it is always
        // exportable.
        Some(path) => KeySpec {
            provider: "file".into(),
            locator: Some(path),
            algorithm,
            exportable: true,
            passphrase,
        },
        None => KeySpec {
            provider: "service".into(),
            locator: None,
            algorithm,
            exportable: keeping.exportable,
            passphrase: None,
        },
    }
}

fn ca(host: &dyn Host, command: Ca) -> Result<Output, Failure> {
    match command {
        Ca::List => {
            let all = authorities(host)?;
            let text = if all.is_empty() {
                "No CAs. Create one with: pki ca create <name> --root\n".to_string()
            } else {
                let rows: Vec<Vec<String>> = all
                    .iter()
                    .map(|a| {
                        vec![
                            a.name.clone(),
                            a.id.clone(),
                            show::state(a).replace('-', " "),
                            show::crl_until(a),
                        ]
                    })
                    .collect();
                show::table(&["NAME", "ID", "STATE", "CRL UNTIL"], &rows)
            };
            Ok(Output {
                json: json!({"authorities": all.iter().map(show::authority_json).collect::<Vec<_>>()}),
                text,
            })
        }

        Ca::Show { ca, out } => {
            let authority = resolve_ca(host, &ca)?;
            let mut text = show::authority_text(&authority);
            let mut json = show::authority_json(&authority);
            if let Some(path) = out {
                let contents = match (&authority.certificate, &authority.request) {
                    (Some(certificate), _) => files::pem(files::CERTIFICATE, certificate),
                    (None, Some(request)) => files::pem(files::REQUEST, request),
                    (None, None) => {
                        return Err(Failure::failed("the CA has no certificate or request")
                            .context(format!("show {ca}")))
                    }
                };
                Reserved::new(&path, false)?.write(contents.as_bytes())?;
                text.push_str(&format!("\nWrote it to {}.\n", path.display()));
                json["written"] = json!(path.display().to_string());
            }
            Ok(Output { json, text })
        }

        Ca::Create(create) => {
            let what = format!("create {}", create.name);
            let templates = resolve_templates(host, &create.issuing.templates)?;
            let key_file = key_file(&create.keeping)?;
            let mut request_file = None;
            let (issuer, root) = if create.issuer.root {
                (Issuer::SelfSigned, true)
            } else if let Some(path) = &create.issuer.offline {
                request_file = Some(Reserved::new(path, false)?);
                (Issuer::Offline, false)
            } else {
                let name = create
                    .issuer
                    .issuer
                    .as_deref()
                    .expect("clap requires an issuer");
                let parent = resolve_ca(host, name)?;
                let passphrase = if sealed(&parent) {
                    Some(existing_passphrase(
                        host,
                        create.issuer_passphrase_file.as_deref(),
                        &format!("Passphrase for the key of CA {}: ", parent.name),
                    )?)
                } else {
                    None
                };
                (
                    Issuer::Authority {
                        ca: parent.id,
                        passphrase,
                    },
                    false,
                )
            };
            let seal = match &create.keeping.key_file {
                Some(path) => Some(new_passphrase(
                    host,
                    create.passphrase_file.as_deref(),
                    &format!("New passphrase for {}: ", path.display()),
                )?),
                None => None,
            };
            let key = key_spec(
                &create.keeping,
                key_file,
                Some(create.algorithm.clone().unwrap_or_else(|| {
                    if root {
                        cli::ROOT_ALGORITHM
                    } else {
                        cli::SUBORDINATE_ALGORITHM
                    }
                    .to_string()
                })),
                seal,
            );
            let lifetime_days = create.lifetime.unwrap_or(if root {
                cli::ROOT_LIFETIME_DAYS
            } else {
                cli::SUBORDINATE_LIFETIME_DAYS
            });
            let authority = manage(
                host,
                &Request::CreateAuthority {
                    name: create.name.clone(),
                    key,
                    issuer,
                    lifetime_days,
                    path_length: create.path_length,
                    templates,
                    crl_distribution_points: create.issuing.crls.clone(),
                },
                &what,
            )?;
            let mut text = format!("Created CA {} ({}).\n", authority.name, authority.id);
            let mut json = json!({"created": show::authority_json(&authority)});
            if let Some(file) = request_file {
                let request = authority.request.as_deref().ok_or_else(|| {
                    Failure::failed("pkid returned no request to have signed").context(&what)
                })?;
                let path = file.path().to_owned();
                file.write(files::pem(files::REQUEST, request).as_bytes())
                    .map_err(|failure| {
                        failure.hint(format!(
                            "The CA was created; write its request with: pki ca show {} --out <file>",
                            authority.id
                        ))
                    })?;
                text.push_str(&format!(
                    "Wrote its request to {}. Once a CA has signed it, run:\n  pki ca install {} <certificate-file>\n",
                    path.display(),
                    authority.id
                ));
                json["request_file"] = json!(path.display().to_string());
            }
            Ok(Output { json, text })
        }

        Ca::Sign {
            ca,
            request,
            name,
            lifetime,
            path_length,
            out,
            passphrase_file,
        } => {
            let what = format!("sign {}", request.display());
            let authority = resolve_ca(host, &ca)?;
            let csr = files::read_der(&request, files::REQUEST)?;
            let out = out.map(|path| Reserved::new(&path, false)).transpose()?;
            let passphrase = if sealed(&authority) {
                Some(existing_passphrase(
                    host,
                    passphrase_file.as_deref(),
                    &format!("Passphrase for the key of CA {}: ", authority.name),
                )?)
            } else {
                None
            };
            let reply = call(
                host,
                &Request::SignSubordinate {
                    ca: authority.id.clone(),
                    csr,
                    name: name.clone(),
                    lifetime_days: lifetime,
                    path_length,
                    passphrase,
                },
                &what,
            )?;
            let Reply::Signed(certificate) = reply else {
                return Err(unexpected(&reply, &what));
            };
            let pem = files::pem(files::CERTIFICATE, &certificate);
            let mut json = json!({"certificate": pem});
            let text = match out {
                Some(file) => {
                    let path = file.path().to_owned();
                    file.write(pem.as_bytes())?;
                    json["written"] = json!(path.display().to_string());
                    format!("Wrote the certificate of {name} to {}.\n", path.display())
                }
                None => pem,
            };
            Ok(Output { json, text })
        }

        Ca::Install { ca, certificate } => {
            let authority = resolve_ca(host, &ca)?;
            let certificate = files::read_der(&certificate, files::CERTIFICATE)?;
            let authority = manage(
                host,
                &Request::InstallAuthority {
                    ca: authority.id,
                    certificate,
                },
                &format!("install {ca}"),
            )?;
            Ok(Output {
                text: format!("Installed the certificate of CA {}.\n", authority.name),
                json: json!({"installed": show::authority_json(&authority)}),
            })
        }

        Ca::Import(import) => {
            let what = format!("import {}", import.name);
            let certificate = files::read_der(&import.certificate, files::CERTIFICATE)?;
            let sealed_key = files::read(&import.sealed_key)?;
            let templates = resolve_templates(host, &import.issuing.templates)?;
            let key_file = key_file(&import.keeping)?;
            let passphrase = existing_passphrase(
                host,
                import.passphrase_file.as_deref(),
                &format!("Passphrase for {}: ", import.sealed_key.display()),
            )?;
            let seal = match &import.keeping.key_file {
                Some(path) => Some(new_passphrase(
                    host,
                    import.new_passphrase_file.as_deref(),
                    &format!("New passphrase for {}: ", path.display()),
                )?),
                None => None,
            };
            let key = key_spec(&import.keeping, key_file, None, seal);
            let authority = manage(
                host,
                &Request::ImportAuthority {
                    name: import.name.clone(),
                    certificate,
                    sealed_key,
                    passphrase,
                    key,
                    templates,
                    crl_distribution_points: import.issuing.crls.clone(),
                },
                &what,
            )?;
            Ok(Output {
                text: format!("Imported CA {} ({}).\n", authority.name, authority.id),
                json: json!({"imported": show::authority_json(&authority)}),
            })
        }

        Ca::ExportKey {
            ca,
            out,
            passphrase_file,
            new_passphrase_file,
        } => {
            let what = format!("export-key {ca}");
            let authority = resolve_ca(host, &ca)?;
            let file = Reserved::new(&out, true)?;
            let current = if sealed(&authority) {
                Some(existing_passphrase(
                    host,
                    passphrase_file.as_deref(),
                    &format!("Passphrase for the key of CA {}: ", authority.name),
                )?)
            } else {
                None
            };
            let passphrase = new_passphrase(
                host,
                new_passphrase_file.as_deref(),
                &format!("Passphrase for {}: ", out.display()),
            )?;
            let reply = call(
                host,
                &Request::ExportKey {
                    ca: authority.id.clone(),
                    current,
                    passphrase,
                },
                &what,
            )?;
            let Reply::SealedKey(sealed) = reply else {
                return Err(unexpected(&reply, &what));
            };
            file.write(&sealed)?;
            Ok(Output {
                text: format!(
                    "Exported the key of CA {} to {}.\n",
                    authority.name,
                    out.display()
                ),
                json: json!({"exported": authority.id, "written": out.display().to_string()}),
            })
        }

        Ca::Set(set) => {
            let what = format!("set {}", set.ca);
            let templates = if set.no_templates {
                Some(Vec::new())
            } else if set.templates.is_empty() {
                None
            } else {
                Some(set.templates.clone())
            };
            let crls = if set.no_crls {
                Some(Vec::new())
            } else if set.crls.is_empty() {
                None
            } else {
                Some(set.crls.clone())
            };
            if templates.is_none() && crls.is_none() && set.crl_lifetime.is_none() {
                return Err(Failure::usage(format!("{what}: nothing to change")));
            }
            let authority = resolve_ca(host, &set.ca)?;
            let templates = templates
                .map(|names| resolve_templates(host, &names))
                .transpose()?;
            let authority = manage(
                host,
                &Request::ConfigureAuthority {
                    ca: authority.id,
                    templates,
                    crl_distribution_points: crls,
                    crl_lifetime_days: set.crl_lifetime,
                },
                &what,
            )?;
            Ok(Output {
                text: show::authority_text(&authority),
                json: json!({"changed": show::authority_json(&authority)}),
            })
        }

        Ca::Creators { set } => {
            let settings = format!("{}\\Settings", pki_management::ROOT);
            let (security, own) = match set {
                Some(text) => {
                    let security = config::parse_sddl(&text)?;
                    let has_dacl = peios::security::SdView::parse(&security)
                        .is_ok_and(|view| view.dacl().is_some());
                    if !has_dacl {
                        return Err(Failure::usage(
                            "creators: the descriptor needs an access list; without one, everyone could create CAs",
                        ));
                    }
                    let mut values = pki_policy::Values::new();
                    values.insert(
                        "ManageSecurity",
                        pki_policy::RegData::Binary(security.clone()),
                    );
                    host.put(&settings, &values, &[]).map_err(|error| {
                        let failure = Failure::io(&error).context("creators");
                        if failure.kind == Kind::Denied {
                            failure.hint("Only an administrator can change pki's configuration.")
                        } else {
                            failure
                        }
                    })?;
                    for warning in security::broad_creators(&security).unwrap_or_default() {
                        host.warn(&warning);
                    }
                    (security, true)
                }
                None => {
                    let snapshot = config::snapshot(host)?;
                    match snapshot.settings.binary("ManageSecurity").ok().flatten() {
                        Some(security) => (security.to_vec(), true),
                        None => (config::parse_sddl(pki_policy::DEFAULT_MANAGE_SDDL)?, false),
                    }
                }
            };
            let text = config::sddl_text(&security);
            Ok(Output {
                text: format!(
                    "Who can create and import CAs: {text}{}\n",
                    if own { "" } else { " (the default)" }
                ),
                json: json!({"security": text, "default": !own}),
            })
        }

        Ca::SetSecurity { ca, sddl } => {
            let what = format!("set-security {ca}");
            let security = config::parse_sddl(&sddl)?;
            let authority = resolve_ca(host, &ca)?;
            let authority = manage(
                host,
                &Request::SetAuthoritySecurity {
                    ca: authority.id,
                    security: security.clone(),
                },
                &what,
            )?;
            for warning in security::broad_ca_grants(&security).unwrap_or_default() {
                host.warn(&warning);
            }
            if authority.granted & show::MANAGE == 0 {
                host.warn("you can no longer manage this CA");
            }
            Ok(Output {
                text: show::authority_text(&authority),
                json: json!({"changed": show::authority_json(&authority)}),
            })
        }

        Ca::PublishCrl {
            ca,
            passphrase_file,
        } => {
            let what = format!("publish-crl {ca}");
            let authority = resolve_ca(host, &ca)?;
            let passphrase = if sealed(&authority) {
                Some(existing_passphrase(
                    host,
                    passphrase_file.as_deref(),
                    &format!("Passphrase for the key of CA {}: ", authority.name),
                )?)
            } else {
                None
            };
            let reply = call(
                host,
                &Request::PublishCrl {
                    ca: authority.id.clone(),
                    passphrase,
                },
                &what,
            )?;
            let Reply::Crl(crl) = reply else {
                return Err(unexpected(&reply, &what));
            };
            Ok(Output {
                text: format!(
                    "Published CRL {} of CA {}, valid until {}.\n",
                    crl.number,
                    authority.name,
                    show::time(crl.next_update)
                ),
                json: json!({
                    "ca": authority.id,
                    "number": crl.number,
                    "this_update": show::time(crl.this_update),
                    "next_update": show::time(crl.next_update),
                }),
            })
        }
    }
}
