//! The overview: whether the CA runs, what needs attention, and the two
//! services. Before `pki setup`, the page to set it up.

use gxwi::settings::{self, Glyph, Kind, Tile, Tone, Width};
use peinit::client::Command;

use super::seen::Trouble;
use super::service::{self, Run, Service};
use super::{describe, words, Window};
use crate::show::{self, OFFICER, READ};

/// The CA's state in a few words, under its name in the side.
pub fn summary(window: &Window) -> String {
    if !window.seen.set_up {
        return "Not set up".to_string();
    }
    match &window.seen.pkid {
        Err(Trouble::Down) => "Not running".to_string(),
        Err(_) => "Not issuing".to_string(),
        Ok(pkid) => {
            let waiting = officer_waiting(window);
            if waiting > 0 {
                format!("{} waiting", words::count(waiting as i64, "request"))
            } else {
                format!(
                    "Running · {}",
                    words::count(pkid.authorities.len() as i64, "authority")
                )
            }
        }
    }
}

/// How many requests wait for an officer at CAs where the person is one.
pub fn officer_waiting(window: &Window) -> usize {
    window
        .seen
        .authorities()
        .iter()
        .filter(|a| a.granted & OFFICER != 0 && a.granted & READ != 0)
        .map(|a| window.seen.waiting.get(&a.id).map_or(0, Vec::len))
        .sum()
}

fn setup_page(window: &Window) -> String {
    let mut page = settings::head(
        Glyph::Certificate,
        Tile::Red,
        "Certificate Authority",
        "Issue certificates for this network's servers, devices and people.",
    );
    page.push_str(&settings::group(
        "",
        &settings::row(
            "Not Set Up",
            "This machine doesn't run a certificate authority yet.",
            &settings::button(
                "Set Up",
                "setup",
                &[],
                Kind::Primary,
                window.seen.may.setup && !window.busy,
            ),
        ),
        "",
    ));
    let rows = [
        ("Templates", "Server and Device, the two kinds of certificate most networks need."),
        ("Names", "Who may request certificates for which names. At first, each account its own, and administrators any."),
        ("Storage", "Where the Certificate Service keeps its keys and records, readable by it alone."),
        ("Revocation Publishing", "A web address other devices check revocation lists at, reserved for it."),
        ("Services", "The Certificate Service and Revocation Publishing, started now and at every boot."),
    ]
    .iter()
    .map(|(label, about)| settings::row(label, about, ""))
    .collect::<String>();
    page.push_str(&settings::group(
        "What Set Up Adds",
        &rows,
        &if window.seen.may.setup {
            settings::note(
                "Then create an authority: a root, and usually an issuing authority under it.",
            )
        } else {
            settings::locked(
                "You don't have permission to set up the certificate authority. Ask an administrator to set it up.",
            )
        },
    ));
    page
}

/// A service's row: its state in words, and the controls the person may
/// use.
fn service_row(window: &Window, title: &str, about: &str, name: &str, service: &Service) -> String {
    let enabled = !window.busy;
    let (state, controls) = match service {
        Service::Undefined => (
            "Not installed on this machine.".to_string(),
            settings::pill("Not Installed", Tone::Plain),
        ),
        Service::Unknown(why) => (service::sentence(why), String::new()),
        Service::Known { state, .. } => {
            let text = match state {
                Run::Running => format!("Running. {about}"),
                Run::Starting => "Starting…".to_string(),
                Run::Stopping => "Stopping…".to_string(),
                Run::Stopped => "Stopped.".to_string(),
                Run::Failed => "Failed. Event Viewer has what it reported.".to_string(),
            };
            let button = |label: &str, action: &str, command: Command, kind: Kind| {
                if service.allows(command) {
                    settings::button(
                        label,
                        "service",
                        &[("service", name), ("action", action)],
                        kind,
                        enabled,
                    )
                } else {
                    String::new()
                }
            };
            let controls = match state {
                Run::Running => format!(
                    "{}{}",
                    button("Restart", "restart", Command::Restart, Kind::Plain),
                    button("Stop", "stop", Command::Stop, Kind::Plain)
                ),
                Run::Starting | Run::Stopping => String::new(),
                Run::Stopped | Run::Failed => {
                    button("Start", "start", Command::Start, Kind::Primary)
                }
            };
            (text, controls)
        }
    };
    settings::row(title, &state, &controls)
}

pub fn page(window: &Window) -> String {
    if !window.seen.set_up {
        return setup_page(window);
    }
    let mut page = settings::head(
        Glyph::Certificate,
        Tile::Red,
        "Certificate Authority",
        "Issue certificates for this network's servers, devices and people.",
    );
    let authorities = window.seen.authorities();
    let waiting = officer_waiting(window);
    let figure = if let Err(trouble) = &window.seen.pkid {
        let (title, about) = match trouble {
            Trouble::Down => (
                "Not Running",
                "Start the Certificate Service to issue and revoke certificates.".to_string(),
            ),
            Trouble::Invalid(_) => (
                "Not Issuing",
                "The configuration is invalid, so nothing is issued until it is put right."
                    .to_string(),
            ),
            Trouble::Database(reason) => (
                "Not Issuing",
                format!(
                    "The certificate database can't be used. {}",
                    service::sentence(reason)
                ),
            ),
            Trouble::Failed(reason) => ("Not Issuing", service::sentence(reason)),
        };
        settings::hero_title(Glyph::Blocked, Tile::Red, title, &about)
    } else if waiting > 0 {
        settings::big(
            &waiting.to_string(),
            if waiting == 1 {
                "request waiting for approval"
            } else {
                "requests waiting for approval"
            },
        )
    } else {
        settings::big(
            &authorities.len().to_string(),
            if authorities.len() == 1 {
                "authority you can use"
            } else {
                "authorities you can use"
            },
        )
    };
    let pill = match &window.seen.pkid {
        Ok(_) if authorities.iter().any(|a| a.certificate.is_some()) => {
            settings::pill("Issuing", Tone::Good)
        }
        Ok(_) => settings::pill("Running", Tone::Plain),
        Err(Trouble::Down) => settings::pill("Not Running", Tone::Bad),
        Err(_) => settings::pill("Not Issuing", Tone::Bad),
    };
    page.push_str(&settings::hero(&figure, &pill));

    let attention = attention(window);
    if !attention.is_empty() {
        page.push_str(&settings::group("Needs Attention", &attention, ""));
    }

    if let Ok(pkid) = &window.seen.pkid {
        if pkid.authorities.is_empty() {
            let rows = settings::row(
                "No Authorities",
                if pkid.create {
                    "Create a root authority to start issuing certificates."
                } else {
                    "There are no authorities you have access to."
                },
                "",
            );
            page.push_str(&settings::group("Authorities", &rows, ""));
        }
    }

    let mut rows = service_row(
        window,
        "Certificate Service",
        "Authorities issue and revoke as their permissions allow.",
        service::PKID,
        &window.seen.pkid_service,
    );
    rows.push_str(&service_row(
        window,
        "Revocation Publishing",
        "Other devices fetch revocation lists from this machine over HTTP.",
        service::HTTPD,
        &window.seen.httpd_service,
    ));
    // Changing the port runs setup again, which reserves it.
    if window.seen.may.http && window.seen.may.setup {
        rows.push_str(&settings::row(
            "Revocation List Port",
            "Where other devices fetch revocation lists. Changing it restarts Revocation Publishing.",
            &format!(
                "{}{}",
                settings::text(
                    "http-port",
                    "Revocation List Port",
                    "number",
                    Width::Short,
                    !window.busy,
                    r#"min="1" max="65535""#,
                ),
                settings::button("Save", "http-port-save", &[], Kind::Plain, !window.busy)
                    .replacen("class=\"st-button\"", "class=\"st-button pki-beside\"", 1),
            ),
        ));
    } else {
        rows.push_str(&settings::fact(
            "Revocation List Port",
            &window
                .seen
                .http_port
                .map_or("Unknown".to_string(), |port| port.to_string()),
            false,
        ));
    }
    let controls = [&window.seen.pkid_service, &window.seen.httpd_service]
        .iter()
        .any(|service| {
            [Command::Start, Command::Stop]
                .into_iter()
                .any(|command| service.allows(command))
        });
    page.push_str(&settings::group(
        "Services",
        &rows,
        &if controls {
            String::new()
        } else {
            settings::locked("You don't have permission to start or stop these services.")
        },
    ));
    let editable = window.seen.may.settings;
    page.push_str(&settings::group(
        "Permissions",
        &settings::row(
            "Who Can Add Authorities",
            &describe::creators(&window.seen.creators(), &window.people),
            &settings::button(
                if editable { "Edit…" } else { "View…" },
                "creators-permissions",
                &[],
                Kind::Plain,
                !window.busy,
            ),
        ),
        &settings::hint("Whoever can add an authority can issue any certificate from it."),
    ));
    if window.seen.pkid.is_ok() {
        page.push_str(&settings::hint(
            "Authorities you have no permission at aren't listed in this window.",
        ));
    }
    page
}

/// The part of an invalid configuration at fault, and how to open it.
struct Fault {
    title: String,
    event: &'static str,
    values: Vec<(&'static str, String)>,
}

/// The part of the configuration an invalid one names first, as pkid
/// reports it: by its key below Machine\Software\Pki.
fn fault(window: &Window, reason: &str) -> Option<Fault> {
    let config = window.seen.config.as_ref().ok()?;
    let (key, _) = reason.split_once(':')?;
    let mut parts = key.split('\\');
    match parts.next()? {
        "Templates" => {
            let id = parts.next()?.to_ascii_lowercase();
            let (_, values) = config
                .templates
                .iter()
                .find(|(guid, _)| guid.eq_ignore_ascii_case(&id))?;
            Some(Fault {
                title: format!("The {} template is invalid", super::templates::name(values)),
                event: "template",
                values: vec![("id", id)],
            })
        }
        "Names" => {
            let tree = match parts.next()? {
                "Dns" => pki_policy::TreeKind::Dns,
                _ => pki_policy::TreeKind::Principal,
            };
            let path: Vec<String> = parts.map(str::to_lowercase).collect();
            let name = pki_management::names::NamePath { tree, path }.display();
            Some(Fault {
                title: format!("{name}'s permissions are invalid"),
                event: "name",
                values: vec![("name", name)],
            })
        }
        _ => None,
    }
}

/// What needs someone's attention, as rows with a button to it.
fn attention(window: &Window) -> String {
    let now = words::now();
    let enabled = !window.busy;
    let mut rows = String::new();
    if let Err(Trouble::Invalid(reason)) = &window.seen.pkid {
        let (title, button) = match fault(window, reason) {
            Some(fault) => {
                let values: Vec<(&str, &str)> =
                    fault.values.iter().map(|(k, v)| (*k, v.as_str())).collect();
                (
                    fault.title,
                    settings::button("Open", fault.event, &values, Kind::Plain, enabled),
                )
            }
            None => ("The configuration is invalid".to_string(), String::new()),
        };
        // Once the part at fault is named, what is wrong with it is enough.
        let detail = match (button.is_empty(), reason.split_once(": ")) {
            (false, Some((_, detail))) => detail,
            _ => reason.as_str(),
        };
        rows.push_str(&settings::item(
            &settings::icon(Glyph::Blocked, Tile::Red),
            &title,
            &[(&service::sentence(detail), false)],
            &button,
        ));
    }
    for (held, name) in &window.seen.ready {
        let id = held.request.to_string();
        rows.push_str(&settings::item(
            &settings::icon(Glyph::Certificate, Tile::Green),
            &format!("Your certificate for {name} is ready"),
            &[("Save it with the key kept for it.", false)],
            &settings::button(
                "Open",
                "request",
                &[("ca", held.ca.as_str()), ("id", id.as_str())],
                Kind::Plain,
                enabled,
            ),
        ));
    }
    for authority in window.seen.authorities() {
        let values = [("ca", authority.id.as_str())];
        let waiting = window.seen.waiting.get(&authority.id).map_or(0, Vec::len);
        if waiting > 0 && authority.granted & OFFICER != 0 && authority.granted & READ != 0 {
            rows.push_str(&settings::item(
                &settings::icon(Glyph::Clock, Tile::Orange),
                &format!(
                    "{} waiting at {}",
                    words::count(waiting as i64, "request"),
                    authority.name
                ),
                &[("Approve or deny them.", false)],
                &settings::button("Review", "review", &values, Kind::Plain, enabled),
            ));
        }
        if authority.certificate.is_none() {
            rows.push_str(&settings::item(
                &settings::icon(Glyph::Shield, Tile::Orange),
                &format!("{} is waiting for its certificate", authority.name),
                &[(
                    "Have its request signed, then install the certificate.",
                    false,
                )],
                &settings::button(
                    "Open",
                    "section",
                    &[("section", &format!("authority:{}", authority.id))],
                    Kind::Plain,
                    enabled,
                ),
            ));
        } else if let Some(crl) = &authority.crl {
            let line = if crl.next_update <= now {
                Some(("Its revocation list has expired: software that checks revocation refuses its certificates.".to_string(), Tile::Red, "expired"))
            } else if show::crl_expiring(authority, now) {
                Some((
                    format!(
                        "Its revocation list expires {}.",
                        words::relative(crl.next_update, now)
                    ),
                    Tile::Orange,
                    "due",
                ))
            } else {
                None
            };
            if let Some((line, tile, state)) = line {
                rows.push_str(&settings::item(
                    &settings::icon(Glyph::Refresh, tile),
                    &format!("{}'s revocation list is {state}", authority.name),
                    &[(line.as_str(), false)],
                    &settings::button(
                        "Open",
                        "section",
                        &[("section", &format!("authority:{}", authority.id))],
                        Kind::Plain,
                        enabled,
                    ),
                ));
            }
        }
    }
    if let Ok(config) = &window.seen.config {
        for (tree, nodes) in [
            (pki_policy::TreeKind::Dns, &config.dns),
            (pki_policy::TreeKind::Principal, &config.principals),
        ] {
            for (path, values) in nodes {
                let Ok(Some(security)) = values.binary("RequestSecurity") else {
                    continue;
                };
                let name = pki_management::names::NamePath {
                    tree,
                    path: path.clone(),
                };
                // Only those who could narrow it are told.
                if !window
                    .seen
                    .may
                    .names
                    .get(&name.key())
                    .is_some_and(|may| may.edit)
                {
                    continue;
                }
                let groups = describe::broad_requesters(security);
                if groups.is_empty() {
                    continue;
                }
                let name = name.display();
                rows.push_str(&settings::item(
                    &settings::icon(Glyph::Tag, Tile::Orange),
                    &format!(
                        "{} may request {name} without approval",
                        describe::and(&groups)
                    ),
                    &[(
                        "Consider Request with Approval instead, so an officer checks each one.",
                        false,
                    )],
                    &settings::button("Open", "name", &[("name", &name)], Kind::Plain, enabled),
                ));
            }
        }
    }
    rows
}
