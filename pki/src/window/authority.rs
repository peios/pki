//! A CA's page: what it is, what the person may do there, how it issues,
//! its revocation list, its key and who may use it.

use gxwi::settings::{self, Glyph, Kind, More, Tile, Tone, Width};
use pkid_core::AuthorityInfo;

use super::{describe, words, Window};
use crate::show::{self, MANAGE, OFFICER, READ, REQUEST};

/// Whether the CA signed its own certificate.
pub fn is_root(authority: &AuthorityInfo) -> bool {
    authority
        .certificate
        .as_deref()
        .and_then(show::summary)
        .is_some_and(|summary| summary.subject == summary.issuer)
}

/// When the CA's own certificate expires.
fn not_after(authority: &AuthorityInfo) -> Option<i64> {
    let der = authority.certificate.as_deref()?;
    let (_, certificate) = x509_parser::parse_x509_certificate(der).ok()?;
    Some(certificate.validity().not_after.timestamp())
}

/// Whether the CA's revocation list has run out.
pub fn crl_expired(authority: &AuthorityInfo, now: i64) -> bool {
    authority
        .crl
        .as_ref()
        .is_some_and(|crl| crl.next_update <= now)
}

/// The CA's state in a few words, under its name in the side.
pub fn summary(authority: &AuthorityInfo) -> String {
    let now = words::now();
    let kind = if is_root(authority) {
        "Root"
    } else {
        "Issuing"
    };
    if authority.certificate.is_none() {
        "Waiting for its certificate".to_string()
    } else if not_after(authority).is_some_and(|at| at <= now) {
        format!("{kind} · expired")
    } else if crl_expired(authority, now) {
        format!("{kind} · revocation list expired")
    } else if show::crl_expiring(authority, now) {
        format!("{kind} · revocation list due")
    } else if words::sealed(authority) {
        format!("{kind} · key offline")
    } else {
        format!("{kind} · ready")
    }
}

/// The colour of the CA's tile: green when it issues unattended, slate for
/// a CA kept offline, orange when it needs something soon, red when it
/// can't be relied on.
pub fn tile(authority: &AuthorityInfo) -> Tile {
    let now = words::now();
    if not_after(authority).is_some_and(|at| at <= now) || crl_expired(authority, now) {
        Tile::Red
    } else if authority.certificate.is_none() || show::crl_expiring(authority, now) {
        Tile::Orange
    } else if words::sealed(authority) {
        Tile::Slate
    } else {
        Tile::Green
    }
}

/// What holding `granted` lets the person do here, in a line.
fn access_note(authority: &AuthorityInfo) -> String {
    let granted = authority.granted;
    let mut can = Vec::new();
    if granted & REQUEST != 0 {
        can.push("request certificates".to_string());
    }
    if granted & READ != 0 {
        can.push("see every request and certificate".to_string());
    } else {
        can.push("see your own requests and certificates".to_string());
    }
    if granted & OFFICER != 0 {
        can.push("approve requests and revoke certificates".to_string());
    }
    if granted & MANAGE != 0 {
        can.push("change this authority and its key".to_string());
    }
    format!("You can {}.", describe::and(&can))
}

/// Under a group the person can't change: why.
fn needs_manage(authority: &AuthorityInfo) -> String {
    settings::locked(&format!(
        "Changing this needs Manage CA permission at {}.",
        authority.name
    ))
}

pub fn page(window: &Window, authority: &AuthorityInfo) -> String {
    let now = words::now();
    let manage = authority.granted & MANAGE != 0;
    let officer = authority.granted & OFFICER != 0;
    let enabled = !window.busy;
    let summary = authority.certificate.as_deref().and_then(show::summary);
    let key = authority
        .certificate
        .as_deref()
        .and_then(words::key_kind)
        .unwrap_or_default();
    let kind = match (authority.certificate.is_some(), is_root(authority)) {
        (false, _) => "Authority",
        (true, true) => "Root Authority",
        (true, false) => "Subordinate Authority",
    };
    let about = if key.is_empty() {
        kind.to_string()
    } else {
        format!("{kind} · {key}")
    };
    let expiry = not_after(authority);
    let state = if authority.certificate.is_none() {
        settings::pill("Waiting for Certificate", Tone::Warn)
    } else if expiry.is_some_and(|at| at <= now) {
        settings::pill("Expired", Tone::Bad)
    } else if crl_expired(authority, now) {
        settings::pill("Revocation List Expired", Tone::Bad)
    } else if words::sealed(authority) {
        settings::pill("Offline", Tone::Plain)
    } else {
        settings::pill("Issuing", Tone::Good)
    };
    let mut page = settings::hero(
        &settings::hero_title(Glyph::Shield, tile(authority), &authority.name, &about),
        &state,
    );
    if let Some(key_file) = authority.key.strip_prefix("file:") {
        if words::sealed(authority) && missing(key_file) {
            page.push_str(&settings::caution(&format!(
                "The key file {key_file} can't be found. Insert the drive it's on before signing with this authority."
            )));
        }
    }

    page.push_str(&settings::group(
        "Your Access",
        &settings::row(
            &words::access(authority.granted),
            &access_note(authority),
            "",
        ),
        "",
    ));

    if authority.certificate.is_none() {
        let mut rows = settings::row(
            "Certificate Request",
            "Have the authority above this one sign it, then install the certificate it issues.",
            &settings::button(
                "Save Request…",
                "save-ca-request",
                &[("ca", &authority.id)],
                Kind::Plain,
                enabled,
            ),
        );
        rows.push_str(&settings::row(
            "Install Certificate",
            "The certificate issued for this authority's request.",
            &settings::button(
                "Install Certificate…",
                "install",
                &[("ca", &authority.id)],
                Kind::Primary,
                enabled && manage,
            ),
        ));
        page.push_str(&settings::group(
            "Waiting for Its Certificate",
            &rows,
            &if manage {
                String::new()
            } else {
                needs_manage(authority)
            },
        ));
    }

    if let Some(summary) = &summary {
        let until = match expiry {
            Some(at) if at <= now => format!("{} (expired)", words::date(at)),
            Some(at) => format!("{} ({})", words::date(at), words::relative(at, now)),
            None => summary.not_after.clone(),
        };
        let mut rows = settings::fact("Subject", &summary.subject, false);
        rows.push_str(&settings::fact("Issued By", &summary.issuer, false));
        rows.push_str(&settings::fact("Valid Until", &until, false));
        rows.push_str(&settings::fact("Key", &words::key_place(authority), false));
        rows.push_str(&settings::fact(
            "Serial Number",
            &summary.serial.to_uppercase(),
            true,
        ));
        rows.push_str(&settings::fact(
            "Fingerprint (SHA-256)",
            &summary.sha256,
            true,
        ));
        rows.push_str(&settings::row(
            "Export Certificate",
            "Save it to install as trusted on other devices.",
            &settings::button(
                "Export…",
                "export-ca",
                &[("ca", &authority.id)],
                Kind::Plain,
                enabled,
            ),
        ));
        page.push_str(&settings::group("Certificate", &rows, ""));
    }

    if manage {
        page.push_str(&super::manage::issuing_form(window, authority));
    } else {
        let templates: Vec<String> = authority.templates.iter().map(|t| t.name.clone()).collect();
        let mut rows = settings::fact(
            "Templates",
            &if templates.is_empty() {
                "None: takes no requests".to_string()
            } else {
                describe::and(&templates)
            },
            false,
        );
        let points = crl_points(window, authority);
        rows.push_str(&settings::fact(
            "Revocation List Addresses",
            &if points.is_empty() {
                "None".to_string()
            } else {
                points.join("\n")
            },
            !points.is_empty(),
        ));
        rows.push_str(&settings::fact(
            "Revocation List Lifetime",
            &words::count(i64::from(authority.crl_lifetime_days), "day"),
            false,
        ));
        page.push_str(&settings::group(
            "Issuing",
            &rows,
            &if manage {
                String::new()
            } else {
                needs_manage(authority)
            },
        ));
    }

    if authority.certificate.is_some() {
        let mut rows = match &authority.crl {
            None => settings::fact("Latest", "None published yet", false),
            Some(crl) => {
                let mut rows = settings::fact(
                    "Latest",
                    &format!(
                        "Number {}, published {}",
                        crl.number,
                        words::relative(crl.this_update, now)
                    ),
                    false,
                );
                let pill = if crl.next_update <= now {
                    settings::pill("Expired", Tone::Bad)
                } else if show::crl_expiring(authority, now) {
                    settings::pill("Due", Tone::Warn)
                } else {
                    String::new()
                };
                rows.push_str(&super::fact_html(
                    "Valid Until",
                    &format!(
                        "{}{pill}",
                        settings::value(
                            &format!(
                                "{} ({})",
                                words::date(crl.next_update),
                                words::relative(crl.next_update, now)
                            ),
                            false
                        )
                    ),
                ));
                rows
            }
        };
        if officer {
            rows.push_str(&settings::row(
                "Publish Now",
                if words::sealed(authority) {
                    "Sign a new list now. The key is sealed, so this asks for its passphrase."
                } else {
                    "The Certificate Service publishes a new list by itself, at half each list's lifetime and after every revocation."
                },
                &settings::button("Publish Now", "publish", &[("ca", &authority.id)], Kind::Plain, enabled && window.asking.is_none()),
            ));
            let asked = super::doing::Asking::Publish {
                ca: authority.id.clone(),
            };
            if window.asking.as_ref() == Some(&asked) {
                rows.push_str(&settings::more(
                    More::Form,
                    &format!(
                        "<p>Type the passphrase of {}'s key to sign the list.</p><div class=\"fields\"><label>Passphrase{}</label></div>{}",
                        gxwi::escape(&authority.name),
                        settings::text(
                            "passphrase",
                            "Passphrase",
                            "password",
                            Width::Normal,
                            true,
                            r#"autocomplete="off" fx-autofocus"#,
                        ),
                        settings::actions(&format!(
                            "{}{}",
                            settings::button("Cancel", "cancel", &[], Kind::Plain, true),
                            settings::button("Publish", "publish", &[("ca", &authority.id)], Kind::Primary, enabled),
                        )),
                    ),
                ));
            }
        }
        page.push_str(&settings::group(
            "Revocation List",
            &rows,
            &if officer {
                String::new()
            } else {
                settings::locked(&format!(
                    "Publishing needs Issue and Manage Certificates permission at {}.",
                    authority.name
                ))
            },
        ));
    }

    let mut rows = settings::row(
        "Who Can Use This Authority",
        &describe::ca_users(&authority.security, &window.people),
        &settings::button(
            if manage { "Edit…" } else { "View…" },
            "ca-permissions",
            &[("ca", &authority.id)],
            Kind::Plain,
            enabled,
        ),
    );
    if describe::denies(&authority.security) {
        rows.push_str(&settings::hint(
            "Some entries deny access; the permissions editor shows them.",
        ));
    }
    page.push_str(&settings::group("Permissions", &rows, ""));

    if manage {
        let mut rows = String::new();
        if authority.certificate.is_some() {
            rows.push_str(&settings::row(
                "Sign a Subordinate Request",
                "Certify another authority, elsewhere, under this one.",
                &settings::button(
                    "Sign…",
                    "sign",
                    &[("ca", &authority.id)],
                    Kind::Plain,
                    enabled,
                ),
            ));
        }
        rows.push_str(&settings::row(
            "Export Key",
            "Save the key in a file sealed under a passphrase, as a backup.",
            &settings::button(
                "Export Key…",
                "export-key",
                &[("ca", &authority.id)],
                Kind::Plain,
                enabled,
            ),
        ));
        page.push_str(&settings::group("Key", &rows, ""));
    }
    page
}

/// Where the CA's certificates say its revocation list is, from its record
/// in the Registry.
pub fn crl_points(window: &Window, authority: &AuthorityInfo) -> Vec<String> {
    let Ok(config) = &window.seen.config else {
        return Vec::new();
    };
    config
        .authorities
        .iter()
        .find(|(id, _)| id.eq_ignore_ascii_case(&authority.id))
        .and_then(|(_, values)| values.multi_sz("CrlDistributionPoints").ok())
        .map(<[String]>::to_vec)
        .unwrap_or_default()
}

/// Whether `path` is known not to exist. A file the person can't look at
/// is not called missing.
fn missing(path: &str) -> bool {
    matches!(std::fs::metadata(path), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
}
