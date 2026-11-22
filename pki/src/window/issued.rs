//! The requests made of the CAs and the certificates they issued: the
//! lists, and one of each in full.
//!
//! pkid shows someone without Read at a CA only their own requests and
//! certificates; the pages say so, rather than look complete.

use gxwi::settings::{self, Glyph, Kind, Tile, Tone};
use gxwi::Fields;
use pkid_core::{AuthorityInfo, CertificateInfo, RequestInfo, RequestStatus};

use super::{describe, waiting, words, Window};
use crate::show::{OFFICER, READ};

/// The Requests section's line in the side.
pub fn requests_summary(window: &Window) -> String {
    let waiting = super::overview::officer_waiting(window);
    if waiting > 0 {
        return format!("{} waiting for approval", waiting);
    }
    let mine: usize = window
        .seen
        .authorities()
        .iter()
        .filter(|a| a.granted & READ == 0)
        .map(|a| window.seen.waiting.get(&a.id).map_or(0, Vec::len))
        .sum();
    if mine > 0 {
        format!("{} of yours waiting", mine)
    } else if window
        .seen
        .authorities()
        .iter()
        .any(|a| a.granted & READ != 0)
    {
        "None waiting".to_string()
    } else {
        "Your requests".to_string()
    }
}

/// The Certificates section's line in the side.
pub fn certificates_summary(window: &Window) -> String {
    if window
        .seen
        .authorities()
        .iter()
        .any(|a| a.granted & READ != 0)
    {
        "Issued and revoked".to_string()
    } else {
        "Your certificates".to_string()
    }
}

/// Above a list: which CA's it is, when there is a choice, and what the
/// person can see of it.
fn chooser(window: &Window, fields: &Fields, what: &str) -> (Option<AuthorityInfo>, String) {
    let authorities: Vec<&AuthorityInfo> = window
        .seen
        .authorities()
        .iter()
        .filter(|a| a.certificate.is_some())
        .collect();
    let Some(ca) = window.listed_ca(fields).cloned() else {
        return (None, String::new());
    };
    let mut html = String::new();
    if authorities.len() > 1 {
        let options: Vec<(String, String)> = authorities
            .iter()
            .map(|a| (a.id.clone(), a.name.clone()))
            .collect();
        html.push_str(&settings::group(
            "",
            &settings::row(
                "Authority",
                "",
                &settings::select("ca", "Authority", &options, !window.busy),
            ),
            "",
        ));
    }
    if ca.granted & READ == 0 {
        html.push_str(&settings::caution(&format!(
            "Showing only your own {what}. Read permission at {} shows everyone's.",
            ca.name
        )));
    }
    (Some(ca), html)
}

fn matches(find: &str, texts: &[&str]) -> bool {
    let find = find.trim().to_lowercase();
    find.is_empty() || texts.iter().any(|text| text.to_lowercase().contains(&find))
}

fn request_tile(status: RequestStatus) -> Tile {
    match status {
        RequestStatus::Pending => Tile::Orange,
        RequestStatus::Issued => Tile::Green,
        RequestStatus::Denied => Tile::Slate,
    }
}

fn request_pill(status: RequestStatus) -> String {
    let tone = match status {
        RequestStatus::Pending => Tone::Warn,
        RequestStatus::Issued => Tone::Good,
        RequestStatus::Denied => Tone::Plain,
    };
    settings::pill(words::request_state(status), tone)
}

/// A request in a line: its number and what it names.
fn request_title(request: &RequestInfo) -> String {
    match request.names.first() {
        Some(first) if request.names.len() > 1 => {
            format!(
                "#{} · {first} and {} more",
                request.id,
                request.names.len() - 1
            )
        }
        Some(first) => format!("#{} · {first}", request.id),
        None => format!("#{}", request.id),
    }
}

fn template_name(authority: &AuthorityInfo, window: &Window, id: &str) -> String {
    if let Some(template) = authority
        .templates
        .iter()
        .find(|t| t.id.eq_ignore_ascii_case(id))
    {
        return template.name.clone();
    }
    if let Ok(config) = &window.seen.config {
        if let Some((_, values)) = config
            .templates
            .iter()
            .find(|(guid, _)| guid.eq_ignore_ascii_case(id))
        {
            if let Ok(Some(name)) = values.sz("Name") {
                return name.to_string();
            }
        }
    }
    if id == "subordinate-ca" {
        "Subordinate Authority".to_string()
    } else {
        id.to_string()
    }
}

/// Where a list is still being read, or couldn't be.
fn loading<T>(list: &Option<Result<Vec<T>, String>>) -> Result<&[T], String> {
    match list {
        None => Err(settings::group("", &settings::row("Reading…", "", ""), "")),
        Some(Err(why)) => Err(settings::caution(&super::service::sentence(why))),
        Some(Ok(items)) => Ok(items),
    }
}

pub fn requests(window: &Window, fields: &Fields) -> String {
    let mut page = settings::head(
        Glyph::Clock,
        Tile::Orange,
        "Requests",
        "Requests for certificates, and what came of them.",
    );
    if let Some(banner) = super::unreachable(window) {
        return page + &banner;
    }
    let (ca, chooser) = chooser(window, fields, "requests");
    let Some(ca) = ca else {
        return page + &settings::caution("There are no authorities you have access to.");
    };
    page.push_str(&chooser);
    let show = match fields.get("show") {
        "" => {
            if ca.granted & OFFICER != 0 {
                "waiting"
            } else {
                "all"
            }
        }
        chosen => chosen,
    };
    let options: Vec<(String, String)> = [
        ("waiting", "Waiting"),
        ("issued", "Issued"),
        ("denied", "Denied"),
        ("all", "All"),
    ]
    .iter()
    .map(|(value, label)| (value.to_string(), label.to_string()))
    .collect();
    page.push_str(&settings::search(
        "find",
        "Find",
        "Find by name, number or person",
        &settings::select("show", "Show", &options, true),
    ));
    let listed = if window.listing.ca == ca.id {
        &window.listing.requests
    } else {
        &None
    };
    let all = match loading(listed) {
        Ok(all) => all,
        Err(html) => return page + &html,
    };
    let find = fields.get("find");
    let chosen: Vec<&RequestInfo> = all
        .iter()
        .filter(|request| match show {
            "waiting" => request.status == RequestStatus::Pending,
            "issued" => request.status == RequestStatus::Issued,
            "denied" => request.status == RequestStatus::Denied,
            _ => true,
        })
        .filter(|request| {
            let id = request.id.to_string();
            let who = window.who(&request.requester);
            let mut texts: Vec<&str> = request.names.iter().map(String::as_str).collect();
            texts.extend([id.as_str(), who.as_str(), request.requester.as_str()]);
            matches(find, &texts)
        })
        .collect();
    let officer = ca.granted & OFFICER != 0;
    let now = words::now();
    let mut rows = String::new();
    for request in chosen.iter().take(window.shown) {
        let icon = settings::icon(Glyph::File, request_tile(request.status));
        let who = window.who(&request.requester);
        let line = format!(
            "{} · {} · {}",
            who,
            template_name(&ca, window, &request.template),
            words::relative(request.submitted, now)
        );
        let id = request.id.to_string();
        let values = [("ca", ca.id.as_str()), ("id", id.as_str())];
        let mine = window.me.as_deref() == Some(request.requester.as_str());
        if waiting(request) && officer && !mine {
            // The queue: approve from the list, or look first.
            let controls = format!(
                "{}{}",
                settings::button("Details", "request", &values, Kind::Plain, true),
                settings::button("Approve", "approve", &values, Kind::Primary, !window.busy),
            );
            rows.push_str(&settings::item(
                &icon,
                &request_title(request),
                &[(&line, false)],
                &controls,
            ));
        } else {
            rows.push_str(&settings::link(
                &icon,
                &request_title(request),
                &[(&line, false)],
                &request_pill(request.status),
                "request",
                &values,
            ));
        }
    }
    if chosen.is_empty() {
        let none = if !find.trim().is_empty() {
            "Nothing matches."
        } else {
            match show {
                "waiting" => "No requests are waiting.",
                "issued" => "No requests have been issued.",
                "denied" => "No requests have been denied.",
                _ => "There are no requests yet.",
            }
        };
        rows.push_str(&settings::row("", "", &settings::none(none)));
    }
    let foot = if chosen.len() > window.shown {
        settings::actions(&settings::button(
            &format!("Show More ({} more)", chosen.len() - window.shown),
            "more",
            &[],
            Kind::Quiet,
            true,
        ))
    } else {
        String::new()
    };
    page.push_str(&settings::group("", &rows, &foot));
    page
}

pub fn request(window: &Window, ca_id: &str, id: i64) -> String {
    let mut page = settings::back("Requests", "back");
    let Some(ca) = window.seen.authority(ca_id) else {
        return page
            + &super::unreachable(window)
                .unwrap_or_else(|| settings::caution("That authority isn't here any more."));
    };
    let listed = if window.listing.ca == ca.id {
        &window.listing.requests
    } else {
        &None
    };
    let all = match loading(listed) {
        Ok(all) => all,
        Err(html) => return page + &html,
    };
    let Some(request) = all.iter().find(|request| request.id == id) else {
        return page
            + &settings::caution(&format!(
                "Request #{id} isn't one you can see at {}.",
                ca.name
            ));
    };
    page.push_str(&settings::hero(
        &settings::hero_title(
            Glyph::File,
            request_tile(request.status),
            &format!("Request #{}", request.id),
            &format!(
                "{} · {}",
                ca.name,
                template_name(ca, window, &request.template)
            ),
        ),
        &request_pill(request.status),
    ));
    let mut rows = settings::fact(
        "Requested By",
        &describe::who_in_full(&request.requester, &window.people),
        false,
    );
    rows.push_str(&settings::fact(
        "Template",
        &template_name(ca, window, &request.template),
        false,
    ));
    rows.push_str(&settings::fact(
        if request.names.len() == 1 {
            "Name"
        } else {
            "Names"
        },
        &request.names.join("\n"),
        true,
    ));
    rows.push_str(&settings::fact(
        "Submitted",
        &words::moment(request.submitted),
        false,
    ));
    if let Some(decided) = request.decided {
        let by = request
            .decider
            .as_deref()
            .map(|sid| format!(" by {}", window.who(sid)))
            .unwrap_or_default();
        let what = match request.status {
            RequestStatus::Denied => "Denied",
            _ => "Approved",
        };
        rows.push_str(&settings::fact(
            what,
            &format!("{}{by}", words::moment(decided)),
            false,
        ));
    }
    page.push_str(&settings::group("Request", &rows, ""));

    if !request.reasons.is_empty() {
        let title = match request.status {
            RequestStatus::Pending => "Why It's Waiting",
            RequestStatus::Denied => "Why It Was Denied",
            RequestStatus::Issued => "Notes",
        };
        let rows: String = request
            .reasons
            .iter()
            .map(|reason| settings::row("", &super::service::sentence(reason), ""))
            .collect();
        page.push_str(&settings::group(title, &rows, ""));
    }

    let id_text = request.id.to_string();
    let values = [("ca", ca.id.as_str()), ("id", id_text.as_str())];
    if waiting(request) {
        let mine = window.me.as_deref() == Some(request.requester.as_str());
        let officer = ca.granted & OFFICER != 0;
        if officer {
            let enabled = !window.busy && !mine;
            let rows = settings::row(
                "Decision",
                if mine {
                    "You can't approve or deny your own request. Another officer has to."
                } else {
                    "Approving issues the certificate. The requester's own permissions are checked again first."
                },
                &format!(
                    "{}{}",
                    settings::button("Deny…", "deny", &values, Kind::Danger, enabled),
                    settings::button("Approve", "approve", &values, Kind::Primary, enabled),
                ),
            );
            page.push_str(&settings::group("", &rows, ""));
        } else {
            page.push_str(&settings::group(
                "",
                &settings::row(
                    "Waiting for an Officer",
                    &format!(
                        "Someone with Issue and Manage Certificates permission at {} decides it.",
                        ca.name
                    ),
                    "",
                ),
                "",
            ));
        }
    }
    if request.status == RequestStatus::Issued {
        let certificate = window
            .listing
            .certificates
            .as_ref()
            .and_then(|list| list.as_ref().ok())
            .and_then(|list| list.iter().find(|c| c.request == request.id));
        if let Some(certificate) = certificate {
            let serial = crate::show::hex(&certificate.serial);
            page.push_str(&settings::group(
                "",
                &settings::link(
                    &settings::icon(Glyph::Certificate, Tile::Blue),
                    "Certificate",
                    &[(&words::serial(&certificate.serial), true)],
                    &certificate_pill(certificate, words::now()),
                    "certificate",
                    &[("ca", ca.id.as_str()), ("serial", serial.as_str())],
                ),
                "",
            ));
        }
    }
    page
}

fn certificate_state(certificate: &CertificateInfo, now: i64) -> (&'static str, Tone, Tile) {
    if certificate.revocation.is_some() {
        ("Revoked", Tone::Bad, Tile::Red)
    } else if certificate.not_after <= now {
        ("Expired", Tone::Plain, Tile::Slate)
    } else if certificate.not_after - now < 30 * 86_400 {
        ("Expires Soon", Tone::Warn, Tile::Orange)
    } else {
        ("Valid", Tone::Good, Tile::Blue)
    }
}

fn certificate_pill(certificate: &CertificateInfo, now: i64) -> String {
    let (text, tone, _) = certificate_state(certificate, now);
    settings::pill(text, tone)
}

pub fn certificates(window: &Window, fields: &Fields) -> String {
    let mut page = settings::head(
        Glyph::Certificate,
        Tile::Blue,
        "Certificates",
        "Certificates the authorities issued, and those revoked.",
    );
    if let Some(banner) = super::unreachable(window) {
        return page + &banner;
    }
    let (ca, chooser) = chooser(window, fields, "certificates");
    let Some(ca) = ca else {
        return page + &settings::caution("There are no authorities you have access to.");
    };
    page.push_str(&chooser);
    let show = match fields.get("show-certificates") {
        "" => "valid",
        chosen => chosen,
    };
    let options: Vec<(String, String)> = [
        ("valid", "Valid"),
        ("revoked", "Revoked"),
        ("expired", "Expired"),
        ("all", "All"),
    ]
    .iter()
    .map(|(value, label)| (value.to_string(), label.to_string()))
    .collect();
    page.push_str(&settings::search(
        "find",
        "Find",
        "Find by name, serial number or person",
        &settings::select("show-certificates", "Show", &options, true),
    ));
    let listed = if window.listing.ca == ca.id {
        &window.listing.certificates
    } else {
        &None
    };
    let all = match loading(listed) {
        Ok(all) => all,
        Err(html) => return page + &html,
    };
    let now = words::now();
    let find = fields.get("find");
    let chosen: Vec<(&CertificateInfo, String, Vec<String>)> = all
        .iter()
        .filter(|certificate| match show {
            "valid" => certificate.revocation.is_none() && certificate.not_after > now,
            "revoked" => certificate.revocation.is_some(),
            "expired" => certificate.revocation.is_none() && certificate.not_after <= now,
            _ => true,
        })
        .map(|certificate| {
            let name = words::certificate_name(&certificate.der).unwrap_or_default();
            (certificate, name, words::names(&certificate.der))
        })
        .filter(|(certificate, name, names)| {
            let serial = crate::show::hex(&certificate.serial);
            let owner = certificate
                .owner
                .as_deref()
                .map(|sid| window.who(sid))
                .unwrap_or_default();
            let mut texts: Vec<&str> = names.iter().map(String::as_str).collect();
            texts.extend([name.as_str(), serial.as_str(), owner.as_str()]);
            matches(find, &texts)
        })
        .collect();
    let mut rows = String::new();
    for (certificate, name, names) in chosen.iter().take(window.shown) {
        let (_, _, tile) = certificate_state(certificate, now);
        let serial = crate::show::hex(&certificate.serial);
        let mut line = names.join(", ");
        if line.is_empty() || line == *name {
            line = String::new();
        }
        let issued = match &certificate.owner {
            Some(owner) => format!(
                "{} · expires {}",
                window.who(owner),
                words::date(certificate.not_after)
            ),
            None => format!("Expires {}", words::date(certificate.not_after)),
        };
        let mut lines: Vec<(&str, bool)> = Vec::new();
        if !line.is_empty() {
            lines.push((&line, false));
        }
        lines.push((&issued, false));
        rows.push_str(&settings::link(
            &settings::icon(Glyph::Certificate, tile),
            if name.is_empty() { "Certificate" } else { name },
            &lines,
            &certificate_pill(certificate, now),
            "certificate",
            &[("ca", ca.id.as_str()), ("serial", serial.as_str())],
        ));
    }
    if chosen.is_empty() {
        let none = if !find.trim().is_empty() {
            "Nothing matches."
        } else {
            match show {
                "valid" => "No certificates are valid now.",
                "revoked" => "No certificates have been revoked.",
                "expired" => "No certificates have expired.",
                _ => "No certificates have been issued yet.",
            }
        };
        rows.push_str(&settings::row("", "", &settings::none(none)));
    }
    let foot = if chosen.len() > window.shown {
        settings::actions(&settings::button(
            &format!("Show More ({} more)", chosen.len() - window.shown),
            "more",
            &[],
            Kind::Quiet,
            true,
        ))
    } else {
        String::new()
    };
    page.push_str(&settings::group("", &rows, &foot));
    page
}

pub fn certificate(window: &Window, ca_id: &str, serial: &[u8]) -> String {
    let mut page = settings::back("Certificates", "back");
    let Some(ca) = window.seen.authority(ca_id) else {
        return page
            + &super::unreachable(window)
                .unwrap_or_else(|| settings::caution("That authority isn't here any more."));
    };
    let listed = if window.listing.ca == ca.id {
        &window.listing.certificates
    } else {
        &None
    };
    let all = match loading(listed) {
        Ok(all) => all,
        Err(html) => return page + &html,
    };
    let Some(certificate) = all.iter().find(|c| c.serial == serial) else {
        return page + &settings::caution("That certificate isn't one you can see.");
    };
    let now = words::now();
    let (_, _, tile) = certificate_state(certificate, now);
    let name = words::certificate_name(&certificate.der).unwrap_or_else(|| "Certificate".into());
    page.push_str(&settings::hero(
        &settings::hero_title(
            Glyph::Certificate,
            tile,
            &name,
            &format!("Issued by {}", ca.name),
        ),
        &certificate_pill(certificate, now),
    ));
    let summary = crate::show::summary(&certificate.der);
    let names = words::names(&certificate.der);
    let mut rows = String::new();
    if let Some(summary) = &summary {
        rows.push_str(&settings::fact("Subject", &summary.subject, false));
    }
    if !names.is_empty() {
        rows.push_str(&settings::fact(
            if names.len() == 1 { "Name" } else { "Names" },
            &names.join("\n"),
            true,
        ));
    }
    if let Some(owner) = &certificate.owner {
        rows.push_str(&settings::fact(
            "Bound to Account",
            &describe::who_in_full(owner, &window.people),
            false,
        ));
    }
    rows.push_str(&settings::fact(
        "Valid From",
        &words::date(certificate.not_before),
        false,
    ));
    rows.push_str(&settings::fact(
        "Valid Until",
        &format!(
            "{} ({})",
            words::date(certificate.not_after),
            words::relative(certificate.not_after, now)
        ),
        false,
    ));
    if let Some(key) = words::key_kind(&certificate.der) {
        rows.push_str(&settings::fact("Key", &key, false));
    }
    rows.push_str(&settings::fact(
        "Serial Number",
        &words::serial(&certificate.serial),
        true,
    ));
    if let Some(summary) = &summary {
        rows.push_str(&settings::fact(
            "Fingerprint (SHA-256)",
            &summary.sha256,
            true,
        ));
    }
    page.push_str(&settings::group("Certificate", &rows, ""));

    if let Some(revocation) = &certificate.revocation {
        let mut rows = settings::fact("Revoked", &words::moment(revocation.revoked), false);
        rows.push_str(&settings::fact(
            "Reason",
            words::reason(revocation.reason),
            false,
        ));
        rows.push_str(&settings::fact(
            "Revoked By",
            &window.who(&revocation.revoker),
            false,
        ));
        page.push_str(&settings::group("Revocation", &rows, ""));
    }

    let serial_text = crate::show::hex(&certificate.serial);
    let id_text = certificate.request.to_string();
    let mut rows = settings::row(
        "Export",
        "Save the certificate, without its key, as a file.",
        &settings::button(
            "Export…",
            "export",
            &[("ca", ca.id.as_str()), ("serial", serial_text.as_str())],
            Kind::Plain,
            !window.busy,
        ),
    );
    rows.push_str(&settings::link(
        &settings::icon(Glyph::File, Tile::Slate),
        &format!("Request #{}", certificate.request),
        &[("The request it was issued for.", false)],
        "",
        "request",
        &[("ca", ca.id.as_str()), ("id", id_text.as_str())],
    ));
    if certificate.revocation.is_none() && ca.granted & OFFICER != 0 {
        rows.push_str(&settings::row(
            "Revoke",
            "Stop it being trusted, for good: software that checks the revocation list refuses it.",
            &settings::button(
                "Revoke…",
                "revoke",
                &[("ca", ca.id.as_str()), ("serial", serial_text.as_str())],
                Kind::Danger,
                !window.busy,
            ),
        ));
    }
    page.push_str(&settings::group("", &rows, ""));
    page
}
