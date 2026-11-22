//! Templates: what each kind of certificate the CAs issue is like, and who
//! may request it.

use gxwi::settings::{self, Glyph, Kind, Tile, Tone};
use pki_policy::Values;

use super::{describe, words, Window};

/// What a purpose (extended key usage) is called.
pub fn purpose(id: &str) -> String {
    match id {
        "server-auth" => "Server Authentication".into(),
        "client-auth" => "Client Authentication".into(),
        "code-signing" => "Code Signing".into(),
        "email-protection" => "Email Protection".into(),
        "time-stamping" => "Time Stamping".into(),
        "ocsp-signing" => "OCSP Signing".into(),
        other => other.into(),
    }
}

/// What a key usage is called.
pub fn key_usage(id: &str) -> String {
    match id {
        "digital-signature" => "Digital Signature".into(),
        "content-commitment" => "Content Commitment".into(),
        "key-encipherment" => "Key Encipherment".into(),
        "data-encipherment" => "Data Encipherment".into(),
        "key-agreement" => "Key Agreement".into(),
        other => other.into(),
    }
}

/// What a key algorithm a template accepts is called.
pub fn algorithm(id: &str) -> String {
    match id {
        "ecdsa-p256" => "ECDSA P-256".into(),
        "ecdsa-p384" => "ECDSA P-384".into(),
        other => match other.strip_prefix("rsa-") {
            Some(bits) => format!("RSA {bits} or larger"),
            None => other.into(),
        },
    }
}

/// What a kind of name is called.
pub fn name_type(id: &str) -> String {
    match id {
        "dns" => "DNS Names".into(),
        "email" => "Email Addresses".into(),
        "upn" => "Account Names".into(),
        other => other.into(),
    }
}

fn strings(values: &Values, name: &str) -> Vec<String> {
    values
        .multi_sz(name)
        .map(<[String]>::to_vec)
        .unwrap_or_default()
}

pub fn name(values: &Values) -> String {
    values
        .sz("Name")
        .ok()
        .flatten()
        .unwrap_or("Unnamed")
        .to_string()
}

fn lifetime(values: &Values) -> String {
    match values.dword("LifetimeDays").ok().flatten() {
        Some(days) if days % 365 == 0 => words::count(i64::from(days / 365), "year"),
        Some(days) => words::count(i64::from(days), "day"),
        None => "Not set".into(),
    }
}

fn approval(values: &Values) -> bool {
    values.sz("Issuance").ok().flatten() == Some("approval")
}

/// The authorities that issue from template `id`, by name: those pkid
/// lists for the person, and any others the Registry records.
fn offered_by(window: &Window, id: &str) -> Vec<String> {
    let mut names: Vec<String> = window
        .seen
        .authorities()
        .iter()
        .filter(|a| a.templates.iter().any(|t| t.id.eq_ignore_ascii_case(id)))
        .map(|a| a.name.clone())
        .collect();
    if let Ok(config) = &window.seen.config {
        for (ca, values) in &config.authorities {
            let issues = strings(values, "Templates")
                .iter()
                .any(|t| t.eq_ignore_ascii_case(id));
            let name = values.sz("Name").ok().flatten().unwrap_or(ca).to_string();
            if issues && !names.contains(&name) {
                names.push(name);
            }
        }
    }
    names
}

/// The Templates section's line in the side.
pub fn summary(window: &Window) -> String {
    match &window.seen.config {
        Ok(config) => words::count(config.templates.len() as i64, "template"),
        Err(_) => "Can't be read".into(),
    }
}

pub fn list(window: &Window) -> String {
    let mut page = settings::head(
        Glyph::File,
        Tile::Violet,
        "Templates",
        "Each kind of certificate the authorities issue, and who may request it.",
    );
    let config = match &window.seen.config {
        Ok(config) => config,
        Err(why) => {
            return page + &settings::banner(&format!("The templates can't be read: {why}"))
        }
    };
    if !window.seen.may.add_template && window.seen.may.templates.values().all(|may| !may.edit) {
        page.push_str(&settings::banner(
            "You can look, but you don't have permission to change templates.",
        ));
    }
    let mut rows = String::new();
    let mut templates: Vec<&(String, Values)> = config.templates.iter().collect();
    templates.sort_by_key(|(_, values)| name(values).to_lowercase());
    for (id, values) in templates {
        let purposes: Vec<String> = strings(values, "Purposes")
            .iter()
            .map(|p| purpose(p))
            .collect();
        let line = format!("{} · {}", describe::and(&purposes), lifetime(values));
        let aside = if approval(values) {
            settings::pill("Needs Approval", Tone::Plain)
        } else {
            String::new()
        };
        rows.push_str(&settings::link(
            &settings::icon(Glyph::File, Tile::Violet),
            &name(values),
            &[(&line, false)],
            &aside,
            "template",
            &[("id", id.as_str())],
        ));
    }
    if config.templates.is_empty() {
        rows.push_str(&settings::row(
            "",
            "",
            &settings::none("There are no templates."),
        ));
    }
    page.push_str(&settings::group("", &rows, ""));
    if window.seen.may.add_template {
        page.push_str(&settings::actions(&settings::button(
            "New Template…",
            "new-template",
            &[],
            Kind::Primary,
            !window.busy,
        )));
    }
    page
}

pub fn page(window: &Window, id: &str) -> String {
    let mut page = settings::back("Templates", "back");
    let Ok(config) = &window.seen.config else {
        return page;
    };
    let Some((_, values)) = config.templates.iter().find(|(guid, _)| guid == id) else {
        return page + &settings::caution("That template isn't here any more.");
    };
    let may = window
        .seen
        .may
        .templates
        .get(id)
        .copied()
        .unwrap_or_default();
    let purposes: Vec<String> = strings(values, "Purposes")
        .iter()
        .map(|p| purpose(p))
        .collect();
    page.push_str(&settings::hero(
        &settings::hero_title(
            Glyph::File,
            Tile::Violet,
            &name(values),
            &describe::and(&purposes),
        ),
        &if approval(values) {
            settings::pill("Needs Approval", Tone::Plain)
        } else {
            settings::pill("Issued at Once", Tone::Good)
        },
    ));
    if !may.edit {
        page.push_str(&settings::banner(
            "You can look, but you don't have permission to change this template.",
        ));
    }
    let usages: Vec<String> = strings(values, "KeyUsages")
        .iter()
        .map(|u| key_usage(u))
        .collect();
    let algorithms: Vec<String> = strings(values, "KeyAlgorithms")
        .iter()
        .map(|a| algorithm(a))
        .collect();
    let types: Vec<String> = strings(values, "NameTypes")
        .iter()
        .map(|t| name_type(t))
        .collect();
    let common_name = match values
        .sz("CommonName")
        .ok()
        .flatten()
        .unwrap_or("first-name")
    {
        "none" => "None",
        "owner-display-name" => "Owner's Display Name",
        _ => "First Name",
    };
    let renewal = values
        .dword("RenewalWindowDays")
        .ok()
        .flatten()
        .unwrap_or(0);
    let mut rows = settings::fact("Purposes", &describe::and(&purposes), false);
    rows.push_str(&settings::fact(
        "Key Usages",
        &describe::and(&usages),
        false,
    ));
    rows.push_str(&settings::fact("Lifetime", &lifetime(values), false));
    rows.push_str(&settings::fact(
        "Renewal Window",
        &if renewal == 0 {
            "None".to_string()
        } else {
            format!("{} before expiry", words::count(i64::from(renewal), "day"))
        },
        false,
    ));
    rows.push_str(&settings::fact(
        "Key Types",
        &describe::and(&algorithms),
        false,
    ));
    rows.push_str(&settings::fact("Name Types", &describe::and(&types), false));
    rows.push_str(&settings::fact("Common Name", common_name, false));
    rows.push_str(&settings::fact(
        "Issuance",
        if approval(values) {
            "After Approval"
        } else {
            "Immediately"
        },
        false,
    ));
    page.push_str(&settings::group("Certificates It Issues", &rows, ""));

    let enrollers = values
        .binary("EnrollSecurity")
        .ok()
        .flatten()
        .map(|security| describe::enrollers(security, &window.people))
        .unwrap_or_else(|| "Nobody".into());
    page.push_str(&settings::group(
        "Permissions",
        &settings::row(
            "Who Can Request",
            &enrollers,
            &settings::button(
                if may.edit { "Edit…" } else { "View…" },
                "template-permissions",
                &[("id", id)],
                Kind::Plain,
                !window.busy,
            ),
        ),
        &settings::hint("Requesting a certificate also needs permission for every name in it."),
    ));

    let offered = offered_by(window, id);
    page.push_str(&settings::group(
        "Offered By",
        &settings::fact(
            "Authorities",
            &if offered.is_empty() {
                "None".to_string()
            } else {
                describe::and(&offered)
            },
            false,
        ),
        "",
    ));
    page
}
