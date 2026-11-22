//! Templates: what each kind of certificate the CAs issue is like, and who
//! may request it.

use gxwi::settings::{self, Glyph, Kind, More, Tile, Tone, Width};
use gxwi::{escape, Fields};
use pki_policy::Values;

use super::act::TemplateForm;
use super::doing::Asking;
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
        if window.asking == Some(Asking::NewTemplate) {
            let from: Vec<(String, String)> = config
                .templates
                .iter()
                .map(|(id, values)| (id.clone(), name(values)))
                .collect();
            page.push_str(&settings::group(
                "New Template",
                &settings::more(
                    More::Form,
                    &format!(
                        r#"<div class="fields"><label>Name{}</label><label>Start From{}</label></div>{}"#,
                        settings::text("new-template-name", "Name", "text", Width::Normal, true, r#"autocomplete="off" fx-autofocus"#),
                        settings::select("new-template-from", "Start From", &from, true),
                        settings::actions(&format!(
                            "{}{}",
                            settings::button("Cancel", "cancel", &[], Kind::Plain, true),
                            settings::button("Add Template", "new-template-confirm", &[], Kind::Primary, !window.busy),
                        )),
                    ),
                ),
                &settings::note("It starts as a copy, and opens to change."),
            ));
        } else {
            page.push_str(&settings::actions(&settings::button(
                "New Template…",
                "new-template",
                &[],
                Kind::Primary,
                !window.busy,
            )));
        }
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
    if may.edit {
        page.push_str(&form(window, values));
    } else {
        page.push_str(&settings::group("Certificates It Issues", &rows, ""));
    }

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

    if may.delete {
        let mut rows = settings::row(
            "Delete Template",
            &if offered.is_empty() {
                "No authority issues from it.".to_string()
            } else {
                format!(
                    "Can't be deleted while {} issues from it. Untick it under Issuing there first.",
                    describe::and(&offered)
                )
            },
            &settings::button(
                "Delete…",
                "delete-template",
                &[("id", id)],
                Kind::Danger,
                !window.busy && offered.is_empty() && window.asking.is_none(),
            ),
        );
        if window.asking == Some(Asking::DeleteTemplate { id: id.to_owned() }) {
            rows.push_str(&settings::more(
                More::Asking,
                &format!(
                    "<p>Delete the {} template? Certificates already issued from it stay valid.</p>{}",
                    escape(&name(values)),
                    settings::actions(&format!(
                        "{}{}",
                        settings::focused_button("Keep It", "cancel", Kind::Plain),
                        settings::button("Delete", "delete-template-confirm", &[], Kind::Danger, !window.busy),
                    )),
                ),
            ));
        }
        page.push_str(&settings::group("", &rows, ""));
    }
    page
}

/// The purposes, key usages, key types and name types a template's form
/// ticks, each `(value, label)`.
pub const PURPOSES: [(&str, &str); 6] = [
    ("server-auth", "Server Authentication"),
    ("client-auth", "Client Authentication"),
    ("email-protection", "Email Protection"),
    ("code-signing", "Code Signing"),
    ("time-stamping", "Time Stamping"),
    ("ocsp-signing", "OCSP Signing"),
];
pub const KEY_USAGES: [(&str, &str); 5] = [
    ("digital-signature", "Digital Signature"),
    ("key-encipherment", "Key Encipherment"),
    ("key-agreement", "Key Agreement"),
    ("data-encipherment", "Data Encipherment"),
    ("content-commitment", "Content Commitment"),
];
pub const EC_KEYS: [(&str, &str); 2] =
    [("ecdsa-p256", "ECDSA P-256"), ("ecdsa-p384", "ECDSA P-384")];
pub const NAME_TYPES: [(&str, &str); 3] = [
    ("dns", "DNS Names"),
    ("email", "Email Addresses"),
    ("upn", "Account Names"),
];

/// Sets the form's fields from `values`.
pub fn fill(values: &Values, fields: &mut Fields) {
    let tick = |fields: &mut Fields, prefix: &str, list: &[(&str, &str)], name: &str| {
        let have = strings(values, name);
        for (value, _) in list {
            let on = have.iter().any(|h| h == value);
            fields.set(&format!("{prefix}{value}"), if on { "on" } else { "" });
        }
    };
    fields.set("tpl-name", &self::name(values));
    tick(fields, "tpl-p-", &PURPOSES, "Purposes");
    tick(fields, "tpl-u-", &KEY_USAGES, "KeyUsages");
    tick(fields, "tpl-a-", &EC_KEYS, "KeyAlgorithms");
    tick(fields, "tpl-n-", &NAME_TYPES, "NameTypes");
    let rsa = strings(values, "KeyAlgorithms")
        .into_iter()
        .find(|a| a.starts_with("rsa-"))
        .unwrap_or_default();
    fields.set("tpl-rsa", &rsa);
    fields.set(
        "tpl-lifetime",
        &values
            .dword("LifetimeDays")
            .ok()
            .flatten()
            .unwrap_or(365)
            .to_string(),
    );
    fields.set(
        "tpl-renewal",
        &values
            .dword("RenewalWindowDays")
            .ok()
            .flatten()
            .unwrap_or(0)
            .to_string(),
    );
    fields.set(
        "tpl-cn",
        values
            .sz("CommonName")
            .ok()
            .flatten()
            .unwrap_or("first-name"),
    );
    fields.set(
        "tpl-issuance",
        values.sz("Issuance").ok().flatten().unwrap_or("immediate"),
    );
}

/// What the form says, for `pki template set`.
pub fn read(values: &Values, fields: &Fields) -> Result<TemplateForm, String> {
    let ticked = |prefix: &str, list: &[(&str, &str)]| -> Vec<String> {
        list.iter()
            .filter(|(value, _)| fields.get(&format!("{prefix}{value}")) == "on")
            .map(|(value, _)| value.to_string())
            .collect()
    };
    // Purposes the form doesn't offer, given as object identifiers, stay.
    let mut purposes = ticked("tpl-p-", &PURPOSES);
    purposes.extend(
        strings(values, "Purposes")
            .into_iter()
            .filter(|p| !PURPOSES.iter().any(|(known, _)| known == p)),
    );
    let mut key_algorithms = ticked("tpl-a-", &EC_KEYS);
    if !fields.get("tpl-rsa").is_empty() {
        key_algorithms.push(fields.get("tpl-rsa").to_owned());
    }
    let name = fields.get("tpl-name").trim().to_owned();
    let number = |field: &str| fields.get(field).trim().parse::<u32>().ok();
    let form = TemplateForm {
        name: name.clone(),
        purposes,
        key_usages: ticked("tpl-u-", &KEY_USAGES),
        lifetime: number("tpl-lifetime").ok_or("The lifetime is a number of days.")?,
        renewal_window: number("tpl-renewal").ok_or("The renewal window is a number of days.")?,
        key_algorithms,
        name_types: ticked("tpl-n-", &NAME_TYPES),
        common_name: fields.get("tpl-cn").to_owned(),
        issuance: fields.get("tpl-issuance").to_owned(),
    };
    if name.is_empty() {
        return Err("Give the template a name.".into());
    }
    if form.purposes.is_empty() {
        return Err("Tick at least one purpose.".into());
    }
    if form.key_usages.is_empty() {
        return Err("Tick at least one key usage.".into());
    }
    if form.key_algorithms.is_empty() {
        return Err("Allow at least one key type.".into());
    }
    if form.name_types.is_empty() {
        return Err("Allow at least one name type.".into());
    }
    Ok(form)
}

fn ticks(prefix: &str, list: &[(&str, &str)], enabled: bool) -> String {
    list.iter()
        .map(|(value, label)| {
            format!(
                r#"<label class="pki-tick">{}<span>{}</span></label>"#,
                settings::switch(&format!("{prefix}{value}"), label, enabled),
                escape(label)
            )
        })
        .collect()
}

/// The template's form, for one who may change it.
fn form(window: &Window, values: &Values) -> String {
    let enabled = !window.busy;
    let mut rows = settings::row(
        "Name",
        "",
        &settings::text(
            "tpl-name",
            "Name",
            "text",
            Width::Normal,
            enabled,
            r#"autocomplete="off""#,
        ),
    );
    rows.push_str(&settings::row(
        "Purposes",
        "What certificates from it may be used for.",
        &format!(
            r#"<span class="pki-ticks">{}</span>"#,
            ticks("tpl-p-", &PURPOSES, enabled)
        ),
    ));
    let others: Vec<String> = strings(values, "Purposes")
        .into_iter()
        .filter(|p| !PURPOSES.iter().any(|(known, _)| known == p))
        .collect();
    if !others.is_empty() {
        rows.push_str(&settings::fact("Other Purposes", &others.join("\n"), true));
    }
    rows.push_str(&settings::row(
        "Key Usages",
        "What the certificate's key may do.",
        &format!(
            r#"<span class="pki-ticks">{}</span>"#,
            ticks("tpl-u-", &KEY_USAGES, enabled)
        ),
    ));
    rows.push_str(&settings::row(
        "Lifetime",
        "Days each certificate is valid. Never beyond the authority's own.",
        &settings::text(
            "tpl-lifetime",
            "Lifetime",
            "number",
            Width::Short,
            enabled,
            r#"min="1" max="7305""#,
        ),
    ));
    rows.push_str(&settings::row(
        "Renewal Window",
        "Days before expiry that renewal is due.",
        &settings::text(
            "tpl-renewal",
            "Renewal Window",
            "number",
            Width::Short,
            enabled,
            r#"min="0""#,
        ),
    ));
    rows.push_str(&settings::row(
        "Key Types",
        "The keys a request may have.",
        &format!(
            r#"<span class="pki-ticks">{}</span>{}"#,
            ticks("tpl-a-", &EC_KEYS, enabled),
            settings::select(
                "tpl-rsa",
                "RSA Keys",
                &[
                    (String::new(), "No RSA".to_string()),
                    ("rsa-2048".to_string(), "RSA 2048 or larger".to_string()),
                    ("rsa-3072".to_string(), "RSA 3072 or larger".to_string()),
                    ("rsa-4096".to_string(), "RSA 4096 or larger".to_string()),
                ],
                enabled,
            ),
        ),
    ));
    rows.push_str(&settings::row(
        "Name Types",
        "The kinds of name its certificates may carry.",
        &format!(
            r#"<span class="pki-ticks">{}</span>"#,
            ticks("tpl-n-", &NAME_TYPES, enabled)
        ),
    ));
    rows.push_str(&settings::row(
        "Common Name",
        "Where the certificate's common name comes from.",
        &settings::select(
            "tpl-cn",
            "Common Name",
            &[
                ("first-name".to_string(), "First Name".to_string()),
                (
                    "owner-display-name".to_string(),
                    "Owner's Display Name".to_string(),
                ),
                ("none".to_string(), "None".to_string()),
            ],
            enabled,
        ),
    ));
    rows.push_str(&settings::row(
        "Issuance",
        "Whether permitted requests are issued at once, or every one waits for an officer.",
        &settings::select(
            "tpl-issuance",
            "Issuance",
            &[
                ("immediate".to_string(), "Immediately".to_string()),
                ("approval".to_string(), "After Approval".to_string()),
            ],
            enabled,
        ),
    ));
    format!(
        r#"<form fx-submit="template-save">{}{}</form>"#,
        settings::group(
            "Certificates It Issues",
            &rows,
            &settings::note("Changes apply to new requests.")
        ),
        settings::actions(&settings::submit("Save Changes", Kind::Primary, enabled)),
    )
}
