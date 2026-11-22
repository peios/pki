//! Making and keeping authorities: adding one, signing for one elsewhere,
//! exporting a key, and what an authority issues. Only those who hold
//! Manage CA see these; pkid checks again when they act.

use gxwi::settings::{self, Glyph, Kind, Tile, Width};
use gxwi::Fields;
use pkid_core::AuthorityInfo;

use super::{templates, Window};
use crate::cli::{
    ROOT_ALGORITHM, ROOT_LIFETIME_DAYS, SUBORDINATE_ALGORITHM, SUBORDINATE_LIFETIME_DAYS,
};
use crate::show::MANAGE;

/// The key algorithms pkid makes CA keys with, best first.
pub const ALGORITHMS: [(&str, &str); 5] = [
    ("rsa-4096", "RSA 4096"),
    ("rsa-3072", "RSA 3072"),
    ("ecdsa-p384", "ECDSA P-384"),
    ("ecdsa-p256", "ECDSA P-256"),
    ("rsa-2048", "RSA 2048"),
];

fn options(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(value, label)| (value.to_string(), label.to_string()))
        .collect()
}

/// A path field and the button that chooses it.
fn path(name: &str, label: &str, choose: &str, enabled: bool) -> String {
    format!(
        "{}{}",
        settings::text(
            name,
            label,
            "text",
            Width::Normal,
            enabled,
            r#"autocomplete="off" spellcheck="false""#
        ),
        settings::button(
            "Choose…",
            "choose",
            &[("field", name), ("for", choose)],
            Kind::Plain,
            enabled
        )
        .replacen("class=\"st-button\"", "class=\"st-button pki-beside\"", 1)
    )
}

fn password(name: &str, label: &str, enabled: bool) -> String {
    settings::text(
        name,
        label,
        "password",
        Width::Normal,
        enabled,
        r#"autocomplete="new-password""#,
    )
}

/// Ticks for each template, named `{prefix}{guid}`.
fn template_ticks(window: &Window, prefix: &str, enabled: bool) -> String {
    let Ok(config) = &window.seen.config else {
        return String::new();
    };
    let mut rows = String::new();
    let mut all: Vec<&(String, pki_policy::Values)> = config.templates.iter().collect();
    all.sort_by_key(|(_, values)| templates::name(values).to_lowercase());
    for (id, values) in all {
        let purposes: Vec<String> = values
            .multi_sz("Purposes")
            .map(<[String]>::to_vec)
            .unwrap_or_default()
            .iter()
            .map(|p| templates::purpose(p))
            .collect();
        rows.push_str(&settings::row(
            &templates::name(values),
            &super::describe::and(&purposes),
            &settings::switch(&format!("{prefix}{id}"), &templates::name(values), enabled),
        ));
    }
    rows
}

/// The templates ticked on a form.
pub fn ticked(window: &Window, fields: &Fields, prefix: &str) -> Vec<String> {
    let Ok(config) = &window.seen.config else {
        return Vec::new();
    };
    config
        .templates
        .iter()
        .filter(|(id, _)| fields.get(&format!("{prefix}{id}")) == "on")
        .map(|(id, _)| id.clone())
        .collect()
}

/// The addresses typed into one field.
pub fn addresses(text: &str) -> Vec<String> {
    super::doing::names(text)
}

/// Sets the Issuing form's fields from what `authority` issues now.
pub fn fill_issuing(window: &Window, authority: &AuthorityInfo, fields: &mut Fields) {
    if let Ok(config) = &window.seen.config {
        for (id, _) in &config.templates {
            let on = authority
                .templates
                .iter()
                .any(|t| t.id.eq_ignore_ascii_case(id));
            fields.set(&format!("iss-{id}"), if on { "on" } else { "" });
        }
    }
    fields.set(
        "iss-crls",
        &super::authority::crl_points(window, authority).join(", "),
    );
    fields.set("iss-lifetime", &authority.crl_lifetime_days.to_string());
}

/// The Issuing group, as a form for one who may change it.
pub fn issuing_form(window: &Window, authority: &AuthorityInfo) -> String {
    let enabled = !window.busy;
    let mut rows = template_ticks(window, "iss-", enabled);
    rows.push_str(&settings::row(
        "Revocation List Addresses",
        "Where software fetches the list, named in every certificate issued: http://ca.lab.home/crl/issuing.crl. Separate more than one with commas.",
        &settings::text("iss-crls", "Revocation List Addresses", "text", Width::Wide, enabled, r#"autocomplete="off" spellcheck="false""#),
    ));
    rows.push_str(&settings::row(
        "Revocation List Lifetime",
        "Days each list is valid. Software refuses this authority's certificates once its list expires.",
        &settings::text("iss-lifetime", "Revocation List Lifetime", "number", Width::Short, enabled, r#"min="1" max="3650""#),
    ));
    format!(
        r#"<form fx-submit="issuing" fx-value-ca="{}">{}{}</form>"#,
        gxwi::escape(&authority.id),
        settings::group("Issuing", &rows, &settings::note("Ticked templates are the requests this authority takes. Changes apply to new certificates.")),
        settings::actions(&settings::submit("Save Changes", Kind::Primary, enabled)),
    )
}

/// The authorities that may sign a new one here: those that issue, and at
/// which the person holds Manage CA.
fn signers(window: &Window) -> Vec<&AuthorityInfo> {
    window
        .seen
        .authorities()
        .iter()
        .filter(|a| a.granted & MANAGE != 0 && a.certificate.is_some())
        .collect()
}

/// Fills the Add an Authority form's defaults for the kind chosen.
pub fn fill_new(fields: &mut Fields) {
    let root = matches!(fields.get("new-kind"), "" | "root");
    fields.set(
        "new-algorithm",
        if root {
            ROOT_ALGORITHM
        } else {
            SUBORDINATE_ALGORITHM
        },
    );
    fields.set(
        "new-lifetime",
        &if root {
            ROOT_LIFETIME_DAYS
        } else {
            SUBORDINATE_LIFETIME_DAYS
        }
        .to_string(),
    );
    fields.set("new-path", if root { "1" } else { "0" });
}

pub fn new_page(window: &Window, fields: &Fields) -> String {
    let mut page = settings::head(
        Glyph::Shield,
        Tile::Green,
        "Add an Authority",
        "A root of trust, an authority under one, or one taken up from a backup.",
    );
    if !window.seen.pkid.as_ref().is_ok_and(|pkid| pkid.create) {
        return page + &settings::banner("You don't have permission to add authorities.");
    }
    let enabled = !window.busy;
    let kind = match fields.get("new-kind") {
        "" => "root",
        chosen => chosen,
    };
    let signers = signers(window);
    let mut kinds = vec![("root", "Root Authority")];
    if !signers.is_empty() {
        kinds.push(("under", "Under an Authority Here"));
    }
    kinds.push(("elsewhere", "Signed by an Authority Elsewhere"));
    kinds.push(("import", "Import From a Backup"));
    let about = match kind {
        "root" => "Signs its own certificate. Devices trust what it issues once they trust it.",
        "under" => "Its certificate is signed by an authority on this machine.",
        "elsewhere" => "Its request is saved to be signed elsewhere, such as by an offline root. It issues once its certificate is installed.",
        _ => "An existing authority, from its certificate and the sealed key file Export Key wrote.",
    };
    let mut rows = settings::row(
        "Kind",
        about,
        &settings::select("new-kind", "Kind", &options(&kinds), enabled),
    );
    rows.push_str(&settings::row(
        "Name",
        "Its certificate's subject, and how it is shown: Lab Root, Lab Issuing.",
        &settings::text(
            "new-name",
            "Name",
            "text",
            Width::Normal,
            enabled,
            r#"autocomplete="off""#,
        ),
    ));
    if kind == "under" {
        let options: Vec<(String, String)> = signers
            .iter()
            .map(|a| (a.id.clone(), a.name.clone()))
            .collect();
        rows.push_str(&settings::row(
            "Signed By",
            "",
            &settings::select("new-issuer", "Signed By", &options, enabled),
        ));
        let chosen = signers
            .iter()
            .find(|a| a.id == fields.get("new-issuer"))
            .or(signers.first());
        if chosen.is_some_and(|a| crate::run::sealed(a)) {
            rows.push_str(&settings::row(
                "Its Key's Passphrase",
                "The signing authority's key is sealed.",
                &password("new-issuer-passphrase", "Its Key's Passphrase", enabled),
            ));
        }
    }
    if kind == "import" {
        rows.push_str(&settings::row(
            "Certificate",
            "The authority's certificate, in PEM or DER.",
            &path(
                "new-certificate",
                "Certificate",
                "open-certificate",
                enabled,
            ),
        ));
        rows.push_str(&settings::row(
            "Sealed Key File",
            "",
            &path("new-sealed", "Sealed Key File", "open-key", enabled),
        ));
        rows.push_str(&settings::row(
            "Its Passphrase",
            "The passphrase the key file was sealed under.",
            &password("new-import-passphrase", "Its Passphrase", enabled),
        ));
    } else {
        rows.push_str(&settings::row(
            "Key Type",
            "",
            &settings::select("new-algorithm", "Key Type", &options(&ALGORITHMS), enabled),
        ));
        rows.push_str(&settings::row(
            "Lifetime",
            "Days its certificate is valid.",
            &settings::text(
                "new-lifetime",
                "Lifetime",
                "number",
                Width::Short,
                enabled,
                r#"min="1""#,
            ),
        ));
        rows.push_str(&settings::row(
            "Authorities Below It",
            "How many levels of authority may sit below this one.",
            &settings::select(
                "new-path",
                "Authorities Below It",
                &options(&[
                    ("", "No Limit"),
                    ("0", "None: it issues to servers, devices and people"),
                    ("1", "1"),
                    ("2", "2"),
                ]),
                enabled,
            ),
        ));
    }
    page.push_str(&settings::group("Authority", &rows, ""));

    let keep = match fields.get("new-keep") {
        "file" => "file",
        _ => "service",
    };
    let mut rows = settings::row(
        "Key Storage",
        if keep == "service" {
            "The Certificate Service keeps the key and signs unattended."
        } else {
            "A file sealed under a passphrase, such as on a drive kept offline. Every signature asks for the passphrase."
        },
        &settings::select(
            "new-keep",
            "Key Storage",
            &options(&[("service", "Certificate Service"), ("file", "Sealed File")]),
            enabled,
        ),
    );
    if keep == "service" {
        rows.push_str(&settings::row(
            "Allow Export",
            "Lets Export Key make a backup of it. It can't be allowed later.",
            &settings::switch("new-exportable", "Allow Export", enabled),
        ));
    } else {
        rows.push_str(&settings::row(
            "Key File",
            "Where the Certificate Service writes it; the folder must be one it can write.",
            &path("new-key-file", "Key File", "save-key", enabled),
        ));
        rows.push_str(&settings::row(
            "Passphrase",
            &format!("At least {} characters.", pki_keys::MIN_PASSPHRASE_CHARS),
            &password("new-passphrase", "Passphrase", enabled),
        ));
        rows.push_str(&settings::row(
            "Confirm Passphrase",
            "",
            &password("new-confirm", "Confirm Passphrase", enabled),
        ));
    }
    page.push_str(&settings::group("Key", &rows, ""));

    let mut rows = template_ticks(window, "new-tpl-", enabled);
    rows.push_str(&settings::row(
        "Revocation List Addresses",
        "Where software fetches its list, such as http://ca.lab.home/crl/issuing.crl. Separate more than one with commas.",
        &settings::text("new-crls", "Revocation List Addresses", "text", Width::Wide, enabled, r#"autocomplete="off" spellcheck="false""#),
    ));
    page.push_str(&format!(
        r#"<form fx-submit="create">{}{}</form>"#,
        settings::group(
            "Issuing",
            &rows,
            &settings::note("A root usually issues from no templates: an authority under it does.")
        ),
        settings::actions(&settings::submit(
            if kind == "import" {
                "Import Authority"
            } else {
                "Create Authority"
            },
            Kind::Primary,
            enabled,
        )),
    ));
    page
}

pub fn sign_page(window: &Window, authority: &AuthorityInfo) -> String {
    let mut page = settings::back(&authority.name, "back");
    page.push_str(&settings::head(
        Glyph::Shield,
        Tile::Green,
        "Sign a Subordinate Request",
        &format!("Certify an authority elsewhere under {}.", authority.name),
    ));
    let enabled = !window.busy;
    let mut rows = settings::row(
        "Request File",
        "The subordinate authority's request, in PEM or DER.",
        &path("sign-request", "Request File", "open-request", enabled),
    );
    rows.push_str(&settings::row(
        "Name",
        "The subordinate authority's name, as its certificate gives it.",
        &settings::text(
            "sign-name",
            "Name",
            "text",
            Width::Normal,
            enabled,
            r#"autocomplete="off""#,
        ),
    ));
    rows.push_str(&settings::row(
        "Lifetime",
        "Days its certificate is valid.",
        &settings::text(
            "sign-lifetime",
            "Lifetime",
            "number",
            Width::Short,
            enabled,
            r#"min="1""#,
        ),
    ));
    rows.push_str(&settings::row(
        "Authorities Below It",
        "",
        &settings::select(
            "sign-path",
            "Authorities Below It",
            &options(&[
                ("0", "None: it issues to servers, devices and people"),
                ("1", "1"),
                ("2", "2"),
                ("", "No Limit"),
            ]),
            enabled,
        ),
    ));
    if crate::run::sealed(authority) {
        rows.push_str(&settings::row(
            "Key Passphrase",
            &format!("{}'s key is sealed.", authority.name),
            &password("sign-passphrase", "Key Passphrase", enabled),
        ));
    }
    rows.push_str(&settings::row(
        "Save Certificate To",
        "",
        &path(
            "sign-out",
            "Save Certificate To",
            "save-certificate",
            enabled,
        ),
    ));
    page.push_str(&format!(
        r#"<form fx-submit="sign" fx-value-ca="{}">{}{}</form>"#,
        gxwi::escape(&authority.id),
        settings::group("Subordinate", &rows, ""),
        settings::actions(&settings::submit("Sign", Kind::Primary, enabled)),
    ));
    page
}

pub fn export_page(window: &Window, authority: &AuthorityInfo) -> String {
    let mut page = settings::back(&authority.name, "back");
    page.push_str(&settings::head(
        Glyph::Key,
        Tile::Green,
        "Export Key",
        &format!(
            "Save {}'s key in a file sealed under a passphrase, as a backup.",
            authority.name
        ),
    ));
    let enabled = !window.busy;
    let mut rows = settings::row(
        "Save To",
        "Anyone with this file and its passphrase can issue as this authority. Keep both apart, and offline.",
        &path("key-out", "Save To", "save-export", enabled),
    );
    if crate::run::sealed(authority) {
        rows.push_str(&settings::row(
            "Current Passphrase",
            "The passphrase the key is sealed under now.",
            &password("key-current", "Current Passphrase", enabled),
        ));
    }
    rows.push_str(&settings::row(
        "New Passphrase",
        &format!(
            "At least {} characters. A few words is easiest to type.",
            pki_keys::MIN_PASSPHRASE_CHARS
        ),
        &password("key-new", "New Passphrase", enabled),
    ));
    rows.push_str(&settings::row(
        "Confirm Passphrase",
        "",
        &password("key-confirm", "Confirm Passphrase", enabled),
    ));
    page.push_str(&format!(
        r#"<form fx-submit="export-key" fx-value-ca="{}">{}{}</form>"#,
        gxwi::escape(&authority.id),
        settings::group("Key File", &rows, ""),
        settings::actions(&settings::submit("Export Key", Kind::Primary, enabled)),
    ));
    page
}
