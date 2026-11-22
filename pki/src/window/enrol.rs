//! Requesting a certificate: a key made here and certified, saved with its
//! chain as a PKCS #12 file, or a request made elsewhere, submitted.
//!
//! The form offers only the authorities the person may request from and
//! the templates they may enrol in, as pkid says. Whether each name is
//! theirs to request is pkid's to decide when the request arrives.

use gxwi::settings::{self, Glyph, Kind, Tile, Width};
use gxwi::Fields;
use pki_policy::Values;
use pkid_core::{AuthorityInfo, TemplateInfo};

use super::{templates, Window};
use crate::show::REQUEST;

/// The key algorithms `pki enroll` makes, best first.
const ALGORITHMS: [(&str, &str); 5] = [
    ("ecdsa-p256", "ECDSA P-256"),
    ("ecdsa-p384", "ECDSA P-384"),
    ("rsa-2048", "RSA 2048"),
    ("rsa-3072", "RSA 3072"),
    ("rsa-4096", "RSA 4096"),
];

/// The authorities the person may request from.
pub fn authorities(window: &Window) -> Vec<&AuthorityInfo> {
    window
        .seen
        .authorities()
        .iter()
        .filter(|a| a.granted & REQUEST != 0 && a.certificate.is_some())
        .collect()
}

/// The authority chosen on the form.
pub fn chosen_ca<'a>(window: &'a Window, fields: &Fields) -> Option<&'a AuthorityInfo> {
    let offered = authorities(window);
    offered
        .iter()
        .find(|a| a.id == fields.get("enrol-ca"))
        .or(offered.first())
        .copied()
}

/// The template chosen on the form, of those the person may enrol in.
pub fn chosen_template<'a>(
    authority: &'a AuthorityInfo,
    fields: &Fields,
) -> Option<&'a TemplateInfo> {
    let offered: Vec<&TemplateInfo> = authority.templates.iter().filter(|t| t.enroll).collect();
    offered
        .iter()
        .find(|t| t.id == fields.get("enrol-template"))
        .or(offered.first())
        .copied()
}

/// A template's values, from the configuration.
pub fn template_values<'a>(window: &'a Window, id: &str) -> Option<&'a Values> {
    let config = window.seen.config.as_ref().ok()?;
    config
        .templates
        .iter()
        .find(|(guid, _)| guid.eq_ignore_ascii_case(id))
        .map(|(_, values)| values)
}

/// Whether a template accepts a key made with `algorithm`.
fn accepts(accepted: &[String], algorithm: &str) -> bool {
    accepted.iter().any(|allowed| {
        if allowed == algorithm {
            return true;
        }
        match (allowed.strip_prefix("rsa-"), algorithm.strip_prefix("rsa-")) {
            (Some(least), Some(bits)) => {
                matches!((least.parse::<u32>(), bits.parse::<u32>()), (Ok(least), Ok(bits)) if bits >= least)
            }
            _ => false,
        }
    })
}

/// The key algorithms the template accepts, of those pki makes.
pub fn algorithms(values: Option<&Values>) -> Vec<(String, String)> {
    let accepted = values
        .and_then(|values| values.multi_sz("KeyAlgorithms").ok())
        .map(<[String]>::to_vec)
        .unwrap_or_default();
    ALGORITHMS
        .iter()
        .filter(|(id, _)| accepted.is_empty() || accepts(&accepted, id))
        .map(|(id, label)| (id.to_string(), label.to_string()))
        .collect()
}

/// A path field with a button to choose it.
fn path_field(name: &str, label: &str, choose: &str, enabled: bool) -> String {
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
        settings::button("Choose…", choose, &[], Kind::Plain, enabled).replacen(
            "class=\"st-button\"",
            "class=\"st-button pki-beside\"",
            1
        )
    )
}

pub fn page(window: &Window, fields: &Fields) -> String {
    let mut page = settings::head(
        Glyph::Key,
        Tile::Green,
        "Request a Certificate",
        "Make a key on this machine and have an authority certify it.",
    );
    if let Some(banner) = super::unreachable(window) {
        return page + &banner;
    }
    let offered = authorities(window);
    let Some(authority) = chosen_ca(window, fields) else {
        return page
            + &settings::banner(
                "There are no authorities you have permission to request certificates from.",
            );
    };
    let enabled = !window.busy;
    let mut rows = String::new();
    if offered.len() > 1 {
        let options: Vec<(String, String)> = offered
            .iter()
            .map(|a| (a.id.clone(), a.name.clone()))
            .collect();
        rows.push_str(&settings::row(
            "Authority",
            "",
            &settings::select("enrol-ca", "Authority", &options, enabled),
        ));
    }
    let Some(template) = chosen_template(authority, fields) else {
        page.push_str(&settings::group("", &rows, ""));
        return page
            + &settings::banner(&format!(
                "{} offers no templates you have permission to request from.",
                authority.name
            ));
    };
    let values = template_values(window, &template.id);
    let options: Vec<(String, String)> = authority
        .templates
        .iter()
        .filter(|t| t.enroll)
        .map(|t| (t.id.clone(), t.name.clone()))
        .collect();
    let about = values
        .map(|values| {
            let purposes: Vec<String> = values
                .multi_sz("Purposes")
                .map(<[String]>::to_vec)
                .unwrap_or_default()
                .iter()
                .map(|p| templates::purpose(p))
                .collect();
            let approval = values.sz("Issuance").ok().flatten() == Some("approval");
            format!(
                "{}{}",
                super::describe::and(&purposes),
                if approval {
                    ". An officer approves each request."
                } else {
                    "."
                }
            )
        })
        .unwrap_or_default();
    rows.push_str(&settings::row(
        "Template",
        &about,
        &settings::select("enrol-template", "Template", &options, enabled),
    ));
    page.push_str(&settings::group("Certificate", &rows, ""));

    let mode = match fields.get("enrol-key") {
        "own" => "own",
        _ => "make",
    };
    let mut rows = String::new();
    if mode == "make" {
        let types = values
            .and_then(|values| values.multi_sz("NameTypes").ok())
            .map(<[String]>::to_vec)
            .unwrap_or_else(|| vec!["dns".into()]);
        for (kind, field, example) in [
            ("dns", "enrol-dns", "radius.lab.home, www.lab.home"),
            ("email", "enrol-email", "alice@home"),
            ("upn", "enrol-upn", "alice@home"),
        ] {
            if !types.iter().any(|t| t == kind) {
                continue;
            }
            rows.push_str(&settings::row(
                &templates::name_type(kind),
                &format!("Separate more than one with commas: {example}."),
                &settings::text(
                    field,
                    &templates::name_type(kind),
                    "text",
                    Width::Wide,
                    enabled,
                    r#"autocomplete="off" spellcheck="false""#,
                ),
            ));
        }
        page.push_str(&settings::group(
            "Names",
            &rows,
            &settings::hint("You can request names you own, and names your permissions allow."),
        ));
    }

    let key_options = vec![
        ("make".to_string(), "Make a Key Here".to_string()),
        ("own".to_string(), "Use My Own Request".to_string()),
    ];
    let mut rows = settings::row(
        "Key",
        if mode == "make" {
            "The key is made on this machine and never leaves it except in the file you save."
        } else {
            "A certificate request made elsewhere, such as by another program, in PEM or DER."
        },
        &settings::select("enrol-key", "Key", &key_options, enabled),
    );
    if mode == "make" {
        rows.push_str(&settings::row(
            "Key Type",
            "",
            &settings::select("enrol-algorithm", "Key Type", &algorithms(values), enabled),
        ));
        rows.push_str(&settings::row(
            "Save To",
            "A PKCS #12 file holding the key, its certificate and the authorities above it.",
            &path_field("enrol-out", "Save To", "choose-out", enabled),
        ));
        rows.push_str(&settings::row(
            "Password",
            "Protects the file. Programs ask for it when they import it.",
            &settings::text(
                "enrol-password",
                "Password",
                "password",
                Width::Normal,
                enabled,
                r#"autocomplete="new-password""#,
            ),
        ));
        rows.push_str(&settings::row(
            "Confirm Password",
            "",
            &settings::text(
                "enrol-confirm",
                "Confirm Password",
                "password",
                Width::Normal,
                enabled,
                r#"autocomplete="new-password""#,
            ),
        ));
    } else {
        rows.push_str(&settings::row(
            "Request File",
            "",
            &path_field("enrol-csr", "Request File", "choose-csr", enabled),
        ));
        rows.push_str(&settings::row(
            "Save Certificate To",
            "",
            &path_field("enrol-out", "Save Certificate To", "choose-out", enabled),
        ));
    }
    page.push_str(&format!(
        r#"<form fx-submit="enrol">{}{}</form>"#,
        settings::group("Key and File", &rows, ""),
        settings::actions(&settings::submit(
            "Request Certificate",
            Kind::Primary,
            enabled
        )),
    ));
    page
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsa_minimums_accept_larger_keys() {
        let accepted = vec!["rsa-3072".to_string()];
        assert!(!accepts(&accepted, "rsa-2048"));
        assert!(accepts(&accepted, "rsa-3072"));
        assert!(accepts(&accepted, "rsa-4096"));
        assert!(!accepts(&accepted, "ecdsa-p256"));
    }
}
