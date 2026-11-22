//! How pki shows what pkid returns, as JSON and as text.

use peios_crypto::digest::{self, Algorithm};
use pkid_core::AuthorityInfo;
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// A command's result, in both forms.
#[derive(Debug, Clone, PartialEq)]
pub struct Output {
    pub json: Value,
    pub text: String,
}

/// A Unix time in RFC 3339, in UTC.
pub fn time(seconds: i64) -> String {
    OffsetDateTime::from_unix_timestamp(seconds)
        .ok()
        .and_then(|time| time.format(&Rfc3339).ok())
        .unwrap_or_else(|| seconds.to_string())
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A SHA-256 fingerprint, as certificate viewers print one.
pub fn fingerprint(der: &[u8]) -> String {
    digest::digest(Algorithm::Sha256, der)
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// What a certificate says about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub not_before: String,
    pub not_after: String,
    pub sha256: String,
}

pub fn summary(der: &[u8]) -> Option<Summary> {
    let (_, certificate) = x509_parser::parse_x509_certificate(der).ok()?;
    let validity = certificate.validity();
    Some(Summary {
        subject: certificate.subject().to_string(),
        issuer: certificate.issuer().to_string(),
        serial: hex(certificate.raw_serial()),
        not_before: time(validity.not_before.timestamp()),
        not_after: time(validity.not_after.timestamp()),
        sha256: fingerprint(der),
    })
}

fn summary_json(summary: &Summary) -> Value {
    json!({
        "subject": summary.subject,
        "issuer": summary.issuer,
        "serial": summary.serial,
        "not_before": summary.not_before,
        "not_after": summary.not_after,
        "sha256": summary.sha256,
    })
}

/// Whether a CA issues, or awaits its certificate.
pub fn state(authority: &AuthorityInfo) -> &'static str {
    if authority.certificate.is_some() {
        "issuing"
    } else {
        "awaiting-certificate"
    }
}

/// How long before expiry a CRL that is renewed by hand is flagged.
const CRL_WARN_BEFORE: i64 = 30 * 86_400;

/// Whether a CA's CRL is running out, as pkid warns about it: a CRL pkid
/// renews itself once three quarters of its life has passed, and one
/// renewed by hand, with a sealed key, 30 days before it expires.
pub fn crl_expiring(authority: &AuthorityInfo, now: i64) -> bool {
    let Some(crl) = &authority.crl else {
        return false;
    };
    let warn_from = if authority.key_available {
        crl.next_update - (crl.next_update - crl.this_update) / 4
    } else {
        crl.next_update - CRL_WARN_BEFORE
    };
    now >= warn_from
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

/// A CA's CRL, in a line.
pub fn crl_text(authority: &AuthorityInfo, now: i64) -> String {
    match &authority.crl {
        None if authority.certificate.is_some() => "none yet".to_string(),
        None => "none".to_string(),
        Some(crl) => {
            let mut text = format!(
                "number {}, valid until {}",
                crl.number,
                time(crl.next_update)
            );
            if crl.next_update <= now {
                text.push_str(" (EXPIRED)");
            } else if crl_expiring(authority, now) {
                text.push_str(" (expires soon)");
            }
            text
        }
    }
}

/// When a CA's CRL expires, flagged when it is running out, for a table.
pub fn crl_until(authority: &AuthorityInfo) -> String {
    let now = now();
    match &authority.crl {
        None => "none".to_string(),
        Some(crl) if crl.next_update <= now => format!("{} EXPIRED", time(crl.next_update)),
        Some(crl) if crl_expiring(authority, now) => {
            format!("{} expires soon", time(crl.next_update))
        }
        Some(crl) => time(crl.next_update),
    }
}

/// The rights a CA's descriptor grants (pki-pipeline's `CA_*`).
pub const READ: u32 = 0x1;
pub const REQUEST: u32 = 0x2;
pub const OFFICER: u32 = 0x4;
pub const MANAGE: u32 = 0x8;

/// The rights the caller holds at a CA, by their names in JSON.
fn access(granted: u32) -> Vec<&'static str> {
    [
        (READ, "read"),
        (REQUEST, "request"),
        (OFFICER, "officer"),
        (MANAGE, "manage"),
    ]
    .into_iter()
    .filter(|(right, _)| granted & right != 0)
    .map(|(_, name)| name)
    .collect()
}

/// The rights the caller holds at a CA, as a reader says them.
fn access_text(granted: u32) -> String {
    let words: Vec<&str> = [
        (READ, "read"),
        (REQUEST, "request"),
        (OFFICER, "issue and manage certificates"),
        (MANAGE, "manage CA"),
    ]
    .into_iter()
    .filter(|(right, _)| granted & right != 0)
    .map(|(_, name)| name)
    .collect();
    if words.is_empty() {
        "none".to_string()
    } else {
        words.join(", ")
    }
}

pub fn authority_json(authority: &AuthorityInfo) -> Value {
    let now = now();
    json!({
        "id": authority.id,
        "name": authority.name,
        "state": state(authority),
        "key": authority.key,
        "key_available": authority.key_available,
        "access": access(authority.granted),
        "templates": authority.templates.iter().map(|template| json!({
            "id": template.id,
            "name": template.name,
            "enroll": template.enroll,
        })).collect::<Vec<_>>(),
        "certificate": authority.certificate.as_deref().and_then(summary).as_ref().map(summary_json),
        "crl_lifetime_days": authority.crl_lifetime_days,
        "crl": authority.crl.as_ref().map(|crl| json!({
            "number": crl.number,
            "this_update": time(crl.this_update),
            "next_update": time(crl.next_update),
            "expired": crl.next_update <= now,
            "expiring": crl_expiring(authority, now),
        })),
    })
}

/// Rows of text, padded into columns.
pub fn table(header: &[&str], rows: &[Vec<String>]) -> String {
    let mut widths: Vec<usize> = header.iter().map(|cell| cell.chars().count()).collect();
    for row in rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.chars().count());
        }
    }
    let mut out = String::new();
    let header: Vec<String> = header.iter().map(|cell| cell.to_string()).collect();
    for row in std::iter::once(&header).chain(rows) {
        let last = row.len().saturating_sub(1);
        for (index, (cell, width)) in row.iter().zip(&widths).enumerate() {
            out.push_str(cell);
            if index < last {
                let pad = width - cell.chars().count() + 2;
                out.extend(std::iter::repeat_n(' ', pad));
            }
        }
        out.push('\n');
    }
    out
}

/// Labelled lines, with the values in one column.
pub fn fields(rows: &[(&str, String)]) -> String {
    let width = rows.iter().map(|(label, _)| label.len()).max().unwrap_or(0) + 2;
    let mut out = String::new();
    for (label, value) in rows {
        out.push_str(&format!("{:<width$}{value}\n", format!("{label}:")));
    }
    out
}

pub fn authority_text(authority: &AuthorityInfo) -> String {
    let templates = if authority.templates.is_empty() {
        "none".to_string()
    } else {
        authority
            .templates
            .iter()
            .map(|template| template.name.clone())
            .collect::<Vec<_>>()
            .join(", ")
    };
    let mut rows = vec![
        ("Name", authority.name.clone()),
        ("ID", authority.id.clone()),
        ("State", state(authority).replace('-', " ")),
        ("Your access", access_text(authority.granted)),
        ("Key", authority.key.clone()),
        (
            "Unattended",
            if authority.key_available {
                "yes".to_string()
            } else {
                "no, each use needs the key's passphrase".to_string()
            },
        ),
        ("Templates", templates),
        ("CRL", crl_text(authority, now())),
        (
            "CRL lifetime",
            format!("{} days", authority.crl_lifetime_days),
        ),
    ];
    if let Some(summary) = authority.certificate.as_deref().and_then(summary) {
        rows.extend([
            ("Subject", summary.subject),
            ("Issuer", summary.issuer),
            ("Serial", summary.serial),
            ("Valid from", summary.not_before),
            ("Valid until", summary.not_after),
            ("SHA-256", summary.sha256),
        ]);
    }
    fields(&rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_align_and_end_without_padding() {
        let text = table(
            &["NAME", "ID"],
            &[
                vec!["Root".into(), "1".into()],
                vec!["Issuing CA".into(), "22".into()],
            ],
        );
        assert_eq!(text, "NAME        ID\nRoot        1\nIssuing CA  22\n");
    }

    #[test]
    fn times_are_utc() {
        assert_eq!(time(0), "1970-01-01T00:00:00Z");
    }
}
