//! How the window says things: dates, counts, rights and keys.

use pkid_core::{AuthorityInfo, RequestStatus};
use time::OffsetDateTime;

use crate::show::{MANAGE, OFFICER, READ, REQUEST};

const DAY: i64 = 86_400;

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

/// A day, as "12 March 2027", in UTC.
pub fn date(seconds: i64) -> String {
    let Ok(time) = OffsetDateTime::from_unix_timestamp(seconds) else {
        return seconds.to_string();
    };
    format!("{} {} {}", time.day(), time.month(), time.year())
}

/// A moment, as "12 March 2027, 14:05 UTC".
pub fn moment(seconds: i64) -> String {
    let Ok(time) = OffsetDateTime::from_unix_timestamp(seconds) else {
        return seconds.to_string();
    };
    format!(
        "{}, {:02}:{:02} UTC",
        date(seconds),
        time.hour(),
        time.minute()
    )
}

/// How far `seconds` is from `now`, roughly: "in 3 days", "2 hours ago".
pub fn relative(seconds: i64, now: i64) -> String {
    let gap = seconds - now;
    if gap.abs() < 60 {
        return "just now".to_string();
    }
    let ahead = gap >= 0;
    let gap = gap.abs();
    let amount = if gap < 3_600 {
        count((gap / 60).max(1), "minute")
    } else if gap < DAY {
        count(gap / 3_600, "hour")
    } else if gap < 60 * DAY {
        count(gap / DAY, "day")
    } else if gap < 730 * DAY {
        count(gap / (30 * DAY), "month")
    } else {
        count(gap / (365 * DAY), "year")
    };
    if ahead {
        format!("in {amount}")
    } else {
        format!("{amount} ago")
    }
}

/// "1 request", "3 requests", "2 authorities".
pub fn count(n: i64, thing: &str) -> String {
    if n == 1 {
        return format!("1 {thing}");
    }
    match thing.strip_suffix('y') {
        Some(stem) if !stem.ends_with(['a', 'e', 'o', 'u']) => format!("{n} {stem}ies"),
        _ => format!("{n} {thing}s"),
    }
}

/// The rights the person holds at a CA, as a list a person reads.
pub fn access(granted: u32) -> String {
    let words: Vec<&str> = [
        (REQUEST, "Request"),
        (READ, "Read"),
        (OFFICER, "Issue and Manage Certificates"),
        (MANAGE, "Manage CA"),
    ]
    .into_iter()
    .filter(|(right, _)| granted & right != 0)
    .map(|(_, name)| name)
    .collect();
    match words.as_slice() {
        [] => "None".to_string(),
        [only] => only.to_string(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// Whether a CA's key is in a passphrase-sealed file, so that signing with
/// it needs the passphrase.
pub fn sealed(authority: &AuthorityInfo) -> bool {
    !authority.key_available && authority.key.starts_with("file:")
}

/// Where a CA's key is kept, as a person reads it.
pub fn key_place(authority: &AuthorityInfo) -> String {
    match authority.key.split_once(':') {
        Some(("service", _)) => "Kept by the Certificate Service".to_string(),
        Some(("file", path)) => format!("Sealed file at {path}"),
        _ => authority.key.clone(),
    }
}

/// A certificate's key, such as "RSA 4096" or "ECDSA P-384".
pub fn key_kind(der: &[u8]) -> Option<String> {
    use x509_parser::public_key::PublicKey;
    let (_, certificate) = x509_parser::parse_x509_certificate(der).ok()?;
    let spki = certificate.public_key();
    match spki.parsed().ok()? {
        PublicKey::RSA(rsa) => Some(format!("RSA {}", rsa.key_size())),
        PublicKey::EC(point) => Some(match point.key_size() {
            256 => "ECDSA P-256".to_string(),
            384 => "ECDSA P-384".to_string(),
            521 => "ECDSA P-521".to_string(),
            bits => format!("ECDSA {bits}"),
        }),
        _ => None,
    }
}

/// What a certificate is, in a few words: its subject's common name, or
/// its first name.
pub fn certificate_name(der: &[u8]) -> Option<String> {
    let (_, certificate) = x509_parser::parse_x509_certificate(der).ok()?;
    if let Some(cn) = certificate
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
    {
        return Some(cn.to_string());
    }
    names(der).into_iter().next()
}

/// The names a certificate is for: its subject alternative names.
pub fn names(der: &[u8]) -> Vec<String> {
    use x509_parser::extensions::GeneralName;
    let Ok((_, certificate)) = x509_parser::parse_x509_certificate(der) else {
        return Vec::new();
    };
    let Ok(Some(alternatives)) = certificate.subject_alternative_name() else {
        return Vec::new();
    };
    alternatives
        .value
        .general_names
        .iter()
        .filter_map(|name| match name {
            GeneralName::DNSName(dns) => Some(dns.to_string()),
            GeneralName::RFC822Name(mail) => Some(mail.to_string()),
            GeneralName::OtherName(..) => None,
            _ => None,
        })
        .collect()
}

/// A request's state, as its pill says it.
pub fn request_state(status: RequestStatus) -> &'static str {
    match status {
        RequestStatus::Pending => "Waiting",
        RequestStatus::Issued => "Issued",
        RequestStatus::Denied => "Denied",
    }
}

/// An RFC 5280 revocation reason, as a person reads it.
pub fn reason(code: u8) -> &'static str {
    match code {
        1 => "Key Compromise",
        2 => "CA Compromise",
        3 => "Affiliation Changed",
        4 => "Superseded",
        5 => "Cessation of Operation",
        6 => "Certificate Hold",
        9 => "Privilege Withdrawn",
        10 => "AA Compromise",
        _ => "Unspecified",
    }
}

/// A serial number as hex, grouped as certificate viewers show it.
pub fn serial(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_and_distances_read_plainly() {
        assert_eq!(date(1_800_000_000), "15 January 2027");
        assert_eq!(relative(10 * DAY, 0), "in 10 days");
        assert_eq!(relative(0, 2 * 3_600), "2 hours ago");
        assert_eq!(relative(400 * DAY, 0), "in 13 months");
        assert_eq!(count(2, "authority"), "2 authorities");
        assert_eq!(count(1, "day"), "1 day");
        assert_eq!(count(3, "day"), "3 days");
    }

    #[test]
    fn rights_are_listed_in_words() {
        assert_eq!(access(0), "None");
        assert_eq!(access(REQUEST), "Request");
        assert_eq!(
            access(0xf),
            "Request, Read, Issue and Manage Certificates and Manage CA"
        );
    }
}
