//! The templates and name-tree roots a new CA starts with.

use crate::access::SecurityBlob;
use crate::values::{RegData, Values};

/// Server certificates: TLS server authentication for DNS names. They last
/// 90 days, with renewal due in the last 30.
pub fn server_template(enroll_security: &SecurityBlob) -> Values {
    template(TemplateDefaults {
        name: "Server",
        purposes: &["server-auth"],
        name_types: &["dns"],
        lifetime_days: 90,
        enroll_security,
    })
}

/// Device certificates: client authentication, as EAP-TLS uses, for UPN and
/// email names. They last a year, with renewal due in the last 30 days.
pub fn device_template(enroll_security: &SecurityBlob) -> Values {
    template(TemplateDefaults {
        name: "Device",
        purposes: &["client-auth"],
        name_types: &["upn", "email"],
        lifetime_days: 365,
        enroll_security,
    })
}

/// The values of a name tree's root: its `RequestSecurity`, normally built
/// from [`DEFAULT_NAME_ROOT_SDDL`](crate::DEFAULT_NAME_ROOT_SDDL).
pub fn name_root(request_security: &SecurityBlob) -> Values {
    let mut values = Values::new();
    values.insert(
        "RequestSecurity",
        RegData::Binary(request_security.as_bytes().to_vec()),
    );
    values
}

struct TemplateDefaults<'a> {
    name: &'a str,
    purposes: &'a [&'a str],
    name_types: &'a [&'a str],
    lifetime_days: u32,
    enroll_security: &'a SecurityBlob,
}

const RENEWAL_WINDOW_DAYS: u32 = 30;

fn template(defaults: TemplateDefaults<'_>) -> Values {
    let list =
        |items: &[&str]| RegData::MultiSz(items.iter().map(|item| item.to_string()).collect());
    let mut values = Values::new();
    values.insert("Name", RegData::Sz(defaults.name.into()));
    values.insert("Purposes", list(defaults.purposes));
    values.insert("KeyUsages", list(&["digital-signature"]));
    values.insert("LifetimeDays", RegData::Dword(defaults.lifetime_days));
    values.insert("RenewalWindowDays", RegData::Dword(RENEWAL_WINDOW_DAYS));
    values.insert(
        "KeyAlgorithms",
        list(&["ecdsa-p256", "ecdsa-p384", "rsa-2048"]),
    );
    values.insert("NameTypes", list(defaults.name_types));
    values.insert("CommonName", RegData::Sz("first-name".into()));
    values.insert("Issuance", RegData::Sz("immediate".into()));
    values.insert(
        "EnrollSecurity",
        RegData::Binary(defaults.enroll_security.as_bytes().to_vec()),
    );
    values
}
