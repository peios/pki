//! What provisioning builds with libpeios that needs no Peios kernel. The
//! Registry and directory writes themselves are qualified in a Peios guest.

use peios::security::sddl;
use pki_management::provision;
use pkid_core::SERVICE_SID;

#[test]
fn every_descriptor_provisioning_writes_parses() {
    for text in [
        provision::state_dacl(),
        provision::keys_dacl(),
        provision::authorities_grant(),
        provision::http_dacl(),
        provision::http_grant(),
        provision::port_reservation(),
    ] {
        sddl::parse(&text).unwrap_or_else(|error| panic!("{text}: {error}"));
    }
}

#[test]
fn only_pkid_gets_full_access_to_its_keys() {
    let dacl = provision::keys_dacl();
    assert!(dacl.starts_with("D:P"), "{dacl}");
    assert!(
        dacl.contains(&format!("(A;OICI;FA;;;{SERVICE_SID})")),
        "{dacl}"
    );
    assert_eq!(dacl.matches(";FA;").count(), 1, "{dacl}");
}
