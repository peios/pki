//! What pkid builds with libpeios that needs no Peios kernel: descriptors,
//! inheritance and recorded identities. Access checks themselves are
//! qualified in a Peios guest.

use std::path::Path;

use peios::msgpack::Writer;
use peios::security::sddl;
use pki_pipeline::{Principal, DEFAULT_CA_SDDL};
use pki_policy::{SecurityBlob, DEFAULT_NAME_ROOT_SDDL, DEFAULT_TEMPLATE_ENROLL_SDDL};
use pkid::identity::Recorded;
use pkid::keystore::ServiceKeyFiles;
use pkid::{provision, service};
use pkid_core::SERVICE_SID;

#[test]
fn every_descriptor_pkid_builds_parses() {
    let keys = ServiceKeyFiles::new(Path::new(service::KEYS_DIR), SERVICE_SID);
    for text in [
        DEFAULT_CA_SDDL.to_string(),
        pkid::config::DEFAULT_MANAGE_SDDL.to_string(),
        DEFAULT_NAME_ROOT_SDDL.to_string(),
        DEFAULT_TEMPLATE_ENROLL_SDDL.to_string(),
        keys.file_descriptor(),
        provision::state_dacl(),
        provision::keys_dacl(),
        provision::authorities_grant(),
    ] {
        sddl::parse(&text).unwrap_or_else(|error| panic!("{text}: {error}"));
    }
    // Startup takes these on trust.
    service::defaults();
}

#[test]
fn the_service_sid_is_a_sid() {
    let sid: peios::security::Sid = SERVICE_SID.parse().unwrap();
    assert_eq!(sid.to_string(), SERVICE_SID);
}

fn snapshot(user: &str, groups: &[(&str, u32)]) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.write_array(2).write_str(user);
    writer.write_array(groups.len() as u32);
    for (sid, attributes) in groups {
        writer
            .write_array(2)
            .write_str(sid)
            .write_uint(u64::from(*attributes));
    }
    writer.to_bytes().unwrap()
}

#[test]
fn recorded_identities_round_trip() {
    let bytes = snapshot(
        "S-1-5-21-1-2-3-1001",
        &[("S-1-5-32-544", 0x7), ("S-1-5-11", 0x7)],
    );
    let recorded = Recorded::decode(&bytes).unwrap();
    assert_eq!(recorded.sid().as_str(), "S-1-5-21-1-2-3-1001");
    assert_eq!(recorded.snapshot().unwrap(), bytes);
}

#[test]
fn damaged_recorded_identities_are_refused() {
    assert!(Recorded::decode(b"").is_err());
    assert!(Recorded::decode(&snapshot("not a SID", &[])).is_err());
    let mut writer = Writer::new();
    writer
        .write_array(3)
        .write_str("S-1-5-11")
        .write_nil()
        .write_nil();
    assert!(Recorded::decode(&writer.to_bytes().unwrap()).is_err());
}

#[test]
fn names_inherit_only_container_entries() {
    let parent = sddl::parse("O:SYG:SYD:(A;CI;0x1;;;PS)(A;CI;0x7;;;BA)(A;;0x7;;;SY)").unwrap();
    let recorded = Recorded::decode(&snapshot("S-1-5-11", &[])).unwrap();
    let child = recorded
        .checker()
        .inherit(&SecurityBlob::new(parent.as_bytes().to_vec()))
        .unwrap();
    let text = sddl::format(child.as_bytes()).unwrap();
    assert!(text.contains(";PS)"), "{text}");
    assert!(text.contains(";BA)"), "{text}");
    assert!(!text.contains(";SY)"), "{text}");

    // And again one level further down, as for a grandchild name.
    let grandchild = recorded.checker().inherit(&child).unwrap();
    let text = sddl::format(grandchild.as_bytes()).unwrap();
    assert!(text.contains(";PS)") && text.contains(";BA)"), "{text}");
}
