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

/// The keys of the seed `name` in `registry.d`, by path.
fn seed(name: &str) -> Vec<serde_json::Value> {
    let path = format!("{}/../registry.d/{name}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{path}: {error}"));
    let seed: serde_json::Value = serde_json::from_str(&text).unwrap();
    seed["keys"].as_array().unwrap().clone()
}

fn key<'a>(keys: &'a [serde_json::Value], path: &str) -> &'a serde_json::Value {
    keys.iter()
        .find(|key| key["path"] == path)
        .unwrap_or_else(|| panic!("no key {path}"))
}

fn multi(key: &serde_json::Value, name: &str) -> Option<Vec<String>> {
    key["values"]
        .as_array()?
        .iter()
        .find(|value| value["name"] == name)
        .map(|value| {
            value["data"]
                .as_array()
                .unwrap()
                .iter()
                .map(|item| item.as_str().unwrap().to_owned())
                .collect()
        })
}

#[test]
fn the_package_defines_the_services_setup_turns_on_and_starts_none() {
    let services = seed("pki-services.reg");
    for service in provision::SERVICES {
        let definition = key(&services, &format!("Machine\\System\\Services\\{service}"));
        assert_eq!(multi(definition, "Triggers"), None, "{service}");
    }
}

#[test]
fn the_policy_grants_each_service_what_it_keeps() {
    let services = seed("pki-services.reg");
    let policy = seed("pki-policy.reg");
    for (service, sid) in [
        ("pkid", SERVICE_SID),
        ("pki-httpd", pkid_core::HTTPD_SERVICE_SID),
    ] {
        let definition = key(&services, &format!("Machine\\System\\Services\\{service}"));
        let kept = multi(definition, "RequiredPrivileges").unwrap();
        let granted = multi(
            key(&policy, &format!("Machine\\Generic\\Authn\\Policy\\{sid}")),
            "Privileges",
        )
        .unwrap();
        assert_eq!(kept, granted, "{service}");
    }
}
