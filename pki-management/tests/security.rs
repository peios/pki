//! The name trees' descriptors, as pkid resolves them.

use peios::security::sddl;
use pki_management::security::{broad_grants, broad_owner, effective, fold};
use pki_policy::{RegData, SecurityBlob, Values, DEFAULT_NAME_ROOT_SDDL};

fn blob(text: &str) -> SecurityBlob {
    SecurityBlob::new(sddl::parse(text).unwrap().as_bytes().to_vec())
}

fn node(path: &[&str], security: Option<&str>) -> (Vec<String>, Values) {
    let mut values = Values::new();
    if let Some(text) = security {
        values.insert(
            "RequestSecurity",
            RegData::Binary(blob(text).as_bytes().to_vec()),
        );
    }
    (path.iter().map(|p| p.to_string()).collect(), values)
}

fn path(segments: &[&str]) -> Vec<String> {
    segments.iter().map(|s| s.to_string()).collect()
}

#[test]
fn a_name_takes_the_nearest_descriptor_through_each_level() {
    let nodes = vec![
        node(&[], Some(DEFAULT_NAME_ROOT_SDDL)),
        node(&["home"], None),
        node(&["home", "lab"], Some("O:SYG:SYD:(A;CI;0x2;;;AU)")),
    ];
    let below = effective(&nodes, &path(&["home", "lab", "www"])).unwrap();
    assert_eq!(below.inherited_levels, 1);
    let text = sddl::format(below.security.as_bytes()).unwrap();
    assert!(text.contains(";AU)"), "{text}");
    // The lab node's own value replaced the root's, as pkid applies it.
    assert!(!text.contains(";BA)"), "{text}");

    let home = effective(&nodes, &path(&["home"])).unwrap();
    assert_eq!(home.inherited_levels, 1);
    assert!(sddl::format(home.security.as_bytes())
        .unwrap()
        .contains(";BA)"));
    assert!(effective(&[], &[]).is_err());
}

#[test]
fn folding_keeps_the_inherited_entries() {
    let root = blob(DEFAULT_NAME_ROOT_SDDL);
    let own = sddl::parse("D:(A;CI;0x1;;;AU)").unwrap();
    let folded = fold(&root, own.as_bytes()).unwrap();
    let text = sddl::format(folded.as_bytes()).unwrap();
    assert!(
        text.contains(";AU)") && text.contains(";BA)") && text.contains(";PS)"),
        "{text}"
    );
    // Only the name's own grant to a broad group is warned of, not what
    // it inherited.
    assert_eq!(broad_grants(folded.as_bytes()).unwrap().len(), 1);
    assert!(broad_grants(root.as_bytes()).unwrap().is_empty());
    let approval = sddl::parse("D:(A;CI;0x2;;;WD)").unwrap();
    assert!(broad_grants(approval.as_bytes()).unwrap().is_empty());
}

#[test]
fn broad_owners_are_named() {
    assert!(broad_owner("S-1-5-11").is_some());
    assert!(broad_owner("S-1-5-21-1-2-3-513").is_some());
    assert!(broad_owner("S-1-5-21-1-2-3-1001").is_none());
}
