//! Who may do what, in words: the people behind SIDs, and descriptors as a
//! line a person reads instead of SDDL.

use std::collections::HashMap;

use peios::security::{AceType, SdView};

use super::seen::{Person, Seen};

const GENERIC_ALL: u32 = 0x1000_0000;

/// What well-known SIDs are called here.
fn well_known(sid: &str) -> Option<&'static str> {
    Some(match sid {
        "S-1-1-0" => "Everyone",
        "S-1-5-7" => "Anonymous Logon",
        "S-1-5-10" => "Owner",
        "S-1-5-11" => "Authenticated Users",
        "S-1-5-18" => "SYSTEM",
        "S-1-5-32-544" => "Administrators",
        "S-1-5-32-545" => "Users",
        pkid_core::SERVICE_SID => "Certificate Service",
        _ => return None,
    })
}

/// Who `sid` is, as a person reads it: a well-known name, the display name
/// authd has, their account, or the SID itself.
pub fn who(sid: &str, people: &HashMap<String, Person>) -> String {
    if let Some(name) = well_known(sid) {
        return name.to_string();
    }
    match people.get(sid) {
        Some(Person {
            display: Some(display),
            ..
        }) => display.clone(),
        Some(person) => person.account.clone(),
        None => sid.to_string(),
    }
}

/// Who `sid` is, with their account when they have a display name too:
/// "Alice Liddell (home\alice)".
pub fn who_in_full(sid: &str, people: &HashMap<String, Person>) -> String {
    match people.get(sid) {
        Some(Person {
            display: Some(display),
            account,
        }) => format!("{display} ({account})"),
        _ => who(sid, people),
    }
}

/// One allow entry of a descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub sid: String,
    pub mask: u32,
}

/// The rights each trustee is allowed, merged, in the descriptor's order.
/// Deny entries are left out: none of pki's defaults use them, and the
/// permissions editor shows them in full.
pub fn grants(security: &[u8]) -> Vec<Grant> {
    let Ok(view) = SdView::parse(security) else {
        return Vec::new();
    };
    let Some(dacl) = view.dacl() else {
        return Vec::new();
    };
    let mut grants: Vec<Grant> = Vec::new();
    for ace in dacl.iter() {
        if ace.ace_type() != AceType::AccessAllowed {
            continue;
        }
        let Some(sid) = ace.sid().map(|sid| sid.to_string()) else {
            continue;
        };
        let mask = ace.mask();
        match grants.iter_mut().find(|grant| grant.sid == sid) {
            Some(grant) => grant.mask |= mask,
            None => grants.push(Grant { sid, mask }),
        }
    }
    grants
}

/// Whether a descriptor has deny entries, which a summary leaves out.
pub fn denies(security: &[u8]) -> bool {
    SdView::parse(security)
        .ok()
        .and_then(|view| {
            view.dacl().map(|dacl| {
                dacl.iter()
                    .any(|ace| ace.ace_type() == AceType::AccessDenied)
            })
        })
        .unwrap_or(false)
}

/// "A", "A and B", "A, B and C".
pub fn and(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [only] => only.clone(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// Who may request a name under its descriptor, in a line: "Owner,
/// Administrators and SYSTEM · Authenticated Users with approval".
pub fn name_requesters(security: &[u8], people: &HashMap<String, Person>) -> String {
    let mut direct = Vec::new();
    let mut approval = Vec::new();
    for grant in grants(security) {
        let all = grant.mask & GENERIC_ALL != 0;
        if all || grant.mask & pki_policy::NAME_REQUEST != 0 {
            direct.push(who(&grant.sid, people));
        } else if grant.mask & pki_policy::NAME_REQUEST_WITH_APPROVAL != 0 {
            approval.push(who(&grant.sid, people));
        }
    }
    let mut parts = Vec::new();
    if !direct.is_empty() {
        parts.push(and(&direct));
    }
    if !approval.is_empty() {
        parts.push(format!("{} with approval", and(&approval)));
    }
    if parts.is_empty() {
        "Nobody".to_string()
    } else {
        parts.join(" · ")
    }
}

/// Who may request from a template, in a line.
pub fn enrollers(security: &[u8], people: &HashMap<String, Person>) -> String {
    let who: Vec<String> = grants(security)
        .into_iter()
        .filter(|grant| grant.mask & (pki_policy::TEMPLATE_ENROLL | GENERIC_ALL) != 0)
        .map(|grant| who(&grant.sid, people))
        .collect();
    if who.is_empty() {
        "Nobody".to_string()
    } else {
        and(&who)
    }
}

/// Who may create and import authorities, in a line.
pub fn creators(security: &[u8], people: &HashMap<String, Person>) -> String {
    let who: Vec<String> = grants(security)
        .into_iter()
        .filter(|grant| grant.mask & (crate::show::MANAGE | GENERIC_ALL) != 0)
        .map(|grant| who(&grant.sid, people))
        .collect();
    if who.is_empty() {
        "Nobody".to_string()
    } else {
        and(&who)
    }
}

/// Who may do what at a CA, in a line: "Authenticated Users request ·
/// Administrators and SYSTEM manage".
pub fn ca_users(security: &[u8], people: &HashMap<String, Person>) -> String {
    use crate::show::{MANAGE, OFFICER, READ, REQUEST};
    let mut tiers: [(&str, Vec<String>); 4] = [
        ("manage", Vec::new()),
        ("approve and revoke", Vec::new()),
        ("read", Vec::new()),
        ("request", Vec::new()),
    ];
    for grant in grants(security) {
        let mask = if grant.mask & GENERIC_ALL != 0 {
            0xf
        } else {
            grant.mask
        };
        let tier = if mask & MANAGE != 0 {
            0
        } else if mask & OFFICER != 0 {
            1
        } else if mask & READ != 0 {
            2
        } else if mask & REQUEST != 0 {
            3
        } else {
            continue;
        };
        tiers[tier].1.push(who(&grant.sid, people));
    }
    let parts: Vec<String> = tiers
        .iter()
        .rev()
        .filter(|(_, who)| !who.is_empty())
        .map(|(what, who)| format!("{} {what}", and(who)))
        .collect();
    if parts.is_empty() {
        "Nobody".to_string()
    } else {
        parts.join(" · ")
    }
}

/// The broad groups, such as Authenticated Users, that a name's own
/// entries let request it without approval (rule R1).
pub fn broad_requesters(security: &[u8]) -> Vec<String> {
    let Ok(view) = SdView::parse(security) else {
        return Vec::new();
    };
    let Some(dacl) = view.dacl() else {
        return Vec::new();
    };
    let mut groups = Vec::new();
    for ace in dacl.iter() {
        let own = !ace.flags().contains(peios::security::AceFlags::INHERITED);
        let grants = ace.mask() & (pki_policy::NAME_REQUEST | GENERIC_ALL) != 0;
        if ace.ace_type() != AceType::AccessAllowed || !own || !grants {
            continue;
        }
        let Some(sid) = ace.sid().map(|sid| sid.to_string()) else {
            continue;
        };
        let broad = matches!(
            sid.as_str(),
            "S-1-1-0" | "S-1-5-7" | "S-1-5-11" | "S-1-5-32-545"
        ) || (sid.starts_with("S-1-5-21-") && sid.ends_with("-513"));
        if broad {
            let name = well_known(&sid).unwrap_or("Domain Users").to_string();
            if !groups.contains(&name) {
                groups.push(name);
            }
        }
    }
    groups
}

/// Every SID the window may show from what it has read: in descriptors,
/// as owners, and as requesters of waiting requests.
pub fn sids(seen: &Seen) -> Vec<String> {
    let mut sids = Vec::new();
    let mut from = |security: &[u8]| {
        sids.extend(grants(security).into_iter().map(|grant| grant.sid));
    };
    for authority in seen.authorities() {
        from(&authority.security);
    }
    if let Ok(config) = &seen.config {
        if let Ok(Some(security)) = config.settings.binary("ManageSecurity") {
            from(security);
        }
        for (_, values) in &config.templates {
            if let Ok(Some(security)) = values.binary("EnrollSecurity") {
                from(security);
            }
        }
        for (_, values) in config.dns.iter().chain(&config.principals) {
            if let Ok(Some(security)) = values.binary("RequestSecurity") {
                from(security);
            }
        }
    }
    if let Ok(config) = &seen.config {
        for (_, values) in config.dns.iter().chain(&config.principals) {
            if let Ok(Some(owner)) = values.sz("Owner") {
                sids.push(owner.to_string());
            }
        }
    }
    for requests in seen.waiting.values() {
        sids.extend(requests.iter().map(|request| request.requester.clone()));
    }
    sids.retain(|sid| well_known(sid).is_none());
    sids.sort();
    sids.dedup();
    sids
}
