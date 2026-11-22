//! The name trees: who may request certificates for which names, and who
//! owns them.

use gxwi::settings::{self, Glyph, Kind, Tile, Tone};
use gxwi::Fields;
use pki_management::names::NamePath;
use pki_management::{security, Snapshot};
use pki_policy::{SecurityBlob, TreeKind, Values};

use super::{describe, service, words, Window};

/// The Names section's line in the side.
pub fn summary(window: &Window) -> String {
    match &window.seen.config {
        Ok(config) => {
            let domains = domains(config).len() as i64;
            let names = words::count((config.dns.len() + config.principals.len()) as i64, "name");
            if domains > 0 {
                format!("{names} · {}", words::count(domains, "domain"))
            } else {
                names
            }
        }
        Err(_) => "Can't be read".into(),
    }
}

pub fn domains(config: &Snapshot) -> Vec<String> {
    config
        .settings
        .multi_sz("PrincipalDomains")
        .map(<[String]>::to_vec)
        .unwrap_or_default()
}

fn nodes(config: &Snapshot, tree: TreeKind) -> &[(Vec<String>, Values)] {
    match tree {
        TreeKind::Dns => &config.dns,
        TreeKind::Principal => &config.principals,
    }
}

fn values<'a>(config: &'a Snapshot, name: &NamePath) -> Option<&'a Values> {
    nodes(config, name.tree)
        .iter()
        .find(|(path, _)| *path == name.path)
        .map(|(_, values)| values)
}

/// Who may request `name`: its own descriptor, or what it inherits.
fn requesters(config: &Snapshot, name: &NamePath) -> Option<(SecurityBlob, usize)> {
    let effective = security::effective(nodes(config, name.tree), &name.path).ok()?;
    Some((effective.security, effective.inherited_levels))
}

fn owner(window: &Window, config: &Snapshot, name: &NamePath) -> String {
    if let Some(owner) = values(config, name).and_then(|v| v.sz("Owner").ok().flatten()) {
        return window.who(owner);
    }
    // A principal name in a listed domain belongs to the account it names.
    if name.tree == TreeKind::Principal {
        if let Some(user) = name.path.last().and_then(|last| last.strip_prefix('@')) {
            let domain: Vec<&str> = name.path[..name.path.len() - 1]
                .iter()
                .rev()
                .map(String::as_str)
                .collect();
            let domain = domain.join(".");
            if domains(config)
                .iter()
                .any(|d| d.eq_ignore_ascii_case(&domain))
            {
                return format!("The account {user}");
            }
        }
    }
    "None".into()
}

fn tree_rows(window: &Window, config: &Snapshot, tree: TreeKind, find: &str) -> String {
    let mut names: Vec<NamePath> = nodes(config, tree)
        .iter()
        .map(|(path, _)| NamePath {
            tree,
            path: path.clone(),
        })
        .collect();
    if !names.iter().any(|name| name.path.is_empty()) {
        names.push(NamePath::root(tree));
    }
    // Each name beneath the one above it.
    names.sort_by(|a, b| a.path.cmp(&b.path));
    let find = find.trim().to_lowercase();
    let mut rows = String::new();
    for name in names {
        let shown = name.display();
        if !find.is_empty() && !shown.contains(&find) {
            continue;
        }
        let Some((security, inherited)) = requesters(config, &name) else {
            continue;
        };
        let who = describe::name_requesters(security.as_bytes(), &window.people);
        let line = if inherited == 0 {
            who
        } else {
            format!("{who} · inherited")
        };
        let owner = values(config, &name).and_then(|v| v.sz("Owner").ok().flatten());
        let aside = match owner {
            Some(owner) => settings::pill(&window.who(owner), Tone::Plain),
            None => String::new(),
        };
        let title = match (tree, name.path.is_empty()) {
            (TreeKind::Dns, true) => "Every Network Name".to_string(),
            (TreeKind::Principal, true) => "Every Account Name".to_string(),
            _ => shown.clone(),
        };
        let depth = name.path.len().min(4);
        rows.push_str(
            &settings::link(
                &settings::icon(Glyph::Tag, Tile::Teal),
                &title,
                &[(&line, false)],
                &aside,
                "name",
                &[("name", &shown)],
            )
            .replacen(
                "class=\"st-row link\"",
                &format!("class=\"st-row link pki-depth-{depth}\""),
                1,
            ),
        );
    }
    if rows.is_empty() {
        rows.push_str(&settings::row("", "", &settings::none("Nothing matches.")));
    }
    rows
}

pub fn list(window: &Window, fields: &Fields) -> String {
    let mut page = settings::head(
        Glyph::Tag,
        Tile::Teal,
        "Names",
        "Who may request certificates for which names.",
    );
    let config = match &window.seen.config {
        Ok(config) => config,
        Err(why) => return page + &settings::banner(&format!("The names can't be read: {why}")),
    };
    if !window.seen.may.settings
        && window
            .seen
            .may
            .names
            .values()
            .all(|may| !may.edit && !may.add)
    {
        page.push_str(&settings::banner(
            "You can look, but you don't have permission to change who may request names.",
        ));
    }

    let listed = domains(config);
    let rows = settings::row(
        "Principal Domains",
        "In these domains, each account owns the names that are its own: alice@home belongs to the account alice, who may request certificates for it.",
        &if listed.is_empty() {
            settings::value("None", false)
        } else {
            settings::value(&listed.join(", "), true)
        },
    );
    page.push_str(&settings::group(
        "Accounts",
        &rows,
        &if window.seen.may.settings {
            String::new()
        } else {
            settings::locked("Only administrators can change the principal domains.")
        },
    ));

    page.push_str(&settings::search("find", "Find", "Find a name", ""));
    let find = fields.get("find");
    page.push_str(&settings::group(
        "Network Names",
        &tree_rows(window, config, TreeKind::Dns, find),
        &settings::hint("Host names such as radius.lab.home. A name without its own permissions inherits them from the name above it."),
    ));
    page.push_str(&settings::group(
        "Account Names",
        &tree_rows(window, config, TreeKind::Principal, find),
        &settings::hint("Names such as alice@home, for email and sign-in certificates."),
    ));
    page
}

pub fn page(window: &Window, text: &str) -> String {
    let mut page = settings::back("Names", "back");
    let Ok(config) = &window.seen.config else {
        return page;
    };
    let name = match NamePath::parse(text) {
        Ok(name) => name,
        Err(why) => return page + &settings::caution(&service::sentence(&why)),
    };
    let may = window.seen.may.names.get(&name.key()).copied();
    let editable = may.is_some_and(|may| may.edit);
    let shown = name.display();
    let kind = match (name.tree, name.path.last()) {
        (TreeKind::Dns, None) => "The root of every network name",
        (TreeKind::Principal, None) => "The root of every account name",
        (TreeKind::Dns, Some(_)) => "Network name",
        (TreeKind::Principal, Some(last)) if last.starts_with('@') => "Account name",
        (TreeKind::Principal, Some(_)) => "Account domain",
    };
    let Some((security, inherited)) = requesters(config, &name) else {
        return page
            + &settings::caution(
                "Who may request this name can't be worked out: its permissions are damaged.",
            );
    };
    page.push_str(&settings::hero(
        &settings::hero_title(Glyph::Tag, Tile::Teal, &shown, kind),
        &if inherited == 0 {
            settings::pill("Own Permissions", Tone::Plain)
        } else {
            settings::pill("Inherited", Tone::Plain)
        },
    ));
    if !editable {
        page.push_str(&settings::banner(
            "You can look, but you don't have permission to change this name.",
        ));
    }
    if inherited == 0 {
        let groups = describe::broad_requesters(security.as_bytes());
        if !groups.is_empty() {
            page.push_str(&settings::caution(&format!(
                "{} may request this name without approval. Consider Request with Approval instead, so an officer checks each one.",
                describe::and(&groups)
            )));
        }
        if name.path.is_empty() {
            for lost in security::lost_root_grants(security.as_bytes()).unwrap_or_default() {
                page.push_str(&settings::caution(if lost.starts_with("Administrators") {
                    "Administrators can't request certificates for names in this tree."
                } else {
                    "Owners can't request certificates for their own names in this tree."
                }));
            }
        }
    }

    let from = if inherited == 0 {
        "Its own".to_string()
    } else {
        let mut above = name.clone();
        for _ in 0..inherited {
            above = above.parent().unwrap_or(above.clone());
        }
        format!("Inherited from {}", above.display())
    };
    let mut rows = settings::row(
        "Who Can Request",
        &describe::name_requesters(security.as_bytes(), &window.people),
        &settings::button(
            if editable { "Edit…" } else { "View…" },
            "name-permissions",
            &[("name", &shown)],
            Kind::Plain,
            !window.busy,
        ),
    );
    rows.push_str(&settings::fact("Permissions", &from, false));
    page.push_str(&settings::group(
        "Requesting",
        &rows,
        &settings::hint(
            "Wildcards, such as *.lab.home, need the Wildcard right on lab.home as well.",
        ),
    ));
    page.push_str(&settings::group(
        "Owner",
        &settings::fact("Owner", &owner(window, config, &name), false),
        &settings::hint("The owner may request the name as their own, and certificates for it are bound to their account."),
    ));
    page
}
