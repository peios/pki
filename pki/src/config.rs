//! The template and name commands, which change pki's configuration in the
//! Registry directly: pkid takes each change up as soon as it is written.
//! Every change is checked by pki-policy's own rules before it is written,
//! since pkid issues nothing while any of its configuration is invalid.

use std::io;

use peios::security::sddl;
use pki_management::names::NamePath;
use pki_management::{security, Snapshot, ROOT};
use pki_policy::{
    NameNode, NameTree, RegData, SecurityBlob, Template, TreeKind, Values,
    DEFAULT_TEMPLATE_ENROLL_SDDL,
};
use serde_json::{json, Value};

use crate::cli::{NameCommand, TemplateCommand, TemplateFields};
use crate::failure::{Failure, Kind};
use crate::host::Host;
use crate::show::{self, Output};

pub fn snapshot(host: &dyn Host) -> Result<Snapshot, Failure> {
    host.snapshot()
        .map_err(|error| Failure::io(&error).context("reading the configuration"))
}

fn written(error: io::Error, what: &str) -> Failure {
    let failure = Failure::io(&error).context(what);
    if failure.kind == Kind::Denied {
        failure.hint("Only an administrator can change pki's configuration.")
    } else {
        failure
    }
}

fn sz<'a>(values: &'a Values, name: &str) -> &'a str {
    values.sz(name).ok().flatten().unwrap_or("")
}

fn list<'a>(values: &'a Values, name: &str) -> &'a [String] {
    values.multi_sz(name).unwrap_or(&[])
}

fn dword(values: &Values, name: &str) -> Option<u32> {
    values.dword(name).ok().flatten()
}

/// A descriptor in SDDL, or a note that it can't be read.
fn sddl_text(bytes: &[u8]) -> String {
    sddl::format(bytes).unwrap_or_else(|_| "(not a valid descriptor)".to_string())
}

/// The descriptor `text` gives, with SYSTEM as its owner and group where it
/// names none, as every descriptor pki and pkid write has them.
pub(crate) fn parse_sddl(text: &str) -> Result<Vec<u8>, Failure> {
    let invalid = |error: peios::Error| {
        Failure::usage(format!("'{text}' is not a valid descriptor: {error}"))
    };
    let parsed = sddl::parse(text).map_err(invalid)?;
    let view = peios::security::SdView::parse(parsed.as_bytes()).map_err(invalid)?;
    if view.owner().is_some() && view.group().is_some() {
        return Ok(parsed.as_bytes().to_vec());
    }
    let owner = view.owner().map_or("SY".to_string(), |sid| sid.to_string());
    let group = view.group().map_or("SY".to_string(), |sid| sid.to_string());
    let canonical = sddl::format(parsed.as_bytes()).map_err(invalid)?;
    let lists = canonical
        .find("D:")
        .or_else(|| canonical.find("S:"))
        .map_or("", |at| &canonical[at..]);
    sddl::parse(&format!("O:{owner}G:{group}{lists}"))
        .map(|sd| sd.as_bytes().to_vec())
        .map_err(invalid)
}

// Templates.

/// The template `text` names, by GUID or name, with its values.
pub fn resolve_template(snapshot: &Snapshot, text: &str) -> Result<(String, Values), Failure> {
    if let Some((id, values)) = snapshot
        .templates
        .iter()
        .find(|(id, _)| id.eq_ignore_ascii_case(text))
    {
        return Ok((id.clone(), values.clone()));
    }
    let named: Vec<_> = snapshot
        .templates
        .iter()
        .filter(|(_, values)| sz(values, "Name").to_lowercase() == text.to_lowercase())
        .collect();
    match named.as_slice() {
        [(id, values)] => Ok((id.clone(), values.clone())),
        [] => Err(Failure::new(
            Kind::NotFound,
            format!("no template '{text}'"),
        )),
        _ => Err(
            Failure::usage(format!("more than one template is named '{text}'"))
                .hint("Name the template by its GUID."),
        ),
    }
}

/// The names of the CAs that issue from template `id`.
fn users(snapshot: &Snapshot, id: &str) -> Vec<String> {
    snapshot
        .authorities
        .iter()
        .filter(|(_, values)| {
            list(values, "Templates")
                .iter()
                .any(|template| template.eq_ignore_ascii_case(id))
        })
        .map(|(ca, values)| match sz(values, "Name") {
            "" => ca.clone(),
            name => name.to_owned(),
        })
        .collect()
}

fn template_json(snapshot: &Snapshot, id: &str, values: &Values) -> Value {
    json!({
        "id": id,
        "name": sz(values, "Name"),
        "purposes": list(values, "Purposes"),
        "key_usages": list(values, "KeyUsages"),
        "lifetime_days": dword(values, "LifetimeDays"),
        "renewal_window_days": dword(values, "RenewalWindowDays").unwrap_or(0),
        "key_algorithms": list(values, "KeyAlgorithms"),
        "name_types": list(values, "NameTypes"),
        "common_name": values.sz("CommonName").ok().flatten().unwrap_or("first-name"),
        "issuance": values.sz("Issuance").ok().flatten().unwrap_or("immediate"),
        "enroll_security": values.binary("EnrollSecurity").ok().flatten().map(sddl_text),
        "used_by": users(snapshot, id),
    })
}

fn template_text(snapshot: &Snapshot, id: &str, values: &Values) -> String {
    let used = users(snapshot, id);
    show::fields(&[
        ("Name", sz(values, "Name").to_owned()),
        ("GUID", id.to_owned()),
        ("Purposes", list(values, "Purposes").join(", ")),
        ("Key usages", list(values, "KeyUsages").join(", ")),
        (
            "Lifetime",
            dword(values, "LifetimeDays").map_or(String::new(), |days| format!("{days} days")),
        ),
        (
            "Renewal due",
            format!(
                "{} days before expiry",
                dword(values, "RenewalWindowDays").unwrap_or(0)
            ),
        ),
        ("Keys", list(values, "KeyAlgorithms").join(", ")),
        ("Names", list(values, "NameTypes").join(", ")),
        (
            "Common name",
            values
                .sz("CommonName")
                .ok()
                .flatten()
                .unwrap_or("first-name")
                .to_owned(),
        ),
        (
            "Issuance",
            values
                .sz("Issuance")
                .ok()
                .flatten()
                .unwrap_or("immediate")
                .to_owned(),
        ),
        (
            "Enrollment",
            values
                .binary("EnrollSecurity")
                .ok()
                .flatten()
                .map_or(String::new(), sddl_text),
        ),
        (
            "Used by",
            if used.is_empty() {
                "no CA".to_string()
            } else {
                used.join(", ")
            },
        ),
    ])
}

/// The values `fields` sets.
fn field_values(fields: &TemplateFields) -> Result<Values, Failure> {
    let mut values = Values::new();
    let multi = |items: &[String]| RegData::MultiSz(items.to_vec());
    if !fields.purposes.is_empty() {
        values.insert("Purposes", multi(&fields.purposes));
    }
    if !fields.key_usages.is_empty() {
        values.insert("KeyUsages", multi(&fields.key_usages));
    }
    if let Some(days) = fields.lifetime {
        values.insert("LifetimeDays", RegData::Dword(days));
    }
    if let Some(days) = fields.renewal_window {
        values.insert("RenewalWindowDays", RegData::Dword(days));
    }
    if !fields.key_algorithms.is_empty() {
        values.insert("KeyAlgorithms", multi(&fields.key_algorithms));
    }
    if !fields.name_types.is_empty() {
        values.insert("NameTypes", multi(&fields.name_types));
    }
    if let Some(source) = &fields.common_name {
        values.insert("CommonName", RegData::Sz(source.clone()));
    }
    if let Some(issuance) = &fields.issuance {
        values.insert("Issuance", RegData::Sz(issuance.clone()));
    }
    if let Some(text) = &fields.enroll_security {
        values.insert("EnrollSecurity", RegData::Binary(parse_sddl(text)?));
    }
    Ok(values)
}

/// `values` with `changes` laid over them.
fn merged(values: &Values, changes: &Values) -> Values {
    let mut out = values.clone();
    for (name, data) in changes.iter() {
        out.insert(name, data.clone());
    }
    out
}

/// What a new template starts from without `--from`: the shipped
/// templates' choices for everything but what it is for.
fn template_defaults() -> Result<Values, Failure> {
    let mut values = Values::new();
    let multi = |items: &[&str]| RegData::MultiSz(items.iter().map(|i| i.to_string()).collect());
    values.insert("KeyUsages", multi(&["digital-signature"]));
    values.insert(
        "KeyAlgorithms",
        multi(&["ecdsa-p256", "ecdsa-p384", "rsa-2048"]),
    );
    values.insert("CommonName", RegData::Sz("first-name".into()));
    values.insert("Issuance", RegData::Sz("immediate".into()));
    values.insert(
        "EnrollSecurity",
        RegData::Binary(parse_sddl(DEFAULT_TEMPLATE_ENROLL_SDDL)?),
    );
    Ok(values)
}

/// Refuses a template pkid wouldn't load.
fn check_template(values: &Values) -> Result<(), Failure> {
    Template::from_values(values)
        .map(|_| ())
        .map_err(|error| Failure::usage(error.to_string()))
}

fn name_taken(snapshot: &Snapshot, name: &str, except: Option<&str>) -> Result<(), Failure> {
    let taken = snapshot.templates.iter().any(|(id, values)| {
        Some(id.as_str()) != except && sz(values, "Name").to_lowercase() == name.to_lowercase()
    });
    if taken {
        return Err(Failure::new(
            Kind::Exists,
            format!("a template is already named '{name}'"),
        ));
    }
    Ok(())
}

pub fn template(host: &dyn Host, command: TemplateCommand) -> Result<Output, Failure> {
    let snapshot = snapshot(host)?;
    match command {
        TemplateCommand::List => {
            let text = if snapshot.templates.is_empty() {
                "No templates. Add the defaults with: pki setup\n".to_string()
            } else {
                let rows: Vec<Vec<String>> = snapshot
                    .templates
                    .iter()
                    .map(|(id, values)| {
                        vec![
                            sz(values, "Name").to_owned(),
                            id.clone(),
                            values
                                .sz("Issuance")
                                .ok()
                                .flatten()
                                .unwrap_or("immediate")
                                .to_owned(),
                            dword(values, "LifetimeDays").map_or(String::new(), |d| d.to_string()),
                            list(values, "Purposes").join(", "),
                        ]
                    })
                    .collect();
                show::table(&["NAME", "GUID", "ISSUANCE", "DAYS", "PURPOSES"], &rows)
            };
            Ok(Output {
                json: json!({
                    "templates": snapshot.templates.iter()
                        .map(|(id, values)| template_json(&snapshot, id, values))
                        .collect::<Vec<_>>(),
                }),
                text,
            })
        }

        TemplateCommand::Show { template } => {
            let (id, values) = resolve_template(&snapshot, &template)?;
            Ok(Output {
                json: template_json(&snapshot, &id, &values),
                text: template_text(&snapshot, &id, &values),
            })
        }

        TemplateCommand::Create { name, from, fields } => {
            let what = format!("create {name}");
            name_taken(&snapshot, &name, None)?;
            let base = match &from {
                Some(from) => resolve_template(&snapshot, from)?.1,
                None => {
                    if fields.purposes.is_empty()
                        || fields.name_types.is_empty()
                        || fields.lifetime.is_none()
                    {
                        return Err(Failure::usage(format!(
                            "{what}: give --purpose, --name-type and --lifetime, or --from"
                        )));
                    }
                    template_defaults()?
                }
            };
            let mut values = merged(&base, &field_values(&fields)?);
            values.insert("Name", RegData::Sz(name.clone()));
            check_template(&values).map_err(|failure| failure.context(&what))?;
            let id = host
                .new_guid()
                .map_err(|error| Failure::io(&error).context(&what))?;
            host.create(&format!("{ROOT}\\Templates\\{id}"), &values)
                .map_err(|error| written(error, &what))?;
            Ok(Output {
                json: json!({"created": template_json(&snapshot, &id, &values)}),
                text: format!("Created template {name} ({id}).\n"),
            })
        }

        TemplateCommand::Set {
            template,
            name,
            fields,
        } => {
            let what = format!("set {template}");
            if fields.is_empty() && name.is_none() {
                return Err(Failure::usage(format!("{what}: nothing to change")));
            }
            let (id, values) = resolve_template(&snapshot, &template)?;
            let mut changes = field_values(&fields)?;
            if let Some(name) = &name {
                name_taken(&snapshot, name, Some(&id))?;
                changes.insert("Name", RegData::Sz(name.clone()));
            }
            let values = merged(&values, &changes);
            check_template(&values).map_err(|failure| failure.context(&what))?;
            host.change(&format!("{ROOT}\\Templates\\{id}"), &changes, &[])
                .map_err(|error| written(error, &what))?;
            Ok(Output {
                json: json!({"changed": template_json(&snapshot, &id, &values)}),
                text: template_text(&snapshot, &id, &values),
            })
        }

        TemplateCommand::Delete { template } => {
            let what = format!("delete {template}");
            let (id, values) = resolve_template(&snapshot, &template)?;
            let used = users(&snapshot, &id);
            if !used.is_empty() {
                return Err(Failure::failed(format!(
                    "{what}: CA {} issues from it",
                    used.join(", ")
                ))
                .hint("Stop each CA issuing from it first, with: pki ca set <ca> --template ..."));
            }
            host.delete(&format!("{ROOT}\\Templates\\{id}"))
                .map_err(|error| written(error, &what))?;
            Ok(Output {
                json: json!({"deleted": id}),
                text: format!("Deleted template {} ({id}).\n", sz(&values, "Name")),
            })
        }
    }
}

// Names.

fn nodes(snapshot: &Snapshot, tree: TreeKind) -> &[(Vec<String>, Values)] {
    match tree {
        TreeKind::Dns => &snapshot.dns,
        TreeKind::Principal => &snapshot.principals,
    }
}

fn same_path(a: &[String], b: &[String]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(a, b)| a.eq_ignore_ascii_case(b))
}

fn node<'a>(snapshot: &'a Snapshot, name: &NamePath) -> Option<&'a Values> {
    nodes(snapshot, name.tree)
        .iter()
        .find(|(path, _)| same_path(path, &name.path))
        .map(|(_, values)| values)
}

fn parse_name(text: &str) -> Result<NamePath, Failure> {
    NamePath::parse(text).map_err(Failure::usage)
}

/// A SID as a name's owner may be given.
fn parse_owner(text: &str) -> Result<String, Failure> {
    let sid: peios::security::Sid = text
        .parse()
        .map_err(|_| Failure::usage(format!("'{text}' is not a SID")))?;
    Ok(sid.to_string())
}

/// Refuses a tree pkid wouldn't load, with `name` changed to `values`
/// (or removed, for `None`).
fn check_tree(
    snapshot: &Snapshot,
    name: &NamePath,
    values: Option<&Values>,
) -> Result<(), Failure> {
    let mut records: Vec<(Vec<String>, Values)> = nodes(snapshot, name.tree)
        .iter()
        .filter(|(path, _)| !same_path(path, &name.path))
        .cloned()
        .collect();
    if let Some(values) = values {
        records.push((name.path.clone(), values.clone()));
    }
    let records = records
        .into_iter()
        .map(|(path, values)| NameNode::from_values(&values).map(|node| (path, node)))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| Failure::usage(error.to_string()))?;
    NameTree::new(name.tree, records)
        .map(|_| ())
        .map_err(|error| Failure::usage(error.to_string()))
}

fn effective(snapshot: &Snapshot, name: &NamePath) -> Result<security::Effective, Failure> {
    security::effective(nodes(snapshot, name.tree), &name.path)
        .map_err(|error| Failure::failed(format!("{}: {error}", name.display())))
}

fn name_json(snapshot: &Snapshot, name: &NamePath) -> Value {
    let values = node(snapshot, name);
    let effective = effective(snapshot, name).ok();
    json!({
        "name": name.display(),
        "tree": NamePath::tree_key(name.tree),
        "exists": values.is_some(),
        "owner": values.and_then(|v| v.sz("Owner").ok().flatten()),
        "security": effective.as_ref().map(|e| sddl_text(e.security.as_bytes())),
        "inherited": effective.as_ref().map(|e| e.inherited_levels > 0),
    })
}

fn name_text(snapshot: &Snapshot, name: &NamePath) -> Result<String, Failure> {
    let values = node(snapshot, name);
    let effective = effective(snapshot, name)?;
    let mut source = name.clone();
    for _ in 0..effective.inherited_levels {
        source = source.parent().expect("inheritance stops at the root");
    }
    let from = if effective.inherited_levels == 0 {
        "its own".to_string()
    } else {
        format!("inherited from {}", source.display())
    };
    Ok(show::fields(&[
        ("Name", name.display()),
        ("Tree", NamePath::tree_key(name.tree).to_owned()),
        (
            "Owner",
            values
                .and_then(|v| v.sz("Owner").ok().flatten())
                .unwrap_or("none")
                .to_owned(),
        ),
        ("Security", sddl_text(effective.security.as_bytes())),
        ("From", from),
    ]))
}

pub fn name(host: &dyn Host, command: NameCommand) -> Result<Output, Failure> {
    let snapshot = snapshot(host)?;
    match command {
        NameCommand::List => {
            let mut all: Vec<NamePath> = Vec::new();
            for tree in [TreeKind::Dns, TreeKind::Principal] {
                for (path, _) in nodes(&snapshot, tree) {
                    all.push(NamePath {
                        tree,
                        path: path.iter().map(|segment| segment.to_lowercase()).collect(),
                    });
                }
            }
            all.sort_by(|a, b| (a.tree as u8, &a.path).cmp(&(b.tree as u8, &b.path)));
            let rows: Vec<Vec<String>> = all
                .iter()
                .map(|name| {
                    let values = node(&snapshot, name);
                    vec![
                        name.display(),
                        values
                            .and_then(|v| v.sz("Owner").ok().flatten())
                            .unwrap_or("")
                            .to_owned(),
                        if values.and_then(|v| v.get("RequestSecurity")).is_some() {
                            "own".to_string()
                        } else {
                            "inherited".to_string()
                        },
                    ]
                })
                .collect();
            let text = if rows.is_empty() {
                "No names. Add the trees' roots with: pki setup\n".to_string()
            } else {
                show::table(&["NAME", "OWNER", "SECURITY"], &rows)
            };
            Ok(Output {
                json: json!({"names": all.iter().map(|n| name_json(&snapshot, n)).collect::<Vec<_>>()}),
                text,
            })
        }

        NameCommand::Show { name } => {
            let name = parse_name(&name)?;
            Ok(Output {
                json: name_json(&snapshot, &name),
                text: name_text(&snapshot, &name)?,
            })
        }

        NameCommand::Add { name, owner } => {
            let name = parse_name(&name)?;
            let what = format!("add {}", name.display());
            if node(&snapshot, &name).is_some() {
                return Err(Failure::new(
                    Kind::Exists,
                    format!("{what}: the name exists already"),
                ));
            }
            let mut values = Values::new();
            if let Some(owner) = &owner {
                values.insert("Owner", RegData::Sz(parse_owner(owner)?));
            }
            check_tree(&snapshot, &name, Some(&values)).map_err(|f| f.context(&what))?;
            host.create(&name.key(), &values)
                .map_err(|error| written(error, &what))?;
            if let Some(warning) = owner.as_deref().and_then(security::broad_owner) {
                host.warn(&warning);
            }
            Ok(Output {
                json: json!({"added": name_json(&snapshot, &name)}),
                text: format!("Added {}.\n", name.display()),
            })
        }

        NameCommand::Remove { name } => {
            let name = parse_name(&name)?;
            let what = format!("remove {}", name.display());
            if name.is_root() {
                return Err(Failure::usage(format!(
                    "{what}: a tree's root can't be removed"
                )));
            }
            if node(&snapshot, &name).is_none() {
                return Err(Failure::new(
                    Kind::NotFound,
                    format!("{what}: no such name"),
                ));
            }
            let below = nodes(&snapshot, name.tree).iter().any(|(path, _)| {
                path.len() > name.path.len() && same_path(&path[..name.path.len()], &name.path)
            });
            if below {
                return Err(
                    Failure::failed(format!("{what}: names are listed below it"))
                        .hint("Remove the names below it first."),
                );
            }
            host.delete(&name.key())
                .map_err(|error| written(error, &what))?;
            Ok(Output {
                json: json!({"removed": name.display()}),
                text: format!("Removed {}.\n", name.display()),
            })
        }

        NameCommand::SetSecurity {
            name,
            sddl: text,
            inherit,
        } => {
            let name = parse_name(&name)?;
            let what = format!("set-security {}", name.display());
            let mut values = node(&snapshot, &name).cloned().unwrap_or_default();
            if inherit {
                if name.is_root() {
                    return Err(Failure::usage(format!(
                        "{what}: a tree's root must have a descriptor of its own"
                    )));
                }
                if values.get("RequestSecurity").is_none() {
                    return Ok(Output {
                        json: json!({"changed": name_json(&snapshot, &name)}),
                        text: format!("{} already inherits its descriptor.\n", name.display()),
                    });
                }
                let mut kept = Values::new();
                for (value, data) in values
                    .iter()
                    .filter(|(value, _)| *value != "RequestSecurity")
                {
                    kept.insert(value, data.clone());
                }
                check_tree(&snapshot, &name, Some(&kept)).map_err(|f| f.context(&what))?;
                host.change(&name.key(), &Values::new(), &["RequestSecurity"])
                    .map_err(|error| written(error, &what))?;
                let changed = after(&snapshot, &name, Some(kept));
                return Ok(Output {
                    json: json!({"changed": name_json(&changed, &name)}),
                    text: name_text(&changed, &name)?,
                });
            }
            let own = parse_sddl(text.as_deref().expect("clap requires a descriptor"))?;
            let folded = match name.parent() {
                // A root inherits from nothing.
                None => SecurityBlob::new(own),
                Some(parent) => {
                    let above = effective(&snapshot, &parent)?;
                    security::fold(&above.security, &own)
                        .map_err(|error| Failure::failed(format!("{what}: {error}")))?
                }
            };
            values.insert(
                "RequestSecurity",
                RegData::Binary(folded.as_bytes().to_vec()),
            );
            check_tree(&snapshot, &name, Some(&values)).map_err(|f| f.context(&what))?;
            let mut set = Values::new();
            set.insert(
                "RequestSecurity",
                RegData::Binary(folded.as_bytes().to_vec()),
            );
            host.put(&name.key(), &set, &[])
                .map_err(|error| written(error, &what))?;
            let mut warnings = security::broad_grants(folded.as_bytes()).unwrap_or_default();
            if name.is_root() {
                warnings.extend(security::lost_root_grants(folded.as_bytes()).unwrap_or_default());
            }
            for warning in warnings {
                host.warn(&warning);
            }
            let changed = after(&snapshot, &name, Some(values));
            Ok(Output {
                json: json!({"changed": name_json(&changed, &name)}),
                text: name_text(&changed, &name)?,
            })
        }

        NameCommand::Domains { domains, none } => {
            let settings = format!("{ROOT}\\Settings");
            let current = list(&snapshot.settings, "PrincipalDomains").to_vec();
            let (listed, changed) = if none {
                host.put(&settings, &Values::new(), &["PrincipalDomains"])
                    .map_err(|error| written(error, "domains"))?;
                (Vec::new(), true)
            } else if domains.is_empty() {
                (current, false)
            } else {
                let mut checked = Vec::new();
                for domain in &domains {
                    match pki_core::DnsName::new(domain.trim()) {
                        Ok(name) if !name.is_wildcard() => checked.push(name.as_str().to_owned()),
                        _ => {
                            return Err(Failure::usage(format!(
                                "domains: '{domain}' is not a domain name"
                            )))
                        }
                    }
                }
                let mut set = Values::new();
                set.insert("PrincipalDomains", RegData::MultiSz(checked.clone()));
                host.put(&settings, &set, &[])
                    .map_err(|error| written(error, "domains"))?;
                (checked, true)
            };
            let text = if listed.is_empty() {
                "No domains: principal names have only the owners set on them.\n".to_string()
            } else {
                format!(
                    "Accounts own their principal names in: {}.\n",
                    listed.join(", ")
                )
            };
            Ok(Output {
                json: json!({"principal_domains": listed, "changed": changed}),
                text,
            })
        }

        NameCommand::SetOwner { name, owner, none } => {
            let name = parse_name(&name)?;
            let what = format!("set-owner {}", name.display());
            let mut values = node(&snapshot, &name).cloned().unwrap_or_default();
            if none {
                let mut kept = Values::new();
                for (value, data) in values.iter().filter(|(value, _)| *value != "Owner") {
                    kept.insert(value, data.clone());
                }
                if node(&snapshot, &name).is_some() {
                    host.change(&name.key(), &Values::new(), &["Owner"])
                        .map_err(|error| written(error, &what))?;
                }
                let changed = after(&snapshot, &name, Some(kept));
                return Ok(Output {
                    json: json!({"changed": name_json(&changed, &name)}),
                    text: name_text(&changed, &name)?,
                });
            }
            let owner = parse_owner(owner.as_deref().expect("clap requires an owner"))?;
            values.insert("Owner", RegData::Sz(owner.clone()));
            check_tree(&snapshot, &name, Some(&values)).map_err(|f| f.context(&what))?;
            let mut set = Values::new();
            set.insert("Owner", RegData::Sz(owner.clone()));
            host.put(&name.key(), &set, &[])
                .map_err(|error| written(error, &what))?;
            if let Some(warning) = security::broad_owner(&owner) {
                host.warn(&warning);
            }
            let changed = after(&snapshot, &name, Some(values));
            Ok(Output {
                json: json!({"changed": name_json(&changed, &name)}),
                text: name_text(&changed, &name)?,
            })
        }
    }
}

/// `snapshot` with `name`'s node set to `values`, to show the result of a
/// change without reading the Registry again.
fn after(snapshot: &Snapshot, name: &NamePath, values: Option<Values>) -> Snapshot {
    let mut changed = snapshot.clone();
    let tree = match name.tree {
        TreeKind::Dns => &mut changed.dns,
        TreeKind::Principal => &mut changed.principals,
    };
    tree.retain(|(path, _)| !same_path(path, &name.path));
    if let Some(values) = values {
        tree.push((name.path.clone(), values));
    }
    changed
}
