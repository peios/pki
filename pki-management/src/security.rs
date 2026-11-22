//! The name trees' request descriptors: what a name inherits, folding the
//! inherited entries into a descriptor written for it, and the grants that
//! deserve a warning (PEI-1709, R1), on names and on CAs.

use peios::security::{sddl, AceFlags, AceType, SdBuilder, SdView, Sid, WellKnown};
use pki_policy::{SecurityBlob, Values, NAME_REQUEST, NAME_REQUEST_WITH_APPROVAL};

/// What a name below a node with `parent` receives by inheritance: only
/// the entries marked to inherit (CI) pass down, as pkid applies them.
pub fn inherit(parent: &SecurityBlob) -> peios::Result<SecurityBlob> {
    let system = Sid::well_known(WellKnown::System);
    let empty = SdBuilder::new()
        .owner(system.as_ref())
        .group(system.as_ref())
        .build()?;
    let inherited = sddl::reinherit(parent.as_bytes(), empty.as_bytes(), true)?;
    Ok(SecurityBlob::new(inherited.as_bytes().to_vec()))
}

/// `own`, with the entries a node below `parent` inherits added, as a
/// node's `RequestSecurity` must be written: an explicit value replaces
/// what the node would inherit, so leaving them out would drop grants such
/// as Administrators'.
pub fn fold(parent: &SecurityBlob, own: &[u8]) -> peios::Result<SecurityBlob> {
    let folded = sddl::reinherit(parent.as_bytes(), own, true)?;
    Ok(SecurityBlob::new(folded.as_bytes().to_vec()))
}

/// Where a node's descriptor comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Effective {
    pub security: SecurityBlob,
    /// How many levels below the nearest node with its own descriptor this
    /// one is; 0 means its own.
    pub inherited_levels: usize,
}

/// The descriptor of the node at `path`, from a tree's `(path, values)`
/// records, computed level by level from the root as pkid does.
pub fn effective(nodes: &[(Vec<String>, Values)], path: &[String]) -> Result<Effective, String> {
    let own = |at: &[String]| -> Result<Option<SecurityBlob>, String> {
        let Some((_, values)) = nodes.iter().find(|(node, _)| {
            node.len() == at.len() && node.iter().zip(at).all(|(a, b)| a.eq_ignore_ascii_case(b))
        }) else {
            return Ok(None);
        };
        Ok(values
            .binary("RequestSecurity")
            .map_err(|error| error.to_string())?
            .map(|bytes| SecurityBlob::new(bytes.to_vec())))
    };
    let mut current = Effective {
        security: own(&[])?.ok_or("the name tree's root has no RequestSecurity")?,
        inherited_levels: 0,
    };
    for depth in 1..=path.len() {
        current = match own(&path[..depth])? {
            Some(security) => Effective {
                security,
                inherited_levels: 0,
            },
            None => Effective {
                security: inherit(&current.security).map_err(|error| error.to_string())?,
                inherited_levels: current.inherited_levels + 1,
            },
        };
    }
    Ok(current)
}

/// Groups so broad that most of the machine's principals are in them.
fn broad(sid: &str) -> Option<&'static str> {
    match sid {
        "S-1-1-0" => Some("Everyone"),
        "S-1-5-7" => Some("Anonymous Logon"),
        "S-1-5-11" => Some("Authenticated Users"),
        "S-1-5-32-545" => Some("Users"),
        _ if sid.starts_with("S-1-5-21-") && sid.ends_with("-513") => Some("Domain Users"),
        _ => None,
    }
}

/// Why making `owner` a name's owner deserves a warning, if it does.
pub fn broad_owner(owner: &str) -> Option<String> {
    broad(owner).map(|group| {
        format!("{group} owns this name now, so every member may request it as its own")
    })
}

/// The descriptor's own entries that let a broad group request names
/// without approval. Inherited entries were judged where they were set.
pub fn broad_grants(security: &[u8]) -> peios::Result<Vec<String>> {
    const GENERIC_ALL: u32 = 0x1000_0000;
    let view = SdView::parse(security)?;
    let Some(dacl) = view.dacl() else {
        return Ok(Vec::new());
    };
    let mut warnings = Vec::new();
    for ace in dacl.iter() {
        let own = !ace.flags().contains(AceFlags::INHERITED);
        let grants = ace.mask() & (NAME_REQUEST | GENERIC_ALL) != 0;
        if ace.ace_type() == AceType::AccessAllowed && own && grants {
            if let Some(group) = ace.sid().and_then(|sid| broad(&sid.to_string())) {
                warnings.push(format!(
                    "{group} may now request these names without approval; prefer Request with approval (0x2)"
                ));
            }
        }
    }
    Ok(warnings)
}

/// The entries of a CA's descriptor that let a broad group approve,
/// revoke or manage at the CA (R1): rights for a few trusted people.
pub fn broad_ca_grants(security: &[u8]) -> peios::Result<Vec<String>> {
    const GENERIC_ALL: u32 = 0x1000_0000;
    const OFFICER: u32 = 0x4;
    const MANAGE: u32 = 0x8;
    let view = SdView::parse(security)?;
    let Some(dacl) = view.dacl() else {
        return Ok(Vec::new());
    };
    let mut warnings = Vec::new();
    for ace in dacl.iter() {
        if ace.ace_type() != AceType::AccessAllowed {
            continue;
        }
        let Some(group) = ace.sid().and_then(|sid| broad(&sid.to_string())) else {
            continue;
        };
        if ace.mask() & (MANAGE | GENERIC_ALL) != 0 {
            warnings.push(format!(
                "{group} may now manage this CA, and so issue any certificate"
            ));
        } else if ace.mask() & OFFICER != 0 {
            warnings.push(format!(
                "{group} may now approve requests and revoke certificates at this CA"
            ));
        }
    }
    Ok(warnings)
}

/// What a tree root's new descriptor takes away that the shipped one
/// grants: Administrators' right to request any name in the tree, and
/// owners' right, through PRINCIPAL SELF, to request their own. A root
/// inherits nothing, so its descriptor replaces these rather than adding
/// to them.
pub fn lost_root_grants(security: &[u8]) -> peios::Result<Vec<String>> {
    const GENERIC_ALL: u32 = 0x1000_0000;
    const ADMINISTRATORS: &str = "S-1-5-32-544";
    const PRINCIPAL_SELF: &str = "S-1-5-10";
    let view = SdView::parse(security)?;
    let granted = |who: &str| {
        view.dacl().is_some_and(|dacl| {
            dacl.iter().any(|ace| {
                ace.ace_type() == AceType::AccessAllowed
                    && ace.flags().contains(AceFlags::CONTAINER_INHERIT)
                    && !ace.flags().contains(AceFlags::NO_PROPAGATE_INHERIT)
                    && ace.mask() & (NAME_REQUEST | NAME_REQUEST_WITH_APPROVAL | GENERIC_ALL) != 0
                    && ace.sid().is_some_and(|sid| sid.to_string() == who)
            })
        })
    };
    let mut warnings = Vec::new();
    if !granted(ADMINISTRATORS) {
        warnings.push("Administrators can't request certificates for names in this tree under this descriptor".to_string());
    }
    if !granted(PRINCIPAL_SELF) {
        warnings.push("owners can't request certificates for their own names in this tree under this descriptor".to_string());
    }
    Ok(warnings)
}
