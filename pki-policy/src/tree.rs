//! The name trees: who may request certificates for which names.
//!
//! Each tree mirrors Registry keys. DNS names are keyed by their labels from
//! the right (`radius.lab.home` is `home\lab\radius`). Principal names
//! (`user@domain`, for email and UPN) are keyed by the domain's labels from
//! the right, then `@user` (`jack@home` is `home\@jack`). Keys are
//! lowercase: names are matched case-insensitively.

use std::collections::BTreeMap;

use pki_core::{AltName, DnsName, Sid};

use crate::access::SecurityBlob;
use crate::values::Values;
use crate::PolicyError;

const LOCAL_PART_MARKER: char = '@';

/// Which tree a name belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TreeKind {
    Dns,
    Principal,
}

/// One node: an optional request descriptor and an optional exact owner.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NameNode {
    pub request_security: Option<SecurityBlob>,
    pub owner: Option<Sid>,
}

impl NameNode {
    /// Reads a node's `RequestSecurity` and `Owner` values.
    pub fn from_values(values: &Values) -> Result<Self, PolicyError> {
        let request_security = values
            .binary("RequestSecurity")?
            .map(|bytes| SecurityBlob::new(bytes.to_vec()));
        let owner = values.sz("Owner")?.map(Sid::new).transpose()?;
        Ok(Self {
            request_security,
            owner,
        })
    }
}

/// Where a name's request rights come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution<'a> {
    /// The descriptor of the nearest node at or above the name that has one.
    pub security: &'a SecurityBlob,
    /// How many levels below that node the name sits; 0 means the name's own
    /// node. The descriptor is inherited once per level.
    pub inherit_levels: usize,
    /// The name's exact owner, if its own node names one.
    pub owner: Option<&'a Sid>,
}

/// One tree of names, from its Registry records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameTree {
    kind: TreeKind,
    nodes: BTreeMap<Vec<String>, NameNode>,
}

impl NameTree {
    /// Builds a tree from `(path, node)` records, where each path lists key
    /// names below the tree's root. The root (the empty path) must carry a
    /// `RequestSecurity`, so every name has one to inherit.
    pub fn new(
        kind: TreeKind,
        records: impl IntoIterator<Item = (Vec<String>, NameNode)>,
    ) -> Result<Self, PolicyError> {
        let mut nodes = BTreeMap::new();
        for (path, node) in records {
            let path = normalise_path(kind, path)?;
            if nodes.insert(path.clone(), node).is_some() {
                return Err(invalid(format!("duplicate name node {}", path.join("\\"))));
            }
        }
        let root_secured = nodes
            .get(&Vec::new())
            .is_some_and(|root| root.request_security.is_some());
        if !root_secured {
            return Err(invalid(format!(
                "the {kind:?} name tree's root has no RequestSecurity"
            )));
        }
        Ok(Self { kind, nodes })
    }

    pub fn kind(&self) -> TreeKind {
        self.kind
    }

    /// Finds the descriptor and owner for the node at `path`.
    pub(crate) fn resolve(&self, path: &[String]) -> Resolution<'_> {
        let mut nearest = None;
        for depth in 0..=path.len() {
            let security = self
                .nodes
                .get(&path[..depth])
                .and_then(|n| n.request_security.as_ref());
            if let Some(security) = security {
                nearest = Some((depth, security));
            }
        }
        // The constructor guarantees the root's descriptor.
        let (depth, security) = nearest.expect("the root has a RequestSecurity");
        let owner = self.nodes.get(path).and_then(|node| node.owner.as_ref());
        Resolution {
            security,
            inherit_levels: path.len() - depth,
            owner,
        }
    }
}

/// Where a requested name is checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NamePath {
    pub(crate) tree: TreeKind,
    pub(crate) path: Vec<String>,
    /// A wildcard name is checked on its parent with the wildcard right.
    pub(crate) wildcard: bool,
}

/// The node a name is checked against, or why policy can't check it.
pub(crate) fn name_path(name: &AltName) -> Result<NamePath, String> {
    match name {
        AltName::Dns(dns) if dns.is_wildcard() => {
            let mut path = dns_path(dns);
            path.pop();
            Ok(NamePath {
                tree: TreeKind::Dns,
                path,
                wildcard: true,
            })
        }
        AltName::Dns(dns) => Ok(NamePath {
            tree: TreeKind::Dns,
            path: dns_path(dns),
            wildcard: false,
        }),
        AltName::Email(mailbox) => Ok(principal_path(mailbox.local(), mailbox.domain())),
        AltName::Upn(upn) => {
            let (user, suffix) = upn.parts();
            let suffix = DnsName::new(suffix)
                .map_err(|_| format!("the UPN suffix of {upn} is not a domain name"))?;
            Ok(principal_path(user, &suffix))
        }
        AltName::Ip(address) => Err(format!(
            "IP address {address} is not covered by name policy"
        )),
    }
}

fn dns_path(name: &DnsName) -> Vec<String> {
    name.as_str().rsplit('.').map(str::to_owned).collect()
}

fn principal_path(user: &str, domain: &DnsName) -> NamePath {
    let mut path = dns_path(domain);
    path.push(format!("{LOCAL_PART_MARKER}{}", user.to_lowercase()));
    NamePath {
        tree: TreeKind::Principal,
        path,
        wildcard: false,
    }
}

fn normalise_path(kind: TreeKind, path: Vec<String>) -> Result<Vec<String>, PolicyError> {
    let last = path.len().saturating_sub(1);
    path.into_iter()
        .enumerate()
        .map(|(index, segment)| {
            let segment = segment.to_lowercase();
            let is_local = segment.starts_with(LOCAL_PART_MARKER);
            let valid = match (kind, is_local) {
                (TreeKind::Principal, true) => index == last && segment.len() > 1,
                (_, false) => DnsName::new(&segment).is_ok() && !segment.contains('.'),
                (TreeKind::Dns, true) => false,
            };
            if !valid {
                return Err(invalid(format!(
                    "{segment:?} is not a valid {kind:?} name key"
                )));
            }
            Ok(segment)
        })
        .collect()
}

fn invalid(detail: String) -> PolicyError {
    PolicyError::InvalidConfiguration(detail)
}
