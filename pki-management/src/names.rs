//! Names as people write them, and the name-tree keys they are kept
//! under (see `pkid.regman`, `Names`).
//!
//! A DNS name such as `radius.lab.home` is `Dns\home\lab\radius`. A
//! principal such as `jack@home` is `Principals\home\@jack`, and `@home`, a
//! domain without a user, is `Principals\home`, whose descriptor every user
//! at `home` inherits. `.` and `@` are the roots of the two trees.

use pki_core::DnsName;
use pki_policy::TreeKind;

use crate::ROOT;

/// A node of one of the name trees.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamePath {
    pub tree: TreeKind,
    /// The key names below the tree's root, lowercase.
    pub path: Vec<String>,
}

impl NamePath {
    /// The node `text` names.
    pub fn parse(text: &str) -> Result<Self, String> {
        let text = text.trim().to_lowercase();
        match text.as_str() {
            "." => return Ok(Self::root(TreeKind::Dns)),
            "@" => return Ok(Self::root(TreeKind::Principal)),
            _ => {}
        }
        if text.starts_with('*') {
            return Err(format!(
                "{text} has no node of its own: grant Wildcard on the name below the *"
            ));
        }
        let labels = |domain: &str| -> Result<Vec<String>, String> {
            DnsName::new(domain).map_err(|error| error.to_string())?;
            Ok(domain.rsplit('.').map(str::to_owned).collect())
        };
        match text.split_once('@') {
            Some((user, domain)) => {
                if user.contains('@') || domain.contains('@') || domain.is_empty() {
                    return Err(format!("{text} is not user@domain or @domain"));
                }
                let mut path = labels(domain)?;
                if !user.is_empty() {
                    path.push(format!("@{user}"));
                }
                Ok(Self {
                    tree: TreeKind::Principal,
                    path,
                })
            }
            None => Ok(Self {
                tree: TreeKind::Dns,
                path: labels(&text)?,
            }),
        }
    }

    pub fn root(tree: TreeKind) -> Self {
        Self {
            tree,
            path: Vec::new(),
        }
    }

    pub fn is_root(&self) -> bool {
        self.path.is_empty()
    }

    /// The node above this one.
    pub fn parent(&self) -> Option<Self> {
        let (_, above) = self.path.split_last()?;
        Some(Self {
            tree: self.tree,
            path: above.to_vec(),
        })
    }

    /// The name as people write it.
    pub fn display(&self) -> String {
        let domain = |labels: &[String]| {
            labels
                .iter()
                .rev()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(".")
        };
        match self.tree {
            TreeKind::Dns if self.path.is_empty() => ".".to_string(),
            TreeKind::Dns => domain(&self.path),
            TreeKind::Principal => match self.path.split_last() {
                None => "@".to_string(),
                Some((last, labels)) if last.starts_with('@') => {
                    format!("{}@{}", &last[1..], domain(labels))
                }
                Some(_) => format!("@{}", domain(&self.path)),
            },
        }
    }

    /// The tree's key below `Names`.
    pub fn tree_key(tree: TreeKind) -> &'static str {
        match tree {
            TreeKind::Dns => "Dns",
            TreeKind::Principal => "Principals",
        }
    }

    /// The node's Registry key.
    pub fn key(&self) -> String {
        let mut key = format!("{ROOT}\\Names\\{}", Self::tree_key(self.tree));
        for segment in &self.path {
            key.push('\\');
            key.push_str(segment);
        }
        key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(text: &str, tree: TreeKind, path: &[&str]) {
        let name = NamePath::parse(text).unwrap();
        assert_eq!(name.tree, tree, "{text}");
        assert_eq!(name.path, path, "{text}");
        assert_eq!(name.display(), text.to_lowercase());
    }

    #[test]
    fn names_map_to_their_keys_and_back() {
        round_trip("radius.lab.home", TreeKind::Dns, &["home", "lab", "radius"]);
        round_trip("Home", TreeKind::Dns, &["home"]);
        round_trip(".", TreeKind::Dns, &[]);
        round_trip("jack@home", TreeKind::Principal, &["home", "@jack"]);
        round_trip("@lab.home", TreeKind::Principal, &["home", "lab"]);
        round_trip("@", TreeKind::Principal, &[]);
        assert_eq!(
            NamePath::parse("radius.lab.home").unwrap().key(),
            "Machine\\Software\\Pki\\Names\\Dns\\home\\lab\\radius"
        );
        assert_eq!(
            NamePath::parse("jack@home")
                .unwrap()
                .parent()
                .unwrap()
                .display(),
            "@home"
        );
    }

    #[test]
    fn what_has_no_node_is_refused() {
        for text in [
            "*.lab.home",
            "jack@",
            "a@b@c",
            "bad_label.home",
            "",
            "-x.home",
        ] {
            assert!(NamePath::parse(text).is_err(), "{text}");
        }
    }
}
