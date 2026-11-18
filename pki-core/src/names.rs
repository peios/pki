//! Names a certificate can carry, security identifiers and name constraints.

use std::fmt;
use std::net::IpAddr;

use crate::Error;

const MAX_DNS_NAME_LEN: usize = 253;
const MAX_DNS_LABEL_LEN: usize = 63;
const WILDCARD_LABEL: &str = "*";

/// A DNS host name, normalised to lowercase ASCII.
///
/// The leftmost label may be `*` for a wildcard name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DnsName(String);

impl DnsName {
    pub fn new(name: &str) -> Result<Self, Error> {
        let name = name.to_ascii_lowercase();
        let invalid = |reason: &str| Error::InvalidValue(format!("DNS name {name:?} {reason}"));
        if name.is_empty() || name.len() > MAX_DNS_NAME_LEN {
            return Err(invalid("has an invalid length"));
        }
        for (index, label) in name.split('.').enumerate() {
            if index == 0 && label == WILDCARD_LABEL {
                continue;
            }
            if label.is_empty() || label.len() > MAX_DNS_LABEL_LEN {
                return Err(invalid("has an empty or overlong label"));
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err(invalid("has a label starting or ending with a hyphen"));
            }
            if !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            {
                return Err(invalid(
                    "contains characters other than letters, digits and hyphens",
                ));
            }
        }
        if name == WILDCARD_LABEL {
            return Err(invalid("is only a wildcard"));
        }
        Ok(Self(name))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_wildcard(&self) -> bool {
        self.0.starts_with("*.")
    }

    /// Whether this name lies within `base`, which is the name itself or any
    /// name formed by adding labels to its left (RFC 5280 §4.2.1.10).
    pub fn is_within(&self, base: &DnsName) -> bool {
        self.0 == base.0 || self.0.ends_with(&format!(".{}", base.0))
    }
}

impl fmt::Display for DnsName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// An `local@domain` address with an ASCII DNS domain.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Mailbox {
    local: String,
    domain: DnsName,
}

impl Mailbox {
    pub fn new(address: &str) -> Result<Self, Error> {
        let (local, domain) = split_at_sign(address)?;
        if !local.is_ascii() {
            return Err(Error::InvalidValue(format!(
                "mailbox {address:?} is not ASCII"
            )));
        }
        let domain = DnsName::new(domain)?;
        if domain.is_wildcard() {
            return Err(Error::InvalidValue(format!(
                "mailbox {address:?} has a wildcard domain"
            )));
        }
        Ok(Self {
            local: local.to_owned(),
            domain,
        })
    }

    pub fn domain(&self) -> &DnsName {
        &self.domain
    }
}

impl fmt::Display for Mailbox {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}@{}", self.local, self.domain)
    }
}

/// A Microsoft user principal name, `user@domain`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UserPrincipalName(String);

impl UserPrincipalName {
    pub fn new(name: &str) -> Result<Self, Error> {
        split_at_sign(name)?;
        Ok(Self(name.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for UserPrincipalName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

fn split_at_sign(address: &str) -> Result<(&str, &str), Error> {
    match address.rsplit_once('@') {
        Some((local, domain)) if !local.is_empty() && !domain.is_empty() => Ok((local, domain)),
        _ => Err(Error::InvalidValue(format!(
            "{address:?} is not of the form name@domain"
        ))),
    }
}

/// A name a certificate vouches for, carried in its Subject Alternative Name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AltName {
    Dns(DnsName),
    Ip(IpAddr),
    Email(Mailbox),
    Upn(UserPrincipalName),
}

impl fmt::Display for AltName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dns(name) => name.fmt(formatter),
            Self::Ip(address) => address.fmt(formatter),
            Self::Email(mailbox) => mailbox.fmt(formatter),
            Self::Upn(name) => name.fmt(formatter),
        }
    }
}

/// A security identifier in its string form, such as `S-1-5-32-544`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Sid(String);

const SID_PREFIX: &str = "S-1-";
const MAX_SID_SUB_AUTHORITIES: usize = 15;
const MAX_SID_AUTHORITY: u64 = (1 << 48) - 1;

impl Sid {
    pub fn new(text: &str) -> Result<Self, Error> {
        let invalid = || Error::InvalidValue(format!("{text:?} is not a SID"));
        let rest = text.strip_prefix(SID_PREFIX).ok_or_else(invalid)?;
        let mut parts = rest.split('-');
        let authority: u64 = parts
            .next()
            .and_then(|part| part.parse().ok())
            .ok_or_else(invalid)?;
        if authority > MAX_SID_AUTHORITY {
            return Err(invalid());
        }
        let mut sub_authorities = 0;
        for part in parts {
            if part.is_empty() || part.parse::<u32>().is_err() {
                return Err(invalid());
            }
            sub_authorities += 1;
        }
        if sub_authorities > MAX_SID_SUB_AUTHORITIES {
            return Err(invalid());
        }
        Ok(Self(text.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Sid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A subject distinguished-name attribute other than the common name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SubjectAttributeKind {
    Country,
    State,
    Locality,
    Organization,
    OrganizationalUnit,
}

/// A fixed subject attribute. Templates set these; requesters cannot.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SubjectAttribute {
    pub kind: SubjectAttributeKind,
    pub value: String,
}

impl SubjectAttribute {
    pub(crate) fn dn_type(&self) -> rcgen::DnType {
        match self.kind {
            SubjectAttributeKind::Country => rcgen::DnType::CountryName,
            SubjectAttributeKind::State => rcgen::DnType::StateOrProvinceName,
            SubjectAttributeKind::Locality => rcgen::DnType::LocalityName,
            SubjectAttributeKind::Organization => rcgen::DnType::OrganizationName,
            SubjectAttributeKind::OrganizationalUnit => rcgen::DnType::OrganizationalUnitName,
        }
    }
}

/// One subtree of a name constraint.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NameSubtree {
    /// The DNS name and every name formed by adding labels to its left.
    Dns(DnsName),
    /// The addresses within a network.
    Ip { network: IpAddr, prefix_len: u8 },
    /// Every mailbox at exactly this host.
    EmailDomain(DnsName),
}

impl NameSubtree {
    /// Builds an IP subtree, refusing a prefix longer than the address.
    pub fn ip(network: IpAddr, prefix_len: u8) -> Result<Self, Error> {
        if u32::from(prefix_len) > address_bits(network) {
            return Err(Error::InvalidValue(format!(
                "prefix /{prefix_len} is too long"
            )));
        }
        Ok(Self::Ip {
            network,
            prefix_len,
        })
    }

    /// Whether `name` has this subtree's type and lies within it.
    fn contains(&self, name: &AltName) -> bool {
        match (self, name) {
            (Self::Dns(base), AltName::Dns(name)) => name.is_within(base),
            (
                Self::Ip {
                    network,
                    prefix_len,
                },
                AltName::Ip(address),
            ) => same_network(*network, *address, *prefix_len),
            (Self::EmailDomain(host), AltName::Email(mailbox)) => mailbox.domain() == host,
            _ => false,
        }
    }

    fn constrains(&self, name: &AltName) -> bool {
        matches!(
            (self, name),
            (Self::Dns(_), AltName::Dns(_))
                | (Self::Ip { .. }, AltName::Ip(_))
                | (Self::EmailDomain(_), AltName::Email(_))
        )
    }
}

fn address_bits(address: IpAddr) -> u32 {
    match address {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

fn same_network(network: IpAddr, address: IpAddr, prefix_len: u8) -> bool {
    let (network, address) = match (network, address) {
        (IpAddr::V4(network), IpAddr::V4(address)) => (
            u128::from(u32::from(network)) << 96,
            u128::from(u32::from(address)) << 96,
        ),
        (IpAddr::V6(network), IpAddr::V6(address)) => (u128::from(network), u128::from(address)),
        _ => return false,
    };
    let mask = u128::MAX
        .checked_shl(128 - u32::from(prefix_len))
        .unwrap_or(0);
    network & mask == address & mask
}

/// Limits on the names any certificate below a CA may carry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NameConstraints {
    pub permitted: Vec<NameSubtree>,
    pub excluded: Vec<NameSubtree>,
}

impl NameConstraints {
    /// Checks `name` the way a verifier would: it must not lie in an excluded
    /// subtree and, if any permitted subtree constrains its type, it must lie
    /// in one of them. User principal names are not constrained.
    pub fn check(&self, name: &AltName) -> Result<(), Error> {
        if self.excluded.iter().any(|subtree| subtree.contains(name)) {
            return Err(Error::ConstraintViolation(format!(
                "{name} is in an excluded subtree"
            )));
        }
        let applicable: Vec<_> = self
            .permitted
            .iter()
            .filter(|subtree| subtree.constrains(name))
            .collect();
        if !applicable.is_empty() && !applicable.iter().any(|subtree| subtree.contains(name)) {
            return Err(Error::ConstraintViolation(format!(
                "{name} is outside permitted subtrees"
            )));
        }
        Ok(())
    }

    pub(crate) fn to_rcgen(&self) -> rcgen::NameConstraints {
        rcgen::NameConstraints {
            permitted_subtrees: self.permitted.iter().map(subtree_to_rcgen).collect(),
            excluded_subtrees: self.excluded.iter().map(subtree_to_rcgen).collect(),
        }
    }
}

fn subtree_to_rcgen(subtree: &NameSubtree) -> rcgen::GeneralSubtree {
    match subtree {
        NameSubtree::Dns(base) => rcgen::GeneralSubtree::DnsName(base.as_str().to_owned()),
        NameSubtree::Ip {
            network,
            prefix_len,
        } => rcgen::GeneralSubtree::IpAddress(rcgen::CidrSubnet::from_addr_prefix(
            *network,
            *prefix_len,
        )),
        NameSubtree::EmailDomain(host) => rcgen::GeneralSubtree::Rfc822Name(host.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_names_are_normalised_and_validated() {
        assert_eq!(DnsName::new("Radius.HOME").unwrap().as_str(), "radius.home");
        assert!(DnsName::new("*.lab.home").unwrap().is_wildcard());
        for invalid in [
            "", "*", "a..home", "-a.home", "a-.home", "a_b.home", "x.*.home",
        ] {
            assert!(DnsName::new(invalid).is_err(), "{invalid:?} accepted");
        }
    }

    #[test]
    fn dns_subtrees_match_whole_labels() {
        let base = DnsName::new("lab.home").unwrap();
        assert!(DnsName::new("lab.home").unwrap().is_within(&base));
        assert!(DnsName::new("a.lab.home").unwrap().is_within(&base));
        assert!(DnsName::new("*.lab.home").unwrap().is_within(&base));
        assert!(!DnsName::new("evillab.home").unwrap().is_within(&base));
    }

    #[test]
    fn sids_are_validated() {
        assert!(Sid::new("S-1-5-21-1-2-3-500").is_ok());
        for invalid in ["S-1-", "S-2-5-32", "S-1-5--32", "S-1-5-x", "s-1-5-32"] {
            assert!(Sid::new(invalid).is_err(), "{invalid:?} accepted");
        }
    }
}
