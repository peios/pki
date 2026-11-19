//! pkid's configuration, from a snapshot of the Registry under
//! `Machine\Software\Pki` (see `pkid.regman`).

use std::collections::BTreeMap;
use std::fmt;

use pki_keys::KeyReference;
use pki_pipeline::Configuration;
use pki_policy::{NameNode, NamePolicy, NameTree, SecurityBlob, Template, TreeKind, Values};

pub use pki_management::{Snapshot, ROOT};

/// What a configuration was loaded from: a Registry snapshot, or why the
/// Registry couldn't be read.
pub type Source = Result<Snapshot, String>;

/// The descriptors pkid uses where the Registry gives none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Defaults {
    /// For a CA without `CaSecurity`: `DEFAULT_CA_SDDL`.
    pub ca_security: SecurityBlob,
    /// For `Settings` without `ManageSecurity`: `DEFAULT_MANAGE_SDDL`.
    pub manage_security: SecurityBlob,
}

/// The default `Settings ManageSecurity`: Administrators and SYSTEM may
/// create and import CAs.
pub const DEFAULT_MANAGE_SDDL: &str = "O:SYG:SYD:(A;;0x8;;;BA)(A;;0x8;;;SY)";

/// A CA as configured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityConfig {
    pub id: String,
    pub name: String,
    /// The CA's DER certificate, unless it awaits one from a CA elsewhere.
    pub certificate: Option<Vec<u8>>,
    /// For a CA awaiting its certificate, the DER request to have signed.
    pub request: Option<Vec<u8>>,
    /// Where its key is kept.
    pub key: KeyReference,
    /// `CaSecurity`, or the default if it has none.
    pub security: SecurityBlob,
    /// The GUIDs of the templates it issues from.
    pub templates: Vec<String>,
    pub crl_distribution_points: Vec<String>,
}

/// A configuration pkid can serve.
pub struct Loaded {
    pub configuration: Configuration,
    pub authorities: Vec<AuthorityConfig>,
    /// `Settings ManageSecurity`: who may create and import CAs, with
    /// Manage CA (0x8).
    pub manage_security: SecurityBlob,
}

impl Loaded {
    pub fn authority(&self, id: &str) -> Option<&AuthorityConfig> {
        self.authorities.iter().find(|authority| authority.id == id)
    }
}

/// Why a configuration can't be served.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

fn invalid(context: &str, detail: impl fmt::Display) -> ConfigError {
    ConfigError(format!("{context}: {detail}"))
}

/// Builds the configuration from `snapshot`. Any invalid record makes the
/// whole configuration invalid: pkid never issues from part of what an
/// administrator wrote.
pub fn load(snapshot: &Snapshot, defaults: &Defaults) -> Result<Loaded, ConfigError> {
    let sid_extension = match snapshot.settings.dword("SidSecurityExtension") {
        Ok(None) => true,
        Ok(Some(value)) => value != 0,
        Err(error) => return Err(invalid("Settings", error)),
    };
    let manage_security = match snapshot.settings.binary("ManageSecurity") {
        Ok(Some(bytes)) => SecurityBlob::new(bytes.to_vec()),
        Ok(None) => defaults.manage_security.clone(),
        Err(error) => return Err(invalid("Settings", error)),
    };

    let mut templates = BTreeMap::new();
    for (id, values) in &snapshot.templates {
        let template = Template::from_values(values)
            .map_err(|error| invalid(&format!("Templates\\{id}"), error))?;
        templates.insert(id.to_ascii_lowercase(), template);
    }

    let tree = |kind, nodes: &[(Vec<String>, Values)], key: &str| {
        let records = nodes
            .iter()
            .map(|(path, values)| {
                NameNode::from_values(values)
                    .map(|node| (path.clone(), node))
                    .map_err(|error| invalid(&format!("{key}\\{}", path.join("\\")), error))
            })
            .collect::<Result<Vec<_>, _>>()?;
        NameTree::new(kind, records).map_err(|error| invalid(key, error))
    };
    let names = NamePolicy::new(
        tree(TreeKind::Dns, &snapshot.dns, "Names\\Dns")?,
        tree(
            TreeKind::Principal,
            &snapshot.principals,
            "Names\\Principals",
        )?,
    )
    .map_err(|error| invalid("Names", error))?;

    let mut authorities = Vec::new();
    for (id, values) in &snapshot.authorities {
        let authority = authority(id, values, &defaults.ca_security)
            .map_err(|error| invalid(&format!("Authorities\\{id}"), error))?;
        for template in &authority.templates {
            if !templates.contains_key(template) {
                return Err(invalid(
                    &format!("Authorities\\{id}"),
                    format!("template {template} does not exist"),
                ));
            }
        }
        authorities.push(authority);
    }

    Ok(Loaded {
        configuration: Configuration {
            templates,
            names,
            sid_extension,
        },
        authorities,
        manage_security,
    })
}

fn authority(
    id: &str,
    values: &Values,
    default_security: &SecurityBlob,
) -> Result<AuthorityConfig, ConfigError> {
    let wrap = |error: pki_policy::PolicyError| ConfigError(error.to_string());
    let name = values.required_sz("Name").map_err(wrap)?.trim();
    if name.is_empty() {
        return Err(ConfigError("Name is empty".into()));
    }
    let certificate = values.binary("Certificate").map_err(wrap)?;
    let request = values.binary("Request").map_err(wrap)?;
    if certificate.is_none() && request.is_none() {
        return Err(ConfigError(
            "a CA needs a Certificate, or a Request while it awaits one".into(),
        ));
    }
    let key: KeyReference = values
        .required_sz("Key")
        .map_err(wrap)?
        .parse()
        .map_err(|error| ConfigError(format!("Key: {error}")))?;
    let security = match values.binary("CaSecurity").map_err(wrap)? {
        Some(bytes) => SecurityBlob::new(bytes.to_vec()),
        None => default_security.clone(),
    };
    let optional_list = |name: &str| match values.get(name) {
        None => Ok(Vec::new()),
        Some(_) => values.multi_sz(name).map(<[String]>::to_vec).map_err(wrap),
    };
    Ok(AuthorityConfig {
        id: id.to_string(),
        name: name.to_string(),
        certificate: certificate.map(<[u8]>::to_vec),
        request: request.map(<[u8]>::to_vec),
        key,
        security,
        templates: optional_list("Templates")?
            .into_iter()
            .map(|template| template.to_ascii_lowercase())
            .collect(),
        crl_distribution_points: optional_list("CrlDistributionPoints")?,
    })
}
