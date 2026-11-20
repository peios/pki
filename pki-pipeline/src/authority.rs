//! The rights, configuration and identities the pipeline works with.

use std::collections::BTreeMap;

use peios_crypto::Signer;
use pki_core::{DisplayName, Sid};
use pki_policy::{AccessChecker, Accounts, NamePolicy, SecurityBlob, Template};

use crate::PipelineError;

/// May see every request to the CA and every certificate it issued.
/// Requesters always see their own.
pub const CA_READ: u32 = 0x0001;
/// May submit requests to the CA. The template and name policy decide what
/// each request may contain.
pub const CA_REQUEST: u32 = 0x0002;
/// Issue and Manage Certificates: may approve and deny held requests and
/// revoke certificates. Nobody approves their own request.
pub const CA_OFFICER: u32 = 0x0004;
/// Manage CA: may change the CA itself and its key.
pub const CA_MANAGE: u32 = 0x0008;
/// Every right a CA's `CaSecurity` can grant.
pub const CA_ALL: u32 = CA_READ | CA_REQUEST | CA_OFFICER | CA_MANAGE;

/// The default `CaSecurity` (rule R1): any authenticated principal may
/// submit requests, and only Administrators and SYSTEM may do anything else.
pub const DEFAULT_CA_SDDL: &str = "O:SYG:SYD:(A;;0x2;;;AU)(A;;0xf;;;BA)(A;;0xf;;;SY)";

/// Someone the pipeline acts for: a requester or an officer.
pub trait Principal {
    fn sid(&self) -> &Sid;

    /// Checks this principal's rights.
    fn checker(&self) -> &dyn AccessChecker;

    /// This principal's identity, encoded so that [`Directory::restore`] can
    /// check its rights again when it is no longer present.
    fn snapshot(&self) -> Result<Vec<u8>, PipelineError>;
}

/// Identity services the pipeline needs beyond the caller, including the
/// account directory that owns principal names in the listed domains.
pub trait Directory: Accounts {
    /// The principal a [`Principal::snapshot`] recorded.
    fn restore(&self, snapshot: &[u8]) -> Result<Box<dyn Principal>, PipelineError>;

    /// A principal's display name, from identity data and never from a
    /// request, for templates that name certificates after their owner.
    fn display_name(&self, sid: &Sid) -> Result<Option<DisplayName>, PipelineError>;
}

/// A CA as the pipeline uses it.
pub struct Authority<'a> {
    /// The CA's configuration identifier.
    pub id: String,
    /// The CA's DER certificate.
    pub certificate: Vec<u8>,
    /// Who may do what at this CA.
    pub security: SecurityBlob,
    /// The GUIDs of the templates this CA issues from.
    pub templates: Vec<String>,
    pub crl_distribution_points: Vec<String>,
    /// The CA's key, unless it is unavailable or locked. Requests can still
    /// be recorded and decided without it, but nothing is issued.
    pub signer: Option<&'a dyn Signer>,
}

/// The configuration requests are decided against.
pub struct Configuration {
    /// Every template, by its GUID.
    pub templates: BTreeMap<String, Template>,
    pub names: NamePolicy,
    /// The `SidSecurityExtension` setting.
    pub sid_extension: bool,
}
