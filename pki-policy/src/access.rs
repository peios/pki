//! Access rights, default descriptors and the access-check interface.

use pki_core::Sid;

use crate::PolicyError;

/// May request certificates naming this name without approval.
pub const NAME_REQUEST: u32 = 0x0001;
/// May request certificates naming this name, held for an officer's approval.
pub const NAME_REQUEST_WITH_APPROVAL: u32 = 0x0002;
/// May request a wildcard certificate (`*.` this name), together with one of
/// the two request rights.
pub const NAME_REQUEST_WILDCARD: u32 = 0x0004;
/// Every right a name's `RequestSecurity` can grant.
pub const NAME_ALL: u32 = NAME_REQUEST | NAME_REQUEST_WITH_APPROVAL | NAME_REQUEST_WILDCARD;

/// May request certificates from this template.
pub const TEMPLATE_ENROLL: u32 = 0x0001;
/// May have certificates from this template requested and renewed
/// automatically. Reserved: automatic enrolment is not implemented yet.
pub const TEMPLATE_AUTOENROLL: u32 = 0x0002;
/// Every right a template's `EnrollSecurity` can grant.
pub const TEMPLATE_ALL: u32 = TEMPLATE_ENROLL | TEMPLATE_AUTOENROLL;

/// The default `RequestSecurity` of each name tree's root (rule R1).
///
/// The owner of a name (PRINCIPAL SELF) may request it; Administrators and
/// SYSTEM may request any name, with or without approval, and wildcards.
/// Nobody else may request anything. `CI` carries the entries to every name
/// below the root.
pub const DEFAULT_NAME_ROOT_SDDL: &str = "O:SYG:SYD:(A;CI;0x1;;;PS)(A;CI;0x7;;;BA)(A;CI;0x7;;;SY)";

/// The default `EnrollSecurity` of the shipped templates.
///
/// Any authenticated principal may enrol; the name policy decides which
/// names each may obtain, so enrolment alone grants nothing.
pub const DEFAULT_TEMPLATE_ENROLL_SDDL: &str = "O:SYG:SYD:(A;;0x1;;;AU)(A;;0x3;;;BA)(A;;0x3;;;SY)";

/// A self-relative security descriptor, opaque to portable code.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SecurityBlob(Vec<u8>);

impl SecurityBlob {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Decides what the requester may do, against security descriptors.
///
/// pkid implements this with `kacs_access_check` on the impersonated
/// requester's token. Tests implement it with a model of their own.
pub trait AccessChecker {
    /// The rights in `desired` that `security` grants the requester.
    /// `self_sid` stands in for PRINCIPAL SELF; without it, PRINCIPAL SELF
    /// entries match nobody.
    fn granted(
        &self,
        security: &SecurityBlob,
        desired: u32,
        self_sid: Option<&Sid>,
    ) -> Result<u32, PolicyError>;

    /// The descriptor a name with no node of its own receives from the node
    /// directly above it, by ordinary inheritance of container entries.
    fn inherit(&self, parent: &SecurityBlob) -> Result<SecurityBlob, PolicyError>;
}
