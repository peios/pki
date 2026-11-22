//! Certificate templates and name policy for Peios PKI.
//!
//! This crate decides *whether* a request may be issued and *what* the
//! certificate contains. It has no Registry or token access of its own:
//! pkid reads the configuration into [`Values`] and supplies an
//! [`AccessChecker`] that runs `kacs_access_check` on the impersonated
//! requester.
//!
//! The decision combines three checks. The template's `EnrollSecurity` must
//! grant enrolment. The key and every name must be of kinds the template
//! issues. Every name's `RequestSecurity`, found in the name trees, must
//! grant a request right, with PRINCIPAL SELF matching the name's owner.

mod access;
pub mod defaults;
mod error;
mod evaluate;
mod profile;
mod template;
mod tree;
mod values;

pub use access::{
    AccessChecker, SecurityBlob, DEFAULT_MANAGE_SDDL, DEFAULT_NAME_ROOT_SDDL,
    DEFAULT_TEMPLATE_ENROLL_SDDL, NAME_ALL, NAME_REQUEST, NAME_REQUEST_WILDCARD,
    NAME_REQUEST_WITH_APPROVAL, TEMPLATE_ALL, TEMPLATE_AUTOENROLL, TEMPLATE_ENROLL,
};
pub use error::PolicyError;
pub use evaluate::{evaluate, Accounts, Decision, NameDecision, NamePolicy, NoAccounts, Outcome};
pub use profile::{leaf_profile, IssueContext};
pub use template::{CommonNameRule, Issuance, KeyRequirement, NameType, Template};
pub use tree::{NameNode, NameTree, Resolution, TreeKind};
pub use values::{RegData, Values};
