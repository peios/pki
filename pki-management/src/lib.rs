//! pki's configuration in the Registry and its state on disk, for
//! everything that reads or changes them: pkid, the `pki` command and its
//! window.
//!
//! pkid reads its whole configuration from `Machine\Software\Pki` (see
//! `pkid.regman`). It writes only its CA records; templates, names and
//! provisioning are an administrator's, through this crate.

pub mod provision;
pub mod registry;

use pki_policy::Values;

/// Where pki's configuration lives.
pub const ROOT: &str = "Machine\\Software\\Pki";

/// pkid's persistent state. An administrator provisions it; pkid doesn't
/// create it, since peinit gives services no state directory of their own.
pub const STATE_DIR: &str = "/var/state/pki";
/// The CA database.
pub const DATABASE: &str = "/var/state/pki/pkid.db";
/// Online CA keys, readable by pkid's service identity alone.
pub const KEYS_DIR: &str = "/var/state/pki/keys";

/// The Registry under [`ROOT`], read in one snapshot.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Snapshot {
    /// `Settings`, or nothing if the key is absent.
    pub settings: Values,
    /// `Templates\<guid>`, by GUID.
    pub templates: Vec<(String, Values)>,
    /// The nodes of `Names\Dns`, by their key path below it.
    pub dns: Vec<(Vec<String>, Values)>,
    /// The nodes of `Names\Principals`.
    pub principals: Vec<(Vec<String>, Values)>,
    /// `Authorities\<id>`, by identifier.
    pub authorities: Vec<(String, Values)>,
}
