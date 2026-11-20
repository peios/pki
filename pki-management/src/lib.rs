//! pki's configuration in the Registry and its state on disk, for
//! everything that reads or changes them: pkid, the `pki` command and its
//! window.
//!
//! pkid reads its whole configuration from `Machine\Software\Pki` (see
//! `pkid.regman`). It writes only its CA records; templates, names and
//! provisioning are an administrator's, through this crate.

pub mod http;
pub mod names;
pub mod provision;
pub mod registry;
pub mod security;
pub mod write;

use std::io;

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
/// The CRLs pkid publishes, at the URL paths pki-httpd serves them on.
pub const HTTP_DIR: &str = "/var/state/pki/http";

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

/// A new random GUID, as templates are named by.
pub fn new_guid() -> io::Result<String> {
    let mut bytes = [0u8; 16];
    peios_crypto::random::fill(&mut bytes).map_err(|error| io::Error::other(error.to_string()))?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    ))
}

/// An I/O error in the system's own wording, without Rust's error number.
pub fn os_message(error: &io::Error) -> String {
    let mut text = error.to_string();
    if let Some(at) = text.find(" (os error ") {
        if text.ends_with(')') {
            text.truncate(at);
        }
    }
    text
}
