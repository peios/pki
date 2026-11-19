//! Preparing a machine for pkid. An administrator runs this, through the
//! `pki` command; pkid itself has no authority to.
//!
//! Provisioning only adds what is missing. It never replaces a value an
//! administrator set, and never relaxes an existing directory.

use std::io;
use std::os::fd::AsFd;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

use peios::registry::{CreateFlags, Key, KeyAccess, OpenFlags, SecInfo, Transaction};
use peios::security::sddl;
use pki_policy::defaults::{device_template, name_root, server_template};
use pki_policy::{SecurityBlob, Values, DEFAULT_NAME_ROOT_SDDL, DEFAULT_TEMPLATE_ENROLL_SDDL};
use pkid_core::SERVICE_SID;

use crate::{KEYS_DIR, ROOT, STATE_DIR};

fn error(error: peios::Error) -> io::Error {
    error.into()
}

/// Creates `path` as a directory with `dacl`, unless it exists.
fn private_directory(path: &str, dacl: &str) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => return Ok(()),
        Ok(_) => return Err(io::Error::other(format!("{path} is not a directory"))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    std::fs::DirBuilder::new().mode(0o700).create(path)?;
    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)?;
    let descriptor = sddl::parse(dacl).map_err(error)?;
    peios::file::fd_set_sd(directory.as_fd(), peios::file::SecInfo::DACL, &descriptor)
        .map_err(error)
}

/// Creates pkid's state directories.
///
/// The database directory admits SYSTEM, Administrators and pkid: the
/// database holds requests and certificates, nothing secret. The key
/// directory admits pkid fully and lets SYSTEM and Administrators only list
/// and pass through it; each key file in it is pkid's alone.
pub fn state_directories() -> io::Result<()> {
    private_directory(STATE_DIR, &state_dacl())?;
    private_directory(KEYS_DIR, &keys_dacl())
}

/// The database directory's DACL.
pub fn state_dacl() -> String {
    format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{SERVICE_SID})")
}

/// The key directory's DACL.
pub fn keys_dacl() -> String {
    format!("D:P(A;;GRGX;;;SY)(A;;GRGX;;;BA)(A;;GA;;;{SERVICE_SID})")
}

/// pkid's own grant on `Authorities`, which the key also inherits to.
pub fn authorities_grant() -> String {
    format!("O:SYG:SYD:(A;CI;GA;;;{SERVICE_SID})")
}

/// A new template GUID.
fn guid() -> io::Result<String> {
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

fn binary_sd(sddl_text: &str) -> io::Result<SecurityBlob> {
    let sd = sddl::parse(sddl_text).map_err(error)?;
    Ok(SecurityBlob::new(sd.as_bytes().to_vec()))
}

fn create(path: &str, transaction: &Transaction) -> io::Result<(Key, bool)> {
    let (key, disposition) = Key::create(
        None,
        path,
        KeyAccess::ALL_ACCESS,
        CreateFlags::empty(),
        None,
        Some(transaction),
    )
    .map_err(error)?;
    Ok((key, disposition == peios::registry::Disposition::CreatedNew))
}

/// Writes `values` to `key`, skipping any already present.
fn write_missing(key: &Key, values: &Values, transaction: &Transaction) -> io::Result<()> {
    for (name, data) in values.iter() {
        match key.query_value(name.as_bytes(), Some(transaction)) {
            Ok(_) => continue,
            Err(failure) => {
                let failure: io::Error = failure.into();
                if failure.kind() != io::ErrorKind::NotFound {
                    return Err(failure);
                }
            }
        }
        let data = crate::registry::data(data);
        key.set_value(name.as_bytes(), data.ty(), &data.encode())
            .in_txn(transaction)
            .call()
            .map_err(error)?;
    }
    Ok(())
}

/// What [`registry`] added.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Seeded {
    /// The GUIDs of the templates created, Server then Device.
    pub templates: Vec<String>,
    pub name_roots: bool,
    pub authorities_key: bool,
}

/// Seeds pkid's configuration in one transaction: the Server and Device
/// templates if there are no templates at all, the name trees' roots with
/// their default descriptors, and the `Authorities` key, which pkid may
/// write so that it can record the CAs an administrator creates through it.
pub fn registry() -> io::Result<Seeded> {
    let transaction = Transaction::begin().map_err(error)?;
    let mut seeded = Seeded::default();
    create(ROOT, &transaction)?;

    let (templates, _) = create(&format!("{ROOT}\\Templates"), &transaction)?;
    let empty = templates.subkeys(Some(&transaction)).next().is_none();
    if empty {
        let enroll = binary_sd(DEFAULT_TEMPLATE_ENROLL_SDDL)?;
        for values in [server_template(&enroll), device_template(&enroll)] {
            let id = guid()?;
            let (key, _) = create(&format!("{ROOT}\\Templates\\{id}"), &transaction)?;
            write_missing(&key, &values, &transaction)?;
            seeded.templates.push(id);
        }
    }

    let root = name_root(&binary_sd(DEFAULT_NAME_ROOT_SDDL)?);
    for tree in ["Dns", "Principals"] {
        let (key, created) = create(&format!("{ROOT}\\Names\\{tree}"), &transaction)?;
        write_missing(&key, &root, &transaction)?;
        seeded.name_roots |= created;
    }

    let (authorities, created) = create(&format!("{ROOT}\\Authorities"), &transaction)?;
    if created {
        // pkid's grant, with everything the key inherits from above it.
        let parent = Key::open_transacted(
            None,
            ROOT,
            KeyAccess::READ_CONTROL,
            OpenFlags::empty(),
            Some(&transaction),
        )
        .map_err(error)?
        .get_security_transacted(SecInfo::DACL, Some(&transaction))
        .map_err(error)?;
        let own = sddl::parse(&authorities_grant()).map_err(error)?;
        let descriptor = sddl::reinherit(parent.as_bytes(), own.as_bytes(), true).map_err(error)?;
        authorities
            .set_security(SecInfo::DACL, &descriptor, Some(&transaction))
            .map_err(error)?;
        seeded.authorities_key = true;
    }
    transaction.commit().map_err(error)?;
    Ok(seeded)
}
