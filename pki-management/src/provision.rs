//! Preparing a machine for pkid. An administrator runs this, through the
//! `pki` command; pkid itself has no authority to.
//!
//! Provisioning only adds what is missing. It never replaces a value an
//! administrator set, and never relaxes an existing directory.

use std::io;
use std::os::fd::AsFd;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

use peios::registry::{Key, KeyAccess, OpenFlags, SecInfo, Transaction};
use peios::security::{sddl, AceFlags, AceType, SdView};
use pki_policy::defaults::{device_template, name_root, server_template};
use pki_policy::{SecurityBlob, Values, DEFAULT_NAME_ROOT_SDDL, DEFAULT_TEMPLATE_ENROLL_SDDL};
use pkid_core::{HTTPD_SERVICE_SID, SERVICE_SID};

use crate::{HTTP_DIR, KEYS_DIR, ROOT, STATE_DIR};

fn error(error: peios::Error) -> io::Error {
    error.into()
}

/// `error`, naming the key or directory it concerns, keeping its kind.
fn at(what: &str) -> impl Fn(io::Error) -> io::Error + '_ {
    move |error| {
        let message = crate::os_message(&error);
        io::Error::new(error.kind(), format!("{what}: {message}"))
    }
}

/// Creates `path` as a directory with `dacl`, unless it exists.
fn private_directory(path: &str, dacl: &str) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => return Ok(()),
        Ok(_) => return Err(io::Error::other(format!("{path} is not a directory"))),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    // Mode 0755: the descriptor decides who gets in. A mode without search
    // for others would keep out pkid's own account, whatever the descriptor
    // grants it.
    std::fs::DirBuilder::new().mode(0o755).create(path)?;
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
/// and pass through it; each key file in it is pkid's alone. The published
/// folder holds the CRLs pkid publishes, which pki-httpd may read.
pub fn state_directories() -> io::Result<()> {
    private_directory(STATE_DIR, &state_dacl()).map_err(at(STATE_DIR))?;
    private_directory(KEYS_DIR, &keys_dacl()).map_err(at(KEYS_DIR))?;
    private_directory(HTTP_DIR, &http_dacl()).map_err(at(HTTP_DIR))
}

/// The database directory's DACL. Its entries pass to the files created in
/// it, the database and SQLite's journals, which would otherwise have none.
pub fn state_dacl() -> String {
    format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{SERVICE_SID})")
}

/// The key directory's DACL.
pub fn keys_dacl() -> String {
    format!("D:P(A;;FRFX;;;SY)(A;;FRFX;;;BA)(A;OICI;FA;;;{SERVICE_SID})")
}

/// The published folder's DACL: pkid writes the CRLs it publishes, and
/// pki-httpd may only read them.
pub fn http_dacl() -> String {
    format!(
        "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{SERVICE_SID})(A;OICI;FR;;;{HTTPD_SERVICE_SID})"
    )
}

/// pkid's own grant on `Authorities`, which the key also inherits to.
pub fn authorities_grant() -> String {
    format!("O:SYG:SYD:(A;CI;KA;;;{SERVICE_SID})")
}

fn binary_sd(sddl_text: &str) -> io::Result<SecurityBlob> {
    let sd = sddl::parse(sddl_text).map_err(error)?;
    Ok(SecurityBlob::new(sd.as_bytes().to_vec()))
}

fn create(path: &str, transaction: &Transaction) -> io::Result<(Key, bool)> {
    crate::write::create_all(
        path,
        KeyAccess::QUERY_VALUE | KeyAccess::SET_VALUE | KeyAccess::ENUMERATE_SUB_KEYS,
        transaction,
    )
    .map_err(at(path))
}

/// Writes `values` to `key`, skipping any already present. Says whether
/// it wrote any.
fn write_missing(key: &Key, values: &Values, transaction: &Transaction) -> io::Result<bool> {
    let mut wrote = false;
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
        wrote = true;
    }
    Ok(wrote)
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
    let transaction = Transaction::begin()
        .map_err(error)
        .map_err(at("starting a Registry transaction"))?;
    let mut seeded = Seeded::default();
    // Whether anything was written: a kernel can refuse to commit an empty
    // transaction, and there is nothing to commit.
    let mut wrote = create(ROOT, &transaction)?.1;

    let (templates, created) = create(&format!("{ROOT}\\Templates"), &transaction)?;
    wrote |= created;
    let empty = templates.subkeys(Some(&transaction)).next().is_none();
    if empty {
        let enroll = binary_sd(DEFAULT_TEMPLATE_ENROLL_SDDL)?;
        for values in [server_template(&enroll), device_template(&enroll)] {
            let id = crate::new_guid()?;
            let (key, _) = create(&format!("{ROOT}\\Templates\\{id}"), &transaction)?;
            write_missing(&key, &values, &transaction)
                .map_err(at(&format!("{ROOT}\\Templates\\{id}")))?;
            seeded.templates.push(id);
            wrote = true;
        }
    }

    let root = name_root(&binary_sd(DEFAULT_NAME_ROOT_SDDL)?);
    for tree in ["Dns", "Principals"] {
        let (key, created) = create(&format!("{ROOT}\\Names\\{tree}"), &transaction)?;
        wrote |= write_missing(&key, &root, &transaction)
            .map_err(at(&format!("{ROOT}\\Names\\{tree}")))?;
        wrote |= created;
        seeded.name_roots |= created;
    }

    wrote |= create(&format!("{ROOT}\\Authorities"), &transaction)?.1;
    if wrote {
        transaction
            .commit()
            .map_err(error)
            .map_err(at("committing the Registry transaction"))?;
    }
    // Outside the transaction: kernels before read-only snapshots
    // (2026-11-16) can't change a descriptor within one. Run again, setup
    // finishes what an interrupted run left.
    seeded.authorities_key = grant_authorities()?;
    Ok(seeded)
}

/// Gives pkid its grant on `Authorities`, with everything the key inherits
/// from above it, unless the key has it. Says whether it was given.
fn grant_authorities() -> io::Result<bool> {
    let path = format!("{ROOT}\\Authorities");
    let key = Key::open(
        None,
        &path,
        KeyAccess::READ_CONTROL | KeyAccess::WRITE_DAC,
        OpenFlags::empty(),
    )
    .map_err(error)
    .map_err(at(&path))?;
    let current = key
        .get_security(SecInfo::DACL)
        .map_err(error)
        .map_err(at(&path))?;
    if grants_pkid(current.as_bytes()) {
        return Ok(false);
    }
    let parent = Key::open(None, ROOT, KeyAccess::READ_CONTROL, OpenFlags::empty())
        .and_then(|key| key.get_security(SecInfo::DACL))
        .map_err(error)
        .map_err(at(ROOT))?;
    let own = sddl::parse(&authorities_grant()).map_err(error)?;
    let descriptor = sddl::reinherit(parent.as_bytes(), own.as_bytes(), true).map_err(error)?;
    key.set_security(SecInfo::DACL, &descriptor, None)
        .map_err(error)
        .map_err(at(&path))?;
    Ok(true)
}

/// Whether `descriptor` has pkid's own grant.
fn grants_pkid(descriptor: &[u8]) -> bool {
    let Ok(view) = SdView::parse(descriptor) else {
        return false;
    };
    view.dacl().is_some_and(|dacl| {
        dacl.iter().any(|ace| {
            ace.ace_type() == AceType::AccessAllowed
                && !ace.flags().contains(AceFlags::INHERITED)
                && ace.sid().is_some_and(|sid| sid.to_string() == SERVICE_SID)
        })
    })
}
