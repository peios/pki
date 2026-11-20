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

/// pki-httpd's grant on `Http`, so that it can read its port.
pub fn http_grant() -> String {
    format!("O:SYG:SYD:(A;;KR;;;{HTTPD_SERVICE_SID})")
}

/// The descriptor of pki-httpd's port reservation: it, and SYSTEM, may
/// bind the port (`KACS_PORT_BIND`).
pub fn port_reservation() -> String {
    format!("O:SYG:SYD:(A;;0x1;;;SY)(A;;0x1;;;{HTTPD_SERVICE_SID})")
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
    /// Whether pki-httpd was given read access to `Http`.
    pub http_key: bool,
    /// What became of pki-httpd's port reservation.
    pub port: Reservation,
}

/// pki-httpd's reservation of its port, which it needs to bind it.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub enum Reservation {
    /// Setup reserved the port for pki-httpd.
    Added(u16),
    /// The port was already reserved for pki-httpd.
    #[default]
    Present,
    /// Another reservation of exactly this port exists, and it doesn't
    /// admit pki-httpd. Setup leaves it as it is.
    Taken(u16),
    /// The machine has no reservation table to add to.
    NoTable,
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
    wrote |= create(&format!("{ROOT}\\Http"), &transaction)?.1;
    if wrote {
        transaction
            .commit()
            .map_err(error)
            .map_err(at("committing the Registry transaction"))?;
    }
    // Outside the transaction: kernels before read-only snapshots
    // (2026-11-16) can't change a descriptor within one. Run again, setup
    // finishes what an interrupted run left.
    seeded.authorities_key = grant(
        &format!("{ROOT}\\Authorities"),
        SERVICE_SID,
        &authorities_grant(),
    )?;
    seeded.http_key = grant(&format!("{ROOT}\\Http"), HTTPD_SERVICE_SID, &http_grant())?;
    seeded.port = reserve_port()?;
    Ok(seeded)
}

/// Gives `sid` the grant `own` on the key `path`, with everything the key
/// inherits from above it, unless the key has an entry of its own for
/// `sid`. Says whether it was given.
fn grant(path: &str, sid: &str, own: &str) -> io::Result<bool> {
    let key = Key::open(
        None,
        path,
        KeyAccess::READ_CONTROL | KeyAccess::WRITE_DAC,
        OpenFlags::empty(),
    )
    .map_err(error)
    .map_err(at(path))?;
    let current = key
        .get_security(SecInfo::DACL)
        .map_err(error)
        .map_err(at(path))?;
    if grants(current.as_bytes(), sid) {
        return Ok(false);
    }
    let parent = Key::open(None, ROOT, KeyAccess::READ_CONTROL, OpenFlags::empty())
        .and_then(|key| key.get_security(SecInfo::DACL))
        .map_err(error)
        .map_err(at(ROOT))?;
    let own = sddl::parse(own).map_err(error)?;
    let descriptor = sddl::reinherit(parent.as_bytes(), own.as_bytes(), true).map_err(error)?;
    key.set_security(SecInfo::DACL, &descriptor, None)
        .map_err(error)
        .map_err(at(path))?;
    Ok(true)
}

/// Whether `descriptor` has an entry of its own allowing `sid` anything.
fn grants(descriptor: &[u8], sid: &str) -> bool {
    let Ok(view) = SdView::parse(descriptor) else {
        return false;
    };
    view.dacl().is_some_and(|dacl| {
        dacl.iter().any(|ace| {
            ace.ace_type() == AceType::AccessAllowed
                && !ace.flags().contains(AceFlags::INHERITED)
                && ace.sid().is_some_and(|entry| entry.to_string() == sid)
        })
    })
}

/// The port reservation table.
pub const PORT_RESERVATIONS: &str = "Machine\\System\\Network\\TcpIp\\PortReservations";

/// The port pki-httpd serves on: `Http Port`, or 80.
pub fn http_port() -> io::Result<u16> {
    let path = format!("{ROOT}\\Http");
    let key = match Key::open(None, &path, KeyAccess::QUERY_VALUE, OpenFlags::empty()) {
        Ok(key) => key,
        Err(failure) => {
            let failure: io::Error = failure.into();
            return if failure.kind() == io::ErrorKind::NotFound {
                Ok(DEFAULT_HTTP_PORT)
            } else {
                Err(at(&path)(failure))
            };
        }
    };
    match key.query_value(b"Port", None) {
        Ok(value) => match peios::registry::Data::decode(value.ty, &value.data) {
            peios::registry::Data::Dword(port) if (1..=65535).contains(&port) => Ok(port as u16),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{path} Port: not a port number from 1 to 65535"),
            )),
        },
        Err(failure) => {
            let failure: io::Error = failure.into();
            if failure.kind() == io::ErrorKind::NotFound {
                Ok(DEFAULT_HTTP_PORT)
            } else {
                Err(at(&path)(failure))
            }
        }
    }
}

/// The port pki-httpd serves on unless `Http Port` sets one.
pub const DEFAULT_HTTP_PORT: u16 = 80;

/// Reserves pki-httpd's TCP port for it, unless a reservation of exactly
/// that port exists, which setup never replaces: the table is shared, and
/// the kernel refuses it whole if it is malformed.
fn reserve_port() -> io::Result<Reservation> {
    let port = http_port()?;
    let key = match Key::open(
        None,
        PORT_RESERVATIONS,
        KeyAccess::QUERY_VALUE | KeyAccess::SET_VALUE,
        OpenFlags::empty(),
    ) {
        Ok(key) => key,
        Err(failure) => {
            let failure: io::Error = failure.into();
            return if failure.kind() == io::ErrorKind::NotFound {
                Ok(Reservation::NoTable)
            } else {
                Err(at(PORT_RESERVATIONS)(failure))
            };
        }
    };
    let selector = format!("tcp:{port}");
    match key.query_value(selector.as_bytes(), None) {
        Ok(existing) if grants(&existing.data, HTTPD_SERVICE_SID) => Ok(Reservation::Present),
        Ok(_) => Ok(Reservation::Taken(port)),
        Err(failure) => {
            let failure: io::Error = failure.into();
            if failure.kind() != io::ErrorKind::NotFound {
                return Err(at(PORT_RESERVATIONS)(failure));
            }
            let descriptor = sddl::parse(&port_reservation()).map_err(error)?;
            let data = peios::registry::Data::Binary(descriptor.as_bytes().to_vec());
            key.set_value(selector.as_bytes(), data.ty(), &data.encode())
                .call()
                .map_err(error)
                .map_err(at(PORT_RESERVATIONS))?;
            Ok(Reservation::Added(port))
        }
    }
}
