//! Reading pki's configuration from the Registry in one snapshot.

use std::io;
use std::time::Duration;

use peios::registry::{Data, Key, KeyAccess, OpenFlags, Transaction};
use pki_policy::{RegData, Values};

use crate::{Snapshot, ROOT};

/// Limits on what is read, so a damaged or hostile configuration can't
/// exhaust its reader.
const MAX_VALUES: usize = 64;
const MAX_VALUE_BYTES: usize = 64 * 1024;
const MAX_RECORDS: usize = 10_000;
const MAX_DEPTH: usize = 64;

fn open(path: &str, transaction: Option<&Transaction>) -> io::Result<Key> {
    Key::open_transacted(
        None,
        path,
        KeyAccess::QUERY_VALUE | KeyAccess::ENUMERATE_SUB_KEYS,
        OpenFlags::empty(),
        transaction,
    )
    .map_err(Into::into)
}

/// Opens `path`, or nothing if it doesn't exist.
fn open_optional(path: &str, transaction: Option<&Transaction>) -> io::Result<Option<Key>> {
    match open(path, transaction) {
        Ok(key) => Ok(Some(key)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn values(key: &Key, transaction: Option<&Transaction>) -> io::Result<Values> {
    let mut out = Values::new();
    let mut count = 0;
    for value in key.values(transaction) {
        let value = value.map_err(io::Error::from)?;
        count += 1;
        if count > MAX_VALUES || value.data.len() > MAX_VALUE_BYTES {
            return Err(io::Error::other("a Registry key exceeds pki's limits"));
        }
        let name = String::from_utf8(value.name)
            .map_err(|_| io::Error::other("a Registry value name is not UTF-8"))?;
        let data = match Data::decode(value.ty, &value.data) {
            Data::Sz(text) => RegData::Sz(text),
            Data::MultiSz(items) => RegData::MultiSz(items),
            Data::Dword(number) => RegData::Dword(number),
            Data::Binary(bytes) => RegData::Binary(bytes),
            // Values of other types are none of pki's; templates and
            // names reject a recognised name of the wrong type.
            _ => continue,
        };
        out.insert(&name, data);
    }
    Ok(out)
}

fn subkey_names(key: &Key, transaction: Option<&Transaction>) -> io::Result<Vec<String>> {
    let mut names = Vec::new();
    for subkey in key.subkeys(transaction) {
        let subkey = subkey.map_err(io::Error::from)?;
        names.push(
            String::from_utf8(subkey.name)
                .map_err(|_| io::Error::other("a Registry key name is not UTF-8"))?,
        );
        if names.len() > MAX_RECORDS {
            return Err(io::Error::other("too many configuration records"));
        }
    }
    Ok(names)
}

/// Each key under `path` with its values, by name.
fn records(path: &str, transaction: Option<&Transaction>) -> io::Result<Vec<(String, Values)>> {
    let Some(parent) = open_optional(path, transaction)? else {
        return Ok(Vec::new());
    };
    let mut records = Vec::new();
    for name in subkey_names(&parent, transaction)? {
        let key = open(&format!("{path}\\{name}"), transaction)?;
        records.push((name, values(&key, transaction)?));
    }
    Ok(records)
}

/// Every node of a name tree, by its key path below the tree's root.
fn tree(path: &str, transaction: Option<&Transaction>) -> io::Result<Vec<(Vec<String>, Values)>> {
    let mut nodes = Vec::new();
    let Some(root) = open_optional(path, transaction)? else {
        return Ok(nodes);
    };
    nodes.push((Vec::new(), values(&root, transaction)?));
    let mut pending = vec![(Vec::<String>::new(), root)];
    while let Some((below, key)) = pending.pop() {
        if below.len() >= MAX_DEPTH {
            return Err(io::Error::other("a name tree is too deep"));
        }
        for name in subkey_names(&key, transaction)? {
            let mut node = below.clone();
            node.push(name);
            let child = open(&format!("{path}\\{}", node.join("\\")), transaction)?;
            nodes.push((node.clone(), values(&child, transaction)?));
            if nodes.len() > MAX_RECORDS {
                return Err(io::Error::other("too many name records"));
            }
            pending.push((node, child));
        }
    }
    Ok(nodes)
}

fn read_once() -> io::Result<Snapshot> {
    // A kernel without read-only snapshots (before 2026-11-16) is read
    // directly. A read that races a change can then see part of it, which
    // fails validation or is superseded: the change also wakes the watch,
    // and the next read sees it whole.
    let snapshot = match Transaction::begin_read_only() {
        Ok(snapshot) => Some(snapshot),
        Err(error) if error.raw_os_error() == Some(libc::ENOSYS) => None,
        Err(error) => return Err(error.into()),
    };
    let transaction = snapshot.as_ref();
    let settings = match open_optional(&format!("{ROOT}\\Settings"), transaction)? {
        Some(key) => values(&key, transaction)?,
        None => Values::new(),
    };
    Ok(Snapshot {
        settings,
        templates: records(&format!("{ROOT}\\Templates"), transaction)?,
        dns: tree(&format!("{ROOT}\\Names\\Dns"), transaction)?,
        principals: tree(&format!("{ROOT}\\Names\\Principals"), transaction)?,
        authorities: records(&format!("{ROOT}\\Authorities"), transaction)?,
    })
}

/// Reads the configuration in one read-only snapshot, retrying briefly if
/// a writer holds the Registry. A failed attempt is discarded whole.
pub fn read() -> io::Result<Snapshot> {
    let mut retries = 3;
    loop {
        match read_once() {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock && retries > 0 => {
                retries -= 1;
                std::thread::sleep(Duration::from_millis(2));
            }
            result => return result,
        }
    }
}

/// A value as the Registry stores it.
pub fn data(value: &RegData) -> Data {
    match value {
        RegData::Sz(text) => Data::Sz(text.clone()),
        RegData::MultiSz(items) => Data::MultiSz(items.clone()),
        RegData::Dword(number) => Data::Dword(*number),
        RegData::Binary(bytes) => Data::Binary(bytes.clone()),
    }
}
