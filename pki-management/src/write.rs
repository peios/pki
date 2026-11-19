//! Changing pki's configuration: each change is one Registry transaction,
//! so pkid never reads half of it.

use std::io;

use peios::registry::{CreateFlags, Disposition, Key, KeyAccess, OpenFlags, Transaction};
use pki_policy::Values;

use crate::registry::data;

/// Creates `path`, and each key above it that is missing, in
/// `transaction`, opening the last with `access`. Says whether `path`
/// itself was new. The Registry creates one key at a time: a key whose
/// parent is missing is refused, and a machine need not have
/// `Machine\Software` yet.
pub fn create_all(
    path: &str,
    access: KeyAccess,
    transaction: &Transaction,
) -> io::Result<(Key, bool)> {
    let segments: Vec<&str> = path.split('\\').collect();
    let mut at = segments[0].to_string();
    let mut last = None;
    // The first segment is the hive, which always exists.
    for (index, segment) in segments.iter().enumerate().skip(1) {
        at.push('\\');
        at.push_str(segment);
        let access = if index + 1 == segments.len() {
            access
        } else {
            KeyAccess::QUERY_VALUE
        };
        let (key, disposition) = Key::create(
            None,
            &at,
            access,
            CreateFlags::empty(),
            None,
            Some(transaction),
        )?;
        last = Some((key, disposition == Disposition::CreatedNew));
    }
    last.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, format!("{path} is a hive")))
}

fn create_path(path: &str, transaction: &Transaction) -> io::Result<(Key, bool)> {
    create_all(
        path,
        KeyAccess::QUERY_VALUE | KeyAccess::SET_VALUE,
        transaction,
    )
}

fn apply(key: &Key, set: &Values, remove: &[&str], transaction: &Transaction) -> io::Result<()> {
    for (name, value) in set.iter() {
        let value = data(value);
        key.set_value(name.as_bytes(), value.ty(), &value.encode())
            .in_txn(transaction)
            .call()?;
    }
    for name in remove {
        if let Err(error) = key.delete_value(name.as_bytes(), None, Some(transaction)) {
            let error: io::Error = error.into();
            if error.kind() != io::ErrorKind::NotFound {
                return Err(error);
            }
        }
    }
    Ok(())
}

/// Sets `set` and removes `remove` on the existing key `path`.
pub fn change(path: &str, set: &Values, remove: &[&str]) -> io::Result<()> {
    let transaction = Transaction::begin()?;
    let key = Key::open_transacted(
        None,
        path,
        KeyAccess::QUERY_VALUE | KeyAccess::SET_VALUE,
        OpenFlags::empty(),
        Some(&transaction),
    )?;
    apply(&key, set, remove, &transaction)?;
    transaction.commit()?;
    Ok(())
}

/// Sets `set` and removes `remove` on `path`, creating it and any keys
/// above it first if they are missing.
pub fn put(path: &str, set: &Values, remove: &[&str]) -> io::Result<()> {
    let transaction = Transaction::begin()?;
    let (key, _) = create_path(path, &transaction)?;
    apply(&key, set, remove, &transaction)?;
    transaction.commit()?;
    Ok(())
}

/// Creates `path` with `set`, failing if it exists.
pub fn create(path: &str, set: &Values) -> io::Result<()> {
    let transaction = Transaction::begin()?;
    let (key, created) = create_path(path, &transaction)?;
    if !created {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "it exists already",
        ));
    }
    apply(&key, set, &[], &transaction)?;
    transaction.commit()?;
    Ok(())
}

/// Deletes the key `path`, which must have no keys below it. One deletion
/// needs no transaction, and kernels before read-only snapshots
/// (2026-11-16) can't delete within one.
pub fn delete(path: &str) -> io::Result<()> {
    let key = Key::open(None, path, KeyAccess::DELETE, OpenFlags::empty())?;
    key.delete_key(None, None)?;
    Ok(())
}
