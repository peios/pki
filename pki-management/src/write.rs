//! Changing pki's configuration: each change is one Registry transaction,
//! so pkid never reads half of it.

use std::io;

use peios::registry::{CreateFlags, Disposition, Key, KeyAccess, OpenFlags, Transaction};
use pki_policy::Values;

use crate::registry::data;

/// Creates `path`, with any keys above it that are missing, in
/// `transaction`. Says whether `path` itself was new.
fn create_path(path: &str, transaction: &Transaction) -> io::Result<(Key, bool)> {
    let (key, disposition) = Key::create(
        None,
        path,
        KeyAccess::QUERY_VALUE | KeyAccess::SET_VALUE,
        CreateFlags::empty(),
        None,
        Some(transaction),
    )?;
    Ok((key, disposition == Disposition::CreatedNew))
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

/// Deletes the key `path`, which must have no keys below it.
pub fn delete(path: &str) -> io::Result<()> {
    let transaction = Transaction::begin()?;
    let key = Key::open_transacted(
        None,
        path,
        KeyAccess::DELETE,
        OpenFlags::empty(),
        Some(&transaction),
    )?;
    key.delete_key(None, Some(&transaction))?;
    transaction.commit()?;
    Ok(())
}
