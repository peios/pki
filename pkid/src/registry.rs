//! Writing pkid's CA records to the Registry, and noticing changes. The
//! configuration itself is read by `pki-management`.

use std::io;

use peios::registry::{CreateFlags, Key, KeyAccess, NotifyFilter, OpenFlags, Transaction};
use pki_management::registry::{data, read};
use pki_policy::Values;

use crate::config::{Source, ROOT};
use crate::dispatch::Configurator;

/// Writes CA records, under the grant provisioning gave pkid on
/// `Authorities`.
pub struct RegistryConfigurator;

impl RegistryConfigurator {
    fn write(id: &str, values: &Values, remove: &[&str]) -> io::Result<()> {
        if id.is_empty()
            || !id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
        {
            return Err(io::Error::other(format!("{id} is not a CA identifier")));
        }
        let transaction = Transaction::begin()?;
        let (key, _) = Key::create(
            None,
            &format!("{ROOT}\\Authorities\\{id}"),
            KeyAccess::QUERY_VALUE | KeyAccess::SET_VALUE,
            CreateFlags::empty(),
            None,
            Some(&transaction),
        )?;
        for (name, value) in values.iter() {
            let value = data(value);
            key.set_value(name.as_bytes(), value.ty(), &value.encode())
                .in_txn(&transaction)
                .call()?;
        }
        for name in remove {
            if let Err(error) = key.delete_value(name.as_bytes(), None, Some(&transaction)) {
                let error: io::Error = error.into();
                if error.kind() != io::ErrorKind::NotFound {
                    return Err(error);
                }
            }
        }
        transaction.commit()?;
        Ok(())
    }
}

impl Configurator for RegistryConfigurator {
    fn write_authority(&self, id: &str, values: &Values, remove: &[&str]) -> Result<(), String> {
        Self::write(id, values, remove).map_err(|error| format!("writing CA {id}: {error}"))
    }

    fn read(&self) -> Source {
        read().map_err(|error| format!("reading the Registry: {error}"))
    }
}

/// A watch on the configuration subtree.
pub struct Watch {
    key: Key,
}

impl Watch {
    pub fn new() -> io::Result<Self> {
        let key = Key::open(None, ROOT, KeyAccess::NOTIFY, OpenFlags::empty())?;
        key.notify(NotifyFilter::ALL, true)?;
        Ok(Self { key })
    }

    /// Waits until the subtree changes. Every change, including an overflow
    /// of the watch's queue, means the same thing to pkid: read it all again.
    pub fn wait(&self) -> io::Result<()> {
        let mut buffer = vec![0; 64 * 1024];
        self.key.read_watch_events(&mut buffer)?;
        Ok(())
    }
}
