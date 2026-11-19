//! Passphrase-sealed key files, for keys kept on the CA machine, on
//! removable media or on an offline machine.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use peios_crypto::{KeyAlgorithm, PrivateKey};

use crate::keyfile::{KeyDescription, KeyFile};
use crate::passphrase::{NewPassphrase, Passphrase};
use crate::provider::{check_algorithm, check_provider, OpenKey, SOFTWARE_ALGORITHMS};
use crate::{KeyError, KeyOptions, KeyProvider, KeyReference};

/// Keeps each key in its own passphrase-sealed file. A key's locator is the
/// file's absolute path.
///
/// Every key is exportable: a sealed file is already an export, which
/// anyone holding it and its passphrase can open. Files are created only
/// readable by their owner, and an existing file is never replaced.
#[derive(Debug, Default)]
pub struct KeyFileProvider;

impl KeyFileProvider {
    pub const NAME: &'static str = "file";

    pub fn new() -> Self {
        Self
    }

    fn path<'a>(&self, key: &'a KeyReference) -> Result<&'a Path, KeyError> {
        check_provider(self, key)?;
        let path = Path::new(key.locator());
        if !path.is_absolute() {
            return Err(KeyError::InvalidReference(format!(
                "{key} is not an absolute path"
            )));
        }
        Ok(path)
    }

    fn read(&self, key: &KeyReference) -> Result<KeyFile, KeyError> {
        let path = self.path(key)?;
        let bytes = fs::read(path).map_err(|error| KeyError::storage(&error, &key.to_string()))?;
        KeyFile::parse(&bytes)
    }
}

impl KeyProvider for KeyFileProvider {
    fn name(&self) -> &str {
        Self::NAME
    }

    fn algorithms(&self) -> &[KeyAlgorithm] {
        SOFTWARE_ALGORITHMS
    }

    fn generate(
        &self,
        locator: &str,
        algorithm: KeyAlgorithm,
        options: &KeyOptions<'_>,
    ) -> Result<KeyReference, KeyError> {
        check_algorithm(self, algorithm)?;
        let key = PrivateKey::generate(algorithm)?;
        self.import(locator, &key, options)
    }

    fn import(
        &self,
        locator: &str,
        key: &PrivateKey,
        options: &KeyOptions<'_>,
    ) -> Result<KeyReference, KeyError> {
        check_algorithm(self, key.algorithm())?;
        if !options.exportable {
            return Err(KeyError::UnsupportedOption(
                "a key file is itself an export and can't be made non-exportable".into(),
            ));
        }
        let passphrase = options.passphrase.ok_or_else(|| {
            KeyError::UnsupportedOption("a key file must be sealed under a passphrase".into())
        })?;
        let reference = KeyReference::new(Self::NAME, locator)?;
        let path = self.path(&reference)?;
        let bytes = KeyFile::seal(key, passphrase)?;
        write_new(path, &bytes)
            .map_err(|error| KeyError::storage(&error, &reference.to_string()))?;
        Ok(reference)
    }

    fn describe(&self, key: &KeyReference) -> Result<KeyDescription, KeyError> {
        Ok(self.read(key)?.description().clone())
    }

    fn open(
        &self,
        key: &KeyReference,
        passphrase: Option<&Passphrase>,
    ) -> Result<OpenKey, KeyError> {
        Ok(Box::new(self.read(key)?.open(passphrase)?))
    }

    fn export(
        &self,
        key: &KeyReference,
        passphrase: Option<&Passphrase>,
        seal_under: &NewPassphrase,
    ) -> Result<Vec<u8>, KeyError> {
        let key = self.read(key)?.open(passphrase)?;
        KeyFile::seal(&key, seal_under)
    }

    fn delete(&self, key: &KeyReference) -> Result<(), KeyError> {
        let path = self.path(key)?;
        fs::remove_file(path).map_err(|error| KeyError::storage(&error, &key.to_string()))
    }
}

/// Writes `bytes` to a new file at `path`, readable only by its owner, and
/// makes it durable before returning. A partly written file is removed.
fn write_new(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    let written = file.write_all(bytes).and_then(|()| file.sync_all());
    if let Err(error) = written {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error);
    }
    if let Some(directory) = path.parent() {
        File::open(directory)?.sync_all()?;
    }
    Ok(())
}
