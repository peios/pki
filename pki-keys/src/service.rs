//! Keys for an online CA, which the CA service uses unattended and which
//! only it can read.

use std::io;

use peios_crypto::{KeyAlgorithm, PrivateKey, Secret};

use crate::keyfile::{KeyDescription, KeyFile};
use crate::passphrase::{NewPassphrase, Passphrase};
use crate::provider::{check_algorithm, check_provider, OpenKey, SOFTWARE_ALGORITHMS};
use crate::{KeyError, KeyOptions, KeyProvider, KeyReference};

/// Storage that only the CA service can read.
///
/// pkid implements this over Peios access control: each key is created
/// with a security descriptor granting access to pkid's service identity
/// alone. Nothing else protects a stored key.
pub trait KeyStore: Send + Sync {
    /// Stores `contents` as `name`, failing with
    /// [`io::ErrorKind::AlreadyExists`] rather than replacing a key.
    fn create(&self, name: &str, contents: &[u8]) -> io::Result<()>;

    /// Reads the key stored as `name`.
    fn read(&self, name: &str) -> io::Result<Secret>;
}

/// Keeps keys in a [`KeyStore`], protected by its access control rather
/// than a passphrase, so the CA service can sign without anyone present.
///
/// A key's locator is its name in the store: letters, digits, `.`, `-` and
/// `_`, not starting with `.`, at most 64 characters.
pub struct ServiceKeyProvider<S> {
    store: S,
}

impl<S: KeyStore> ServiceKeyProvider<S> {
    pub const NAME: &'static str = "service";

    pub fn new(store: S) -> Self {
        Self { store }
    }

    fn name_of<'a>(&self, key: &'a KeyReference) -> Result<&'a str, KeyError> {
        check_provider(self, key)?;
        let name = key.locator();
        let valid = name.len() <= 64
            && !name.starts_with('.')
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'));
        if !valid {
            return Err(KeyError::InvalidReference(format!(
                "{key} is not a key name"
            )));
        }
        Ok(name)
    }

    fn read(&self, key: &KeyReference) -> Result<KeyFile, KeyError> {
        let name = self.name_of(key)?;
        let bytes = self
            .store
            .read(name)
            .map_err(|error| KeyError::storage(&error, &key.to_string()))?;
        KeyFile::parse(bytes.expose())
    }
}

impl<S: KeyStore> KeyProvider for ServiceKeyProvider<S> {
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
        if options.passphrase.is_some() {
            return Err(KeyError::UnsupportedOption(
                "service keys are protected by access control, not a passphrase".into(),
            ));
        }
        let reference = KeyReference::new(Self::NAME, locator)?;
        let name = self.name_of(&reference)?;
        let contents = KeyFile::clear(key, options.exportable)?;
        self.store
            .create(name, contents.expose())
            .map_err(|error| KeyError::storage(&error, &reference.to_string()))?;
        Ok(reference)
    }

    fn describe(&self, key: &KeyReference) -> Result<KeyDescription, KeyError> {
        Ok(self.read(key)?.description().clone())
    }

    fn open(
        &self,
        key: &KeyReference,
        _passphrase: Option<&Passphrase>,
    ) -> Result<OpenKey, KeyError> {
        Ok(Box::new(self.read(key)?.open(None)?))
    }

    fn export(
        &self,
        key: &KeyReference,
        _passphrase: Option<&Passphrase>,
        seal_under: &NewPassphrase,
    ) -> Result<Vec<u8>, KeyError> {
        let file = self.read(key)?;
        if !file.description().exportable {
            return Err(KeyError::NotExportable);
        }
        KeyFile::seal(&file.open(None)?, seal_under)
    }
}
