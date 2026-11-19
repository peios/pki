use peios_crypto::{KeyAlgorithm, PrivateKey, Signer};

use crate::keyfile::KeyDescription;
use crate::passphrase::{NewPassphrase, Passphrase};
use crate::{KeyError, KeyReference};

/// Every algorithm Peios offers, all of which software providers hold.
pub const SOFTWARE_ALGORITHMS: &[KeyAlgorithm] = &[
    KeyAlgorithm::EcdsaP256,
    KeyAlgorithm::EcdsaP384,
    KeyAlgorithm::Rsa2048,
    KeyAlgorithm::Rsa3072,
    KeyAlgorithm::Rsa4096,
];

/// A key opened for signing.
pub type OpenKey = Box<dyn Signer + Send + Sync>;

/// How a provider should keep a key it creates or imports.
#[derive(Debug, Clone, Copy)]
pub struct KeyOptions<'a> {
    /// Whether the key may later be exported. This can't be changed once
    /// the key exists.
    pub exportable: bool,
    /// The passphrase to seal the key under, for providers that seal keys.
    pub passphrase: Option<&'a NewPassphrase>,
}

/// Somewhere CA keys are kept.
///
/// A provider may keep keys anywhere, including hardware that never
/// releases them, so nothing here assumes a key is a file, can be exported
/// or is always reachable. Providers make no access checks: the CA service
/// decides who may use, create or export a key before asking a provider.
pub trait KeyProvider: Send + Sync {
    /// The name every reference to this provider's keys carries.
    fn name(&self) -> &str;

    /// The algorithms this provider can create and hold keys of.
    fn algorithms(&self) -> &[KeyAlgorithm];

    /// Creates a key of `algorithm` at `locator`.
    fn generate(
        &self,
        locator: &str,
        algorithm: KeyAlgorithm,
        options: &KeyOptions<'_>,
    ) -> Result<KeyReference, KeyError>;

    /// Stores an existing key at `locator`, such as one restored from a
    /// backup.
    fn import(
        &self,
        locator: &str,
        key: &PrivateKey,
        options: &KeyOptions<'_>,
    ) -> Result<KeyReference, KeyError>;

    /// Describes a stored key without opening it.
    fn describe(&self, key: &KeyReference) -> Result<KeyDescription, KeyError>;

    /// Opens a stored key for signing. Keys sealed under a passphrase need
    /// it; others ignore `passphrase`.
    fn open(
        &self,
        key: &KeyReference,
        passphrase: Option<&Passphrase>,
    ) -> Result<OpenKey, KeyError>;

    /// Exports a stored key as a key file sealed under `seal_under`. A key
    /// is never exported in the clear.
    fn export(
        &self,
        key: &KeyReference,
        passphrase: Option<&Passphrase>,
        seal_under: &NewPassphrase,
    ) -> Result<Vec<u8>, KeyError>;

    /// Destroys a stored key, such as one made for a CA whose creation then
    /// failed. The CA service decides who may; a destroyed key can't be
    /// recovered except from an export.
    fn delete(&self, key: &KeyReference) -> Result<(), KeyError>;
}

/// Refuses an algorithm `provider` does not hold.
pub(crate) fn check_algorithm(
    provider: &dyn KeyProvider,
    algorithm: KeyAlgorithm,
) -> Result<(), KeyError> {
    if provider.algorithms().contains(&algorithm) {
        Ok(())
    } else {
        Err(KeyError::UnsupportedAlgorithm(algorithm))
    }
}

/// Refuses a reference to another provider's key.
pub(crate) fn check_provider(
    provider: &dyn KeyProvider,
    key: &KeyReference,
) -> Result<(), KeyError> {
    if key.provider() == provider.name() {
        Ok(())
    } else {
        Err(KeyError::InvalidReference(format!(
            "{key} is not a {} key",
            provider.name()
        )))
    }
}

/// The providers a CA service can use, found by name.
#[derive(Default)]
pub struct KeyProviders {
    providers: Vec<Box<dyn KeyProvider>>,
}

impl KeyProviders {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds `provider`, refusing a second provider of the same name.
    pub fn add(&mut self, provider: Box<dyn KeyProvider>) -> Result<(), KeyError> {
        if self.get(provider.name()).is_some() {
            return Err(KeyError::AlreadyExists(format!(
                "the {} provider",
                provider.name()
            )));
        }
        self.providers.push(provider);
        Ok(())
    }

    pub fn get(&self, name: &str) -> Option<&dyn KeyProvider> {
        self.providers
            .iter()
            .find(|provider| provider.name() == name)
            .map(|provider| provider.as_ref())
    }

    /// The provider holding `key`.
    pub fn for_key(&self, key: &KeyReference) -> Result<&dyn KeyProvider, KeyError> {
        self.get(key.provider())
            .ok_or_else(|| KeyError::InvalidReference(format!("no provider holds {key}")))
    }
}
