use std::fmt;
use std::io;

use peios_crypto::KeyAlgorithm;

/// A failure to store, describe, open or export a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyError {
    /// The key can't be reached now, such as a key file on removable media
    /// that isn't attached. Trying again later may succeed.
    Unavailable(String),
    /// The key is sealed under a passphrase and none was given.
    Locked,
    /// The passphrase is wrong, or the key was damaged or altered. The two
    /// are one error so that a guesser learns nothing from it.
    WrongPassphraseOrDamaged,
    /// The key was created non-exportable.
    NotExportable,
    /// The provider can't hold keys of this algorithm.
    UnsupportedAlgorithm(KeyAlgorithm),
    /// The provider can't honour an option, such as a passphrase for a key
    /// it protects by access control.
    UnsupportedOption(String),
    /// A new passphrase is too weak to protect a key.
    WeakPassphrase(String),
    /// A key reference is malformed or belongs to another provider.
    InvalidReference(String),
    /// A key already exists where a new one would be stored.
    AlreadyExists(String),
    /// Stored key data is malformed or contradicts itself.
    Malformed(String),
    /// Reading or writing key storage failed.
    Storage(io::ErrorKind, String),
    /// A cryptographic operation failed.
    Crypto(peios_crypto::Error),
}

impl KeyError {
    /// Classifies a storage failure for the key at `what`.
    pub fn storage(error: &io::Error, what: &str) -> Self {
        match error.kind() {
            io::ErrorKind::NotFound => Self::Unavailable(format!("{what} was not found")),
            io::ErrorKind::AlreadyExists => Self::AlreadyExists(what.to_string()),
            kind => Self::Storage(kind, format!("{what}: {error}")),
        }
    }
}

impl fmt::Display for KeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(detail) => write!(formatter, "key unavailable: {detail}"),
            Self::Locked => formatter.write_str("the key needs its passphrase"),
            Self::WrongPassphraseOrDamaged => {
                formatter.write_str("the passphrase is wrong, or the key is damaged")
            }
            Self::NotExportable => formatter.write_str("the key is not exportable"),
            Self::UnsupportedAlgorithm(algorithm) => {
                write!(formatter, "the provider can't hold {algorithm:?} keys")
            }
            Self::UnsupportedOption(detail) => write!(formatter, "unsupported option: {detail}"),
            Self::WeakPassphrase(detail) => write!(formatter, "passphrase too weak: {detail}"),
            Self::InvalidReference(detail) => write!(formatter, "invalid key reference: {detail}"),
            Self::AlreadyExists(what) => write!(formatter, "{what} already exists"),
            Self::Malformed(detail) => write!(formatter, "malformed key: {detail}"),
            Self::Storage(_, detail) => write!(formatter, "key storage failed: {detail}"),
            Self::Crypto(error) => write!(formatter, "cryptography failed: {error}"),
        }
    }
}

impl std::error::Error for KeyError {}

impl From<peios_crypto::Error> for KeyError {
    fn from(error: peios_crypto::Error) -> Self {
        match error {
            peios_crypto::Error::WrongPassphraseOrDamaged => Self::WrongPassphraseOrDamaged,
            peios_crypto::Error::MalformedSealed => Self::Malformed("not a sealed key".into()),
            peios_crypto::Error::InvalidKey => Self::Malformed("not a key Peios offers".into()),
            error => Self::Crypto(error),
        }
    }
}
