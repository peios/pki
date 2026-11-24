//! Key storage for Peios PKI.
//!
//! A CA's private key lives with a [`KeyProvider`], and configuration
//! records it as a [`KeyReference`]. Providers may keep keys anywhere,
//! including hardware that never releases them, so callers never assume a
//! key is a file, can be exported or is reachable right now.
//!
//! Two providers hold keys in software. [`KeyFileProvider`] seals each key
//! under a passphrase, for roots and other keys kept offline or on
//! removable media. [`ServiceKeyProvider`] keeps keys that the CA service
//! uses unattended, protected by the access control of a [`KeyStore`] that
//! pkid supplies. Both write the same [key file format](keyfile), and an
//! export is always a passphrase-sealed key file, never a key in the clear.
//!
//! Every passphrase that seals a key must be a [`NewPassphrase`], which
//! enforces [`MIN_PASSPHRASE_CHARS`]. Providers make no access checks of
//! their own.

mod error;
mod file;
pub mod keyfile;
mod passphrase;
mod provider;
mod reference;
mod service;
#[cfg(test)]
mod vectors;

pub use error::KeyError;
pub use file::KeyFileProvider;
pub use keyfile::{describe_sealed_key, open_sealed_key, seal_key, KeyDescription, Protection};
pub use passphrase::{NewPassphrase, Passphrase, MIN_PASSPHRASE_CHARS};
pub use peios_crypto::{KeyAlgorithm, PrivateKey, PublicKey, Signer};
pub use provider::{KeyOptions, KeyProvider, KeyProviders, OpenKey, SOFTWARE_ALGORITHMS};
pub use reference::KeyReference;
pub use service::{KeyStore, ServiceKeyProvider};
