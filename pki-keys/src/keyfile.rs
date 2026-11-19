//! The key file format, which every software provider and every export use.
//!
//! A key file is version 1 of this layout:
//!
//! | Offset | Size | Field                                                |
//! |-------:|-----:|------------------------------------------------------|
//! |      0 |    8 | magic, ASCII `PEIOSKEY`                              |
//! |      8 |    1 | format version, 1                                    |
//! |      9 |    1 | algorithm: 1 P-256, 2 P-384, 3 RSA-2048, 4 RSA-3072, 5 RSA-4096 |
//! |     10 |    1 | protection: 1 passphrase, 2 access control           |
//! |     11 |    1 | flags: bit 0 set means not exportable; others zero   |
//! |     12 |    2 | public key length, big-endian                        |
//! |     14 |    … | public key, a DER `SubjectPublicKeyInfo`             |
//! |      … |    … | private key                                          |
//!
//! With passphrase protection, the private key is a peios-crypto sealed
//! blob of its PKCS #8 encoding. With access-control protection it is the
//! PKCS #8 encoding itself, and only the storage's access control keeps it
//! secret.
//!
//! Everything before the private key is readable without the passphrase, so
//! a tool can say which key a file holds before asking for it. None of it
//! is secret: the CA's certificate carries the same public key. It is not
//! authenticated either, so opening a key checks that the private key
//! matches the recorded algorithm and public key.
//!
//! A passphrase-protected file can't be marked not exportable. Whoever has
//! the file and the passphrase already has the key.

use peios_crypto::{KeyAlgorithm, PrivateKey, PublicKey, Secret, Signer};

use crate::passphrase::{NewPassphrase, Passphrase};
use crate::KeyError;

const MAGIC: &[u8; 8] = b"PEIOSKEY";
const FORMAT_VERSION: u8 = 1;
const HEADER_LEN: usize = 14;
const PROTECTION_PASSPHRASE: u8 = 1;
const PROTECTION_ACCESS_CONTROL: u8 = 2;
const FLAG_NOT_EXPORTABLE: u8 = 0x01;

/// How a stored private key is kept secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protection {
    /// Sealed under a passphrase, which must be given to open the key.
    Passphrase,
    /// Kept in storage that only the CA service can read.
    AccessControl,
}

/// What a stored key is, as far as can be told without opening it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyDescription {
    pub algorithm: KeyAlgorithm,
    pub public_key: PublicKey,
    pub protection: Protection,
    pub exportable: bool,
}

/// `key` as a key file sealed under `passphrase`, such as one a requester
/// keeps while its certificate awaits approval.
pub fn seal_key(key: &PrivateKey, passphrase: &NewPassphrase) -> Result<Vec<u8>, KeyError> {
    KeyFile::seal(key, passphrase)
}

/// A parsed key file.
pub(crate) struct KeyFile {
    description: KeyDescription,
    private_key: Secret,
}

impl KeyFile {
    /// Encodes `key` sealed under `passphrase`.
    pub(crate) fn seal(key: &PrivateKey, passphrase: &NewPassphrase) -> Result<Vec<u8>, KeyError> {
        let pkcs8 = key.to_pkcs8()?;
        let sealed = peios_crypto::seal_with_passphrase(pkcs8.expose(), passphrase.bytes())?;
        Ok(encode(key, Protection::Passphrase, true, &sealed))
    }

    /// Encodes `key` in the clear, for storage protected by access control.
    pub(crate) fn clear(key: &PrivateKey, exportable: bool) -> Result<Secret, KeyError> {
        let pkcs8 = key.to_pkcs8()?;
        Ok(Secret::new(encode(
            key,
            Protection::AccessControl,
            exportable,
            pkcs8.expose(),
        )))
    }

    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, KeyError> {
        let malformed = |detail: &str| KeyError::Malformed(detail.to_string());
        if bytes.len() < HEADER_LEN || &bytes[..8] != MAGIC {
            return Err(malformed("not a Peios key file"));
        }
        if bytes[8] != FORMAT_VERSION {
            return Err(malformed("a key file version this build does not read"));
        }
        let algorithm = algorithm_from_id(bytes[9])?;
        let protection = match bytes[10] {
            PROTECTION_PASSPHRASE => Protection::Passphrase,
            PROTECTION_ACCESS_CONTROL => Protection::AccessControl,
            _ => return Err(malformed("an unknown key protection")),
        };
        let flags = bytes[11];
        if flags & !FLAG_NOT_EXPORTABLE != 0 {
            return Err(malformed("unknown key file flags"));
        }
        let exportable = flags & FLAG_NOT_EXPORTABLE == 0;
        if protection == Protection::Passphrase && !exportable {
            return Err(malformed("a passphrase-sealed key marked not exportable"));
        }
        let public_len = usize::from(u16::from_be_bytes([bytes[12], bytes[13]]));
        let rest = &bytes[HEADER_LEN..];
        if public_len == 0 || rest.len() <= public_len {
            return Err(malformed("a truncated key file"));
        }
        let (public_key, private_key) = rest.split_at(public_len);
        let public_key = PublicKey::from_spki(public_key)?;
        if public_key.algorithm() != algorithm {
            return Err(malformed("the public key is not of the recorded algorithm"));
        }
        Ok(Self {
            description: KeyDescription {
                algorithm,
                public_key,
                protection,
                exportable,
            },
            private_key: Secret::from(private_key),
        })
    }

    pub(crate) fn description(&self) -> &KeyDescription {
        &self.description
    }

    /// The private key, unsealed with `passphrase` if the file is sealed.
    pub(crate) fn open(&self, passphrase: Option<&Passphrase>) -> Result<PrivateKey, KeyError> {
        let key = match self.description.protection {
            Protection::Passphrase => {
                let passphrase = passphrase.ok_or(KeyError::Locked)?;
                let pkcs8 = peios_crypto::open_with_passphrase(
                    self.private_key.expose(),
                    passphrase.bytes(),
                )?;
                PrivateKey::from_pkcs8(pkcs8.expose())?
            }
            Protection::AccessControl => PrivateKey::from_pkcs8(self.private_key.expose())?,
        };
        if key.algorithm() != self.description.algorithm
            || key.public_key() != &self.description.public_key
        {
            return Err(KeyError::Malformed(
                "the private key does not match the recorded public key".into(),
            ));
        }
        Ok(key)
    }
}

fn encode(key: &PrivateKey, protection: Protection, exportable: bool, private: &[u8]) -> Vec<u8> {
    let public = key.public_key().spki();
    let public_len = u16::try_from(public.len()).expect("Peios public keys are under 64 KiB");
    let mut bytes = Vec::with_capacity(HEADER_LEN + public.len() + private.len());
    bytes.extend_from_slice(MAGIC);
    bytes.push(FORMAT_VERSION);
    bytes.push(algorithm_id(key.algorithm()));
    bytes.push(match protection {
        Protection::Passphrase => PROTECTION_PASSPHRASE,
        Protection::AccessControl => PROTECTION_ACCESS_CONTROL,
    });
    bytes.push(if exportable { 0 } else { FLAG_NOT_EXPORTABLE });
    bytes.extend_from_slice(&public_len.to_be_bytes());
    bytes.extend_from_slice(public);
    bytes.extend_from_slice(private);
    bytes
}

fn algorithm_id(algorithm: KeyAlgorithm) -> u8 {
    match algorithm {
        KeyAlgorithm::EcdsaP256 => 1,
        KeyAlgorithm::EcdsaP384 => 2,
        KeyAlgorithm::Rsa2048 => 3,
        KeyAlgorithm::Rsa3072 => 4,
        KeyAlgorithm::Rsa4096 => 5,
    }
}

fn algorithm_from_id(id: u8) -> Result<KeyAlgorithm, KeyError> {
    match id {
        1 => Ok(KeyAlgorithm::EcdsaP256),
        2 => Ok(KeyAlgorithm::EcdsaP384),
        3 => Ok(KeyAlgorithm::Rsa2048),
        4 => Ok(KeyAlgorithm::Rsa3072),
        5 => Ok(KeyAlgorithm::Rsa4096),
        _ => Err(KeyError::Malformed("an unknown key algorithm".into())),
    }
}

/// Describes a sealed key file, such as a backup, without its passphrase.
pub fn describe_sealed_key(bytes: &[u8]) -> Result<KeyDescription, KeyError> {
    let file = sealed(bytes)?;
    Ok(file.description)
}

/// Opens a sealed key file, such as a backup, for import into a provider.
pub fn open_sealed_key(bytes: &[u8], passphrase: &Passphrase) -> Result<PrivateKey, KeyError> {
    sealed(bytes)?.open(Some(passphrase))
}

fn sealed(bytes: &[u8]) -> Result<KeyFile, KeyError> {
    let file = KeyFile::parse(bytes)?;
    if file.description.protection != Protection::Passphrase {
        return Err(KeyError::Malformed(
            "not a passphrase-sealed key file".into(),
        ));
    }
    Ok(file)
}
