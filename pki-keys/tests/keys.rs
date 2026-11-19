//! Behaviour of the key storage providers.

use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use peios_crypto::{Secret, SignatureScheme};
use pki_core::{create_root, CaProfile, CaSubject, IssuingCa, SerialNumber, Validity};
use pki_keys::{
    describe_sealed_key, open_sealed_key, KeyAlgorithm, KeyError, KeyFileProvider, KeyOptions,
    KeyProvider, KeyProviders, KeyReference, KeyStore, NewPassphrase, Passphrase, PrivateKey,
    Protection, ServiceKeyProvider, Signer, MIN_PASSPHRASE_CHARS,
};
use time::macros::datetime;

const PASSPHRASE: &str = "correct horse battery staple";

/// A key store in memory, standing in for pkid's access-controlled one.
/// Clones share their keys, so a test can inspect what a provider stored.
#[derive(Default, Clone)]
struct MemoryStore(Arc<Mutex<HashMap<String, Vec<u8>>>>);

impl KeyStore for MemoryStore {
    fn create(&self, name: &str, contents: &[u8]) -> io::Result<()> {
        let mut keys = self.0.lock().unwrap();
        if keys.contains_key(name) {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        keys.insert(name.to_string(), contents.to_vec());
        Ok(())
    }

    fn read(&self, name: &str) -> io::Result<Secret> {
        let keys = self.0.lock().unwrap();
        let contents = keys.get(name).ok_or(io::ErrorKind::NotFound)?;
        Ok(Secret::from(contents.as_slice()))
    }
}

impl MemoryStore {
    fn bytes(&self, name: &str) -> Vec<u8> {
        self.0.lock().unwrap()[name].clone()
    }

    fn change(&self, name: &str, change: impl FnOnce(&mut Vec<u8>)) {
        change(self.0.lock().unwrap().get_mut(name).unwrap());
    }
}

/// A fresh, empty directory for one test's key files.
fn directory(test: &str) -> PathBuf {
    let directory = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(test);
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

fn new_passphrase(text: &str) -> NewPassphrase {
    NewPassphrase::new(text).unwrap()
}

fn sealed(passphrase: &NewPassphrase) -> KeyOptions<'_> {
    KeyOptions {
        exportable: true,
        passphrase: Some(passphrase),
    }
}

const SERVICE: KeyOptions<'static> = KeyOptions {
    exportable: true,
    passphrase: None,
};

const SERVICE_NOT_EXPORTABLE: KeyOptions<'static> = KeyOptions {
    exportable: false,
    passphrase: None,
};

fn assert_signs(key: &dyn Signer, scheme: SignatureScheme) {
    let signature = key.sign(scheme, b"to be signed").unwrap();
    key.public_key()
        .verify(scheme, b"to be signed", &signature)
        .unwrap();
}

#[test]
fn key_files_are_sealed_under_their_passphrase() {
    let provider = KeyFileProvider::new();
    let path = directory("sealed").join("root.key");
    let passphrase = new_passphrase(PASSPHRASE);
    let reference = provider
        .generate(
            path.to_str().unwrap(),
            KeyAlgorithm::EcdsaP384,
            &sealed(&passphrase),
        )
        .unwrap();
    assert_eq!(reference.to_string(), format!("file:{}", path.display()));

    let description = provider.describe(&reference).unwrap();
    assert_eq!(description.algorithm, KeyAlgorithm::EcdsaP384);
    assert_eq!(description.protection, Protection::Passphrase);
    assert!(description.exportable);

    assert_eq!(
        provider.open(&reference, None).err(),
        Some(KeyError::Locked)
    );
    assert_eq!(
        provider
            .open(&reference, Some(&Passphrase::new("a different passphrase")))
            .err(),
        Some(KeyError::WrongPassphraseOrDamaged)
    );
    let key = provider
        .open(&reference, Some(&Passphrase::new(PASSPHRASE)))
        .unwrap();
    assert_eq!(key.public_key(), &description.public_key);
    assert_signs(key.as_ref(), SignatureScheme::EcdsaSha384);

    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(describe_sealed_key(&bytes).unwrap(), description);
}

#[cfg(unix)]
#[test]
fn key_files_are_readable_only_by_their_owner() {
    use std::os::unix::fs::PermissionsExt;

    let provider = KeyFileProvider::new();
    let path = directory("owner-only").join("root.key");
    let passphrase = new_passphrase(PASSPHRASE);
    provider
        .generate(
            path.to_str().unwrap(),
            KeyAlgorithm::EcdsaP256,
            &sealed(&passphrase),
        )
        .unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn key_files_are_never_replaced() {
    let provider = KeyFileProvider::new();
    let path = directory("never-replaced").join("root.key");
    let passphrase = new_passphrase(PASSPHRASE);
    let locator = path.to_str().unwrap();
    provider
        .generate(locator, KeyAlgorithm::EcdsaP256, &sealed(&passphrase))
        .unwrap();
    let before = std::fs::read(&path).unwrap();
    let again = provider.generate(locator, KeyAlgorithm::EcdsaP256, &sealed(&passphrase));
    assert!(matches!(again, Err(KeyError::AlreadyExists(_))));
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn key_files_need_a_passphrase_and_are_always_exportable() {
    let provider = KeyFileProvider::new();
    let directory = directory("file-options");
    let locator = directory.join("root.key");
    let locator = locator.to_str().unwrap();
    let passphrase = new_passphrase(PASSPHRASE);

    let unsealed = provider.generate(locator, KeyAlgorithm::EcdsaP256, &SERVICE);
    assert!(matches!(unsealed, Err(KeyError::UnsupportedOption(_))));
    let not_exportable = KeyOptions {
        exportable: false,
        passphrase: Some(&passphrase),
    };
    let result = provider.generate(locator, KeyAlgorithm::EcdsaP256, &not_exportable);
    assert!(matches!(result, Err(KeyError::UnsupportedOption(_))));
    assert!(!directory.join("root.key").exists());
}

#[test]
fn missing_key_files_are_unavailable() {
    let provider = KeyFileProvider::new();
    let path = directory("missing").join("not-attached").join("root.key");
    let reference = KeyReference::new("file", path.to_str().unwrap()).unwrap();
    assert!(matches!(
        provider.describe(&reference),
        Err(KeyError::Unavailable(_))
    ));
    assert!(matches!(
        provider.open(&reference, Some(&Passphrase::new(PASSPHRASE))),
        Err(KeyError::Unavailable(_))
    ));
}

#[test]
fn key_file_locators_are_absolute_paths() {
    let provider = KeyFileProvider::new();
    let passphrase = new_passphrase(PASSPHRASE);
    let result = provider.generate("root.key", KeyAlgorithm::EcdsaP256, &sealed(&passphrase));
    assert!(matches!(result, Err(KeyError::InvalidReference(_))));
}

#[test]
fn new_passphrases_need_fifteen_characters() {
    assert_eq!(MIN_PASSPHRASE_CHARS, 15);
    assert!(matches!(
        NewPassphrase::new("fourteen chars"),
        Err(KeyError::WeakPassphrase(_))
    ));
    assert!(NewPassphrase::new("fifteen chars!!").is_ok());
    // Characters, not bytes: fourteen two-byte characters are too few.
    assert!(NewPassphrase::new(&"é".repeat(14)).is_err());
    assert!(NewPassphrase::new(&"é".repeat(15)).is_ok());
}

#[test]
fn passphrases_match_however_their_characters_are_encoded() {
    let provider = KeyFileProvider::new();
    let path = directory("normalised").join("root.key");
    // "é" as one code point, then as "e" with a combining acute accent.
    let composed = "caf\u{e9} au lait, s'il vous pla\u{ee}t";
    let decomposed = "cafe\u{301} au lait, s'il vous plai\u{302}t";
    assert_ne!(composed, decomposed);
    let passphrase = new_passphrase(composed);
    let reference = provider
        .generate(
            path.to_str().unwrap(),
            KeyAlgorithm::EcdsaP256,
            &sealed(&passphrase),
        )
        .unwrap();
    provider
        .open(&reference, Some(&Passphrase::new(decomposed)))
        .unwrap();
}

#[test]
fn service_keys_open_without_a_passphrase() {
    let provider = ServiceKeyProvider::new(MemoryStore::default());
    let reference = provider
        .generate("issuing-2026", KeyAlgorithm::Rsa3072, &SERVICE)
        .unwrap();
    assert_eq!(reference.to_string(), "service:issuing-2026");
    let description = provider.describe(&reference).unwrap();
    assert_eq!(description.algorithm, KeyAlgorithm::Rsa3072);
    assert_eq!(description.protection, Protection::AccessControl);
    let key = provider.open(&reference, None).unwrap();
    assert_eq!(key.public_key(), &description.public_key);
    assert_signs(key.as_ref(), SignatureScheme::RsaPkcs1Sha256);
}

#[test]
fn service_keys_refuse_a_passphrase_and_bad_names() {
    let provider = ServiceKeyProvider::new(MemoryStore::default());
    let passphrase = new_passphrase(PASSPHRASE);
    let result = provider.generate("issuing", KeyAlgorithm::EcdsaP256, &sealed(&passphrase));
    assert!(matches!(result, Err(KeyError::UnsupportedOption(_))));
    for name in ["../issuing", ".hidden", "with space", &"x".repeat(65)] {
        let result = provider.generate(name, KeyAlgorithm::EcdsaP256, &SERVICE);
        assert!(
            matches!(result, Err(KeyError::InvalidReference(_))),
            "{name}"
        );
    }
}

#[test]
fn exports_are_sealed_and_restore_the_same_key() {
    let online = ServiceKeyProvider::new(MemoryStore::default());
    let reference = online
        .generate("issuing", KeyAlgorithm::EcdsaP256, &SERVICE)
        .unwrap();
    let backup_passphrase = new_passphrase("a long backup passphrase");
    let backup = online.export(&reference, None, &backup_passphrase).unwrap();

    let description = describe_sealed_key(&backup).unwrap();
    assert_eq!(description.protection, Protection::Passphrase);
    assert_eq!(
        description.public_key,
        online.describe(&reference).unwrap().public_key
    );
    assert_eq!(
        open_sealed_key(&backup, &Passphrase::new("not the backup passphrase")).err(),
        Some(KeyError::WrongPassphraseOrDamaged)
    );

    let restored = open_sealed_key(&backup, &Passphrase::new("a long backup passphrase")).unwrap();
    let replacement = ServiceKeyProvider::new(MemoryStore::default());
    let restored = replacement.import("issuing", &restored, &SERVICE).unwrap();
    assert_eq!(
        replacement.describe(&restored).unwrap().public_key,
        description.public_key
    );
}

#[test]
fn key_files_can_be_resealed_under_a_new_passphrase() {
    let provider = KeyFileProvider::new();
    let path = directory("reseal").join("root.key");
    let passphrase = new_passphrase(PASSPHRASE);
    let reference = provider
        .generate(
            path.to_str().unwrap(),
            KeyAlgorithm::EcdsaP256,
            &sealed(&passphrase),
        )
        .unwrap();
    let new = new_passphrase("an entirely new passphrase");
    assert_eq!(
        provider.export(&reference, None, &new).err(),
        Some(KeyError::Locked)
    );
    let exported = provider
        .export(&reference, Some(&Passphrase::new(PASSPHRASE)), &new)
        .unwrap();
    open_sealed_key(&exported, &Passphrase::new("an entirely new passphrase")).unwrap();
}

#[test]
fn non_exportable_keys_are_never_exported() {
    let provider = ServiceKeyProvider::new(MemoryStore::default());
    let reference = provider
        .generate("issuing", KeyAlgorithm::EcdsaP256, &SERVICE_NOT_EXPORTABLE)
        .unwrap();
    assert!(!provider.describe(&reference).unwrap().exportable);
    provider.open(&reference, None).unwrap();
    let result = provider.export(&reference, None, &new_passphrase(PASSPHRASE));
    assert_eq!(result.err(), Some(KeyError::NotExportable));
}

#[test]
fn service_key_files_are_not_restorable_as_backups() {
    let store = MemoryStore::default();
    let provider = ServiceKeyProvider::new(store.clone());
    provider
        .generate("issuing", KeyAlgorithm::EcdsaP256, &SERVICE)
        .unwrap();
    let clear = store.bytes("issuing");
    assert!(matches!(
        describe_sealed_key(&clear),
        Err(KeyError::Malformed(_))
    ));
}

#[test]
fn a_swapped_public_key_is_detected_on_open() {
    let store = MemoryStore::default();
    let provider = ServiceKeyProvider::new(store.clone());
    let reference = provider
        .generate("issuing", KeyAlgorithm::EcdsaP256, &SERVICE)
        .unwrap();
    // Record another key's public key in the header, as someone trying to
    // pass one key off as another might.
    let other = PrivateKey::generate(KeyAlgorithm::EcdsaP256).unwrap();
    let other = other.public_key().spki().to_vec();
    store.change("issuing", |bytes| {
        bytes[14..14 + other.len()].copy_from_slice(&other);
    });
    assert_eq!(
        provider.describe(&reference).unwrap().public_key.spki(),
        other.as_slice()
    );
    assert!(matches!(
        provider.open(&reference, None),
        Err(KeyError::Malformed(_))
    ));
}

#[test]
fn damaged_key_files_are_refused() {
    let store = MemoryStore::default();
    let provider = ServiceKeyProvider::new(store.clone());
    let reference = provider
        .generate("issuing", KeyAlgorithm::EcdsaP256, &SERVICE)
        .unwrap();
    let original = store.bytes("issuing");
    let damage: [(usize, u8); 5] = [(0, b'X'), (8, 2), (9, 9), (10, 3), (11, 0x02)];
    for (offset, value) in damage {
        store.change("issuing", |bytes| {
            bytes.clone_from(&original);
            bytes[offset] = value;
        });
        assert!(
            matches!(provider.describe(&reference), Err(KeyError::Malformed(_))),
            "byte {offset}"
        );
    }
    store.change("issuing", |bytes| bytes.truncate(20));
    assert!(matches!(
        provider.describe(&reference),
        Err(KeyError::Malformed(_))
    ));
}

#[test]
fn a_sealed_key_marked_not_exportable_is_refused() {
    let passphrase = new_passphrase(PASSPHRASE);
    let online = ServiceKeyProvider::new(MemoryStore::default());
    let reference = online
        .generate("issuing", KeyAlgorithm::EcdsaP256, &SERVICE)
        .unwrap();
    let mut backup = online.export(&reference, None, &passphrase).unwrap();
    backup[11] = 0x01;
    assert!(matches!(
        describe_sealed_key(&backup),
        Err(KeyError::Malformed(_))
    ));
}

#[test]
fn references_round_trip_as_text() {
    let reference: KeyReference = "file:/media/usb/root.key".parse().unwrap();
    assert_eq!(reference.provider(), "file");
    assert_eq!(reference.locator(), "/media/usb/root.key");
    assert_eq!(reference.to_string(), "file:/media/usb/root.key");
    for text in ["no-separator", ":locator", "File:x", "file:", "file:a\nb"] {
        assert!(
            matches!(
                text.parse::<KeyReference>(),
                Err(KeyError::InvalidReference(_))
            ),
            "{text:?}"
        );
    }
}

#[test]
fn providers_refuse_each_others_keys() {
    let online = ServiceKeyProvider::new(MemoryStore::default());
    let reference = KeyReference::new("file", "/media/usb/root.key").unwrap();
    assert!(matches!(
        online.describe(&reference),
        Err(KeyError::InvalidReference(_))
    ));
}

#[test]
fn key_providers_are_found_by_reference() {
    let mut providers = KeyProviders::new();
    providers.add(Box::new(KeyFileProvider::new())).unwrap();
    providers
        .add(Box::new(ServiceKeyProvider::new(MemoryStore::default())))
        .unwrap();
    assert!(matches!(
        providers.add(Box::new(KeyFileProvider::new())),
        Err(KeyError::AlreadyExists(_))
    ));

    let reference = providers
        .get("service")
        .unwrap()
        .generate("issuing", KeyAlgorithm::EcdsaP256, &SERVICE)
        .unwrap();
    let provider = providers.for_key(&reference).unwrap();
    assert_eq!(provider.name(), "service");
    provider.open(&reference, None).unwrap();

    let unknown = KeyReference::new("pkcs11", "slot-0").unwrap();
    assert!(matches!(
        providers.for_key(&unknown),
        Err(KeyError::InvalidReference(_))
    ));
}

#[test]
fn a_stored_key_signs_a_root_certificate() {
    let provider = ServiceKeyProvider::new(MemoryStore::default());
    let reference = provider
        .generate("root", KeyAlgorithm::Rsa4096, &SERVICE)
        .unwrap();
    let key = provider.open(&reference, None).unwrap();
    let profile = CaProfile {
        subject: CaSubject {
            common_name: "Test Root".into(),
            attributes: Vec::new(),
        },
        validity: Validity::new(
            datetime!(2026-01-01 0:00 UTC),
            datetime!(2036-01-01 0:00 UTC),
        )
        .unwrap(),
        path_length: Some(1),
        name_constraints: None,
        extended_key_usages: None,
        crl_distribution_points: Vec::new(),
    };
    let root = create_root(key.as_ref(), &profile, &SerialNumber::random().unwrap()).unwrap();
    IssuingCa::new(root.der(), key.as_ref()).unwrap();
}
