//! Key algorithms, subject public keys, signers and in-memory software keys.

use std::cell::RefCell;

use ring::rand::SystemRandom;
use ring::signature::{
    EcdsaKeyPair, KeyPair, RsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING,
    ECDSA_P384_SHA384_ASN1_SIGNING, RSA_PKCS1_SHA256,
};
use x509_parser::prelude::FromDer;
use x509_parser::public_key::PublicKey;
use x509_parser::x509::SubjectPublicKeyInfo;
use zeroize::Zeroizing;

use crate::Error;

const OID_RSA_ENCRYPTION: &[u64] = &[1, 2, 840, 113549, 1, 1, 1];
const OID_EC_PUBLIC_KEY: &[u64] = &[1, 2, 840, 10045, 2, 1];
const OID_CURVE_P256: &[u64] = &[1, 2, 840, 10045, 3, 1, 7];
const OID_CURVE_P384: &[u64] = &[1, 3, 132, 0, 34];

/// The smallest RSA modulus the CA accepts.
pub const MIN_RSA_MODULUS_BITS: u32 = 2048;
/// The largest RSA modulus the CA accepts; larger keys only cost verifiers time.
pub const MAX_RSA_MODULUS_BITS: u32 = 16384;

/// An elliptic curve for ECDSA keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EcdsaCurve {
    P256,
    P384,
}

/// The size of an RSA modulus, within the accepted range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RsaModulusBits(u32);

impl RsaModulusBits {
    /// Accepts sizes from [`MIN_RSA_MODULUS_BITS`] to [`MAX_RSA_MODULUS_BITS`].
    pub fn new(bits: u32) -> Result<Self, Error> {
        if !(MIN_RSA_MODULUS_BITS..=MAX_RSA_MODULUS_BITS).contains(&bits) {
            return Err(Error::UnsupportedKey(format!(
                "an RSA modulus of {bits} bits is outside {MIN_RSA_MODULUS_BITS} to \
                 {MAX_RSA_MODULUS_BITS} bits"
            )));
        }
        Ok(Self(bits))
    }

    pub fn bits(self) -> u32 {
        self.0
    }
}

/// The algorithm of a public or private key.
///
/// The algorithm also fixes how a CA key signs: ECDSA P-256 with SHA-256,
/// ECDSA P-384 with SHA-384, and RSA with PKCS #1 v1.5 and SHA-256, which
/// every client the CA serves can verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyAlgorithm {
    Ecdsa(EcdsaCurve),
    Rsa(RsaModulusBits),
}

impl KeyAlgorithm {
    pub(crate) fn signature_algorithm(self) -> &'static rcgen::SignatureAlgorithm {
        match self {
            Self::Ecdsa(EcdsaCurve::P256) => &rcgen::PKCS_ECDSA_P256_SHA256,
            Self::Ecdsa(EcdsaCurve::P384) => &rcgen::PKCS_ECDSA_P384_SHA384,
            Self::Rsa(_) => &rcgen::PKCS_RSA_SHA256,
        }
    }
}

/// A validated X.509 SubjectPublicKeyInfo with a supported algorithm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectPublicKey {
    spki_der: Vec<u8>,
    key_bits: Vec<u8>,
    algorithm: KeyAlgorithm,
}

impl SubjectPublicKey {
    /// Parses a DER SubjectPublicKeyInfo, refusing unsupported algorithms,
    /// curves and RSA sizes.
    pub fn from_der(spki_der: &[u8]) -> Result<Self, Error> {
        let (remainder, spki) = SubjectPublicKeyInfo::from_der(spki_der)
            .map_err(|error| Error::UnsupportedKey(format!("unparseable public key: {error}")))?;
        if !remainder.is_empty() {
            return Err(Error::UnsupportedKey(
                "trailing bytes after the public key".into(),
            ));
        }
        let algorithm = classify(&spki)?;
        Ok(Self {
            spki_der: spki_der.to_vec(),
            key_bits: spki.subject_public_key.data.to_vec(),
            algorithm,
        })
    }

    pub fn algorithm(&self) -> KeyAlgorithm {
        self.algorithm
    }

    /// The DER SubjectPublicKeyInfo.
    pub fn der(&self) -> &[u8] {
        &self.spki_der
    }
}

fn classify(spki: &SubjectPublicKeyInfo<'_>) -> Result<KeyAlgorithm, Error> {
    let oid = oid_arcs(&spki.algorithm.algorithm)?;
    if oid == OID_RSA_ENCRYPTION {
        let Ok(PublicKey::RSA(rsa)) = spki.parsed() else {
            return Err(Error::UnsupportedKey("malformed RSA public key".into()));
        };
        let bits = u32::try_from(rsa.key_size())
            .map_err(|_| Error::UnsupportedKey("RSA modulus is too large".into()))?;
        return Ok(KeyAlgorithm::Rsa(RsaModulusBits::new(bits)?));
    }
    if oid == OID_EC_PUBLIC_KEY {
        let curve = spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|parameters| parameters.as_oid().ok())
            .ok_or_else(|| Error::UnsupportedKey("EC key without a named curve".into()))?;
        let curve = oid_arcs(&curve)?;
        if curve == OID_CURVE_P256 {
            return Ok(KeyAlgorithm::Ecdsa(EcdsaCurve::P256));
        }
        if curve == OID_CURVE_P384 {
            return Ok(KeyAlgorithm::Ecdsa(EcdsaCurve::P384));
        }
        return Err(Error::UnsupportedKey(
            "EC keys must use P-256 or P-384".into(),
        ));
    }
    Err(Error::UnsupportedKey(
        "only ECDSA and RSA keys are supported".into(),
    ))
}

pub(crate) fn oid_arcs(oid: &x509_parser::oid_registry::Oid<'_>) -> Result<Vec<u64>, Error> {
    oid.iter()
        .map(|arcs| arcs.collect())
        .ok_or_else(|| Error::UnsupportedKey(format!("object identifier {oid} is too large")))
}

impl rcgen::PublicKeyData for SubjectPublicKey {
    fn der_bytes(&self) -> &[u8] {
        &self.key_bits
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        self.algorithm.signature_algorithm()
    }
}

/// Signs certificates and CRLs on behalf of a CA.
///
/// Key storage providers implement this. A signer may keep its private key
/// anywhere, including hardware that never releases it.
pub trait Signer {
    /// The public half of the signing key.
    fn public_key(&self) -> &SubjectPublicKey;

    /// Signs `message` with the algorithm fixed by the key's
    /// [`KeyAlgorithm`]. ECDSA signatures must be DER `Ecdsa-Sig-Value`
    /// structures and RSA signatures PKCS #1 v1.5, as X.509 requires.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error>;
}

/// Adapts a [`Signer`] to rcgen's signing interface.
///
/// rcgen reports every signer failure as a bare `RemoteKeyError`, so the
/// adapter keeps the signer's own error for [`RcgenSigner::error`].
pub(crate) struct RcgenSigner<'a> {
    signer: &'a dyn Signer,
    failure: RefCell<Option<Error>>,
}

impl<'a> RcgenSigner<'a> {
    pub(crate) fn new(signer: &'a dyn Signer) -> Self {
        Self {
            signer,
            failure: RefCell::new(None),
        }
    }

    /// Translates an rcgen error, restoring the signer's error if signing
    /// was what failed.
    pub(crate) fn error(&self, error: rcgen::Error) -> Error {
        match (error, self.failure.borrow_mut().take()) {
            (rcgen::Error::RemoteKeyError, Some(failure)) => failure,
            (error, _) => error.into(),
        }
    }
}

impl rcgen::PublicKeyData for RcgenSigner<'_> {
    fn der_bytes(&self) -> &[u8] {
        rcgen::PublicKeyData::der_bytes(self.signer.public_key())
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        rcgen::PublicKeyData::algorithm(self.signer.public_key())
    }
}

impl rcgen::SigningKey for RcgenSigner<'_> {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        self.signer.sign(message).map_err(|error| {
            *self.failure.borrow_mut() = Some(error);
            rcgen::Error::RemoteKeyError
        })
    }
}

/// A private key held in process memory, loaded from or exported as PKCS #8.
///
/// Key storage providers that keep keys in software build on this type. The
/// PKCS #8 bytes are wiped from memory when the key is dropped.
pub struct SoftwareKey {
    pkcs8: Zeroizing<Vec<u8>>,
    pair: SoftwarePair,
    public_key: SubjectPublicKey,
    random: SystemRandom,
}

enum SoftwarePair {
    Ecdsa(EcdsaKeyPair),
    Rsa(RsaKeyPair),
}

impl SoftwareKey {
    /// Generates a new ECDSA key.
    ///
    /// RSA generation is left to key storage providers, because `ring` can
    /// only load RSA keys.
    pub fn generate_ecdsa(curve: EcdsaCurve) -> Result<Self, Error> {
        let random = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(ecdsa_signing(curve), &random)
            .map_err(|_| Error::Signing("ECDSA key generation failed".into()))?;
        Self::from_pkcs8(pkcs8.as_ref())
    }

    /// Loads an ECDSA P-256, ECDSA P-384 or RSA private key from PKCS #8 DER.
    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self, Error> {
        let random = SystemRandom::new();
        let pkcs8 = Zeroizing::new(pkcs8.to_vec());
        for curve in [EcdsaCurve::P256, EcdsaCurve::P384] {
            if let Ok(pair) = EcdsaKeyPair::from_pkcs8(ecdsa_signing(curve), &pkcs8, &random) {
                let spki = ecdsa_spki(curve, pair.public_key().as_ref());
                return Ok(Self {
                    public_key: SubjectPublicKey::from_der(&spki)?,
                    pkcs8,
                    pair: SoftwarePair::Ecdsa(pair),
                    random,
                });
            }
        }
        let pair = RsaKeyPair::from_pkcs8(&pkcs8).map_err(|error| {
            Error::UnsupportedKey(format!("not an ECDSA P-256, P-384 or RSA key: {error}"))
        })?;
        let spki = rsa_spki(pair.public().as_ref());
        Ok(Self {
            public_key: SubjectPublicKey::from_der(&spki)?,
            pkcs8,
            pair: SoftwarePair::Rsa(pair),
            random,
        })
    }

    /// The private key as PKCS #8 DER.
    pub fn pkcs8(&self) -> &[u8] {
        &self.pkcs8
    }
}

impl Signer for SoftwareKey {
    fn public_key(&self) -> &SubjectPublicKey {
        &self.public_key
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        match &self.pair {
            SoftwarePair::Ecdsa(pair) => pair
                .sign(&self.random, message)
                .map(|signature| signature.as_ref().to_vec())
                .map_err(|_| Error::Signing("ECDSA signing failed".into())),
            SoftwarePair::Rsa(pair) => {
                let mut signature = vec![0; pair.public().modulus_len()];
                pair.sign(&RSA_PKCS1_SHA256, &self.random, message, &mut signature)
                    .map_err(|_| Error::Signing("RSA signing failed".into()))?;
                Ok(signature)
            }
        }
    }
}

fn ecdsa_signing(curve: EcdsaCurve) -> &'static ring::signature::EcdsaSigningAlgorithm {
    match curve {
        EcdsaCurve::P256 => &ECDSA_P256_SHA256_ASN1_SIGNING,
        EcdsaCurve::P384 => &ECDSA_P384_SHA384_ASN1_SIGNING,
    }
}

fn ecdsa_spki(curve: EcdsaCurve, point: &[u8]) -> Vec<u8> {
    let curve = match curve {
        EcdsaCurve::P256 => OID_CURVE_P256,
        EcdsaCurve::P384 => OID_CURVE_P384,
    };
    yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_sequence(|writer| {
                writer
                    .next()
                    .write_oid(&yasna::models::ObjectIdentifier::from_slice(
                        OID_EC_PUBLIC_KEY,
                    ));
                writer
                    .next()
                    .write_oid(&yasna::models::ObjectIdentifier::from_slice(curve));
            });
            writer.next().write_bitvec_bytes(point, point.len() * 8);
        });
    })
}

fn rsa_spki(rsa_public_key: &[u8]) -> Vec<u8> {
    yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_sequence(|writer| {
                writer
                    .next()
                    .write_oid(&yasna::models::ObjectIdentifier::from_slice(
                        OID_RSA_ENCRYPTION,
                    ));
                writer.next().write_null();
            });
            writer
                .next()
                .write_bitvec_bytes(rsa_public_key, rsa_public_key.len() * 8);
        });
    })
}
