//! Key algorithms, subject public keys and the adapter that lets a
//! peios-crypto [`Signer`] sign through rcgen.

use std::cell::RefCell;

use peios_crypto::{SignatureScheme, Signer, VerifyingKey};
use x509_parser::prelude::FromDer;
use x509_parser::public_key::PublicKey;
use x509_parser::x509::SubjectPublicKeyInfo;

use crate::Error;

const OID_RSA_ENCRYPTION: &[u64] = &[1, 2, 840, 113549, 1, 1, 1];
const OID_EC_PUBLIC_KEY: &[u64] = &[1, 2, 840, 10045, 2, 1];
const OID_CURVE_P256: &[u64] = &[1, 2, 840, 10045, 3, 1, 7];
const OID_CURVE_P384: &[u64] = &[1, 3, 132, 0, 34];

/// The smallest RSA modulus the CA accepts.
pub const MIN_RSA_MODULUS_BITS: u32 = peios_crypto::MIN_RSA_MODULUS_BITS as u32;
/// The largest RSA modulus the CA accepts: the largest whose signatures
/// peios-crypto verifies, since a request must prove possession of its key.
pub const MAX_RSA_MODULUS_BITS: u32 = peios_crypto::MAX_RSA_MODULUS_BITS as u32;

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

    /// The peios-crypto scheme matching [`Self::signature_algorithm`].
    pub(crate) fn signature_scheme(self) -> SignatureScheme {
        match self {
            Self::Ecdsa(EcdsaCurve::P256) => SignatureScheme::EcdsaSha256,
            Self::Ecdsa(EcdsaCurve::P384) => SignatureScheme::EcdsaSha384,
            Self::Rsa(_) => SignatureScheme::RsaPkcs1Sha256,
        }
    }
}

/// A validated X.509 SubjectPublicKeyInfo with a supported algorithm.
///
/// The key is held in its canonical encoding, so a certificate always
/// carries an EC point uncompressed, however the request encoded it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectPublicKey {
    key: VerifyingKey,
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
        let key = VerifyingKey::from_spki(spki_der)
            .map_err(|error| Error::UnsupportedKey(format!("unusable public key: {error}")))?;
        let (_, canonical) = SubjectPublicKeyInfo::from_der(key.spki())
            .map_err(|error| Error::UnsupportedKey(format!("unparseable public key: {error}")))?;
        let key_bits = canonical.subject_public_key.data.to_vec();
        Ok(Self {
            key,
            key_bits,
            algorithm,
        })
    }

    pub fn algorithm(&self) -> KeyAlgorithm {
        self.algorithm
    }

    /// The DER SubjectPublicKeyInfo, in its canonical encoding.
    pub fn der(&self) -> &[u8] {
        self.key.spki()
    }

    pub(crate) fn verifying_key(&self) -> &VerifyingKey {
        &self.key
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

/// Adapts a peios-crypto [`Signer`] to rcgen's signing interface.
///
/// The CA key signs with the scheme its [`KeyAlgorithm`] fixes. rcgen
/// reports every signer failure as a bare `RemoteKeyError`, so the adapter
/// keeps the signer's own error for [`RcgenSigner::error`].
pub(crate) struct RcgenSigner<'a> {
    signer: &'a dyn Signer,
    public_key: SubjectPublicKey,
    failure: RefCell<Option<Error>>,
}

impl<'a> RcgenSigner<'a> {
    pub(crate) fn new(signer: &'a dyn Signer) -> Result<Self, Error> {
        Ok(Self {
            signer,
            public_key: SubjectPublicKey::from_der(signer.public_key().spki())?,
            failure: RefCell::new(None),
        })
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
        rcgen::PublicKeyData::der_bytes(&self.public_key)
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        rcgen::PublicKeyData::algorithm(&self.public_key)
    }
}

impl rcgen::SigningKey for RcgenSigner<'_> {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        let scheme = self.public_key.algorithm().signature_scheme();
        self.signer.sign(scheme, message).map_err(|error| {
            *self.failure.borrow_mut() = Some(Error::Crypto(error));
            rcgen::Error::RemoteKeyError
        })
    }
}
