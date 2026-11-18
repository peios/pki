//! Everything needed to build a certificate, as decided by policy.

use ring::rand::{SecureRandom, SystemRandom};
use time::OffsetDateTime;

use crate::names::{AltName, NameConstraints, Sid, SubjectAttribute};
use crate::usage::{ExtendedKeyUsages, KeyUsage};
use crate::Error;

/// The period during which a certificate is valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Validity {
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
}

impl Validity {
    pub fn new(not_before: OffsetDateTime, not_after: OffsetDateTime) -> Result<Self, Error> {
        if not_after <= not_before {
            return Err(Error::InvalidValue(
                "validity must end after it begins".into(),
            ));
        }
        Ok(Self {
            not_before,
            not_after,
        })
    }

    pub fn not_before(&self) -> OffsetDateTime {
        self.not_before
    }

    pub fn not_after(&self) -> OffsetDateTime {
        self.not_after
    }

    pub(crate) fn within(&self, outer: &Validity) -> bool {
        self.not_before >= outer.not_before && self.not_after <= outer.not_after
    }
}

/// Bytes in a generated serial number: 127 random bits, above the 64-bit
/// minimum the CA/Browser Forum requires, within the 20-octet maximum.
const SERIAL_LEN: usize = 16;
const MAX_SERIAL_LEN: usize = 20;

/// A certificate or CRL serial number, as the positive big-endian integer
/// encoded in the certificate.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SerialNumber(Vec<u8>);

impl SerialNumber {
    /// Generates an unpredictable serial number.
    pub fn random() -> Result<Self, Error> {
        let mut bytes = [0; SERIAL_LEN];
        let random = SystemRandom::new();
        // Clearing the top bit keeps the integer positive; a non-zero first
        // byte keeps its DER encoding exactly these bytes.
        loop {
            random
                .fill(&mut bytes)
                .map_err(|_| Error::Signing("no randomness for a serial number".into()))?;
            bytes[0] &= 0x7f;
            if bytes[0] != 0 {
                return Ok(Self(bytes.to_vec()));
            }
        }
    }

    /// Accepts the minimal big-endian encoding of a positive integer of at
    /// most 20 octets, as stored from an issued certificate.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let invalid = || Error::InvalidValue("not a valid certificate serial number".into());
        let (first, rest) = bytes.split_first().ok_or_else(invalid)?;
        let minimal = *first != 0 || rest.first().is_some_and(|byte| byte & 0x80 != 0);
        if bytes.len() > MAX_SERIAL_LEN || !minimal || first & 0x80 != 0 {
            return Err(invalid());
        }
        Ok(Self(bytes.to_vec()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub(crate) fn to_rcgen(&self) -> rcgen::SerialNumber {
        rcgen::SerialNumber::from_slice(&self.0)
    }
}

/// The upper bound X.520 sets on a common name.
const MAX_COMMON_NAME_LEN: usize = 64;

/// A human-readable name, such as a person's display name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DisplayName(String);

impl DisplayName {
    /// Accepts 1 to 64 characters with no control characters and no
    /// surrounding whitespace.
    pub fn new(name: &str) -> Result<Self, Error> {
        let length = name.chars().count();
        if length == 0 || length > MAX_COMMON_NAME_LEN {
            return Err(Error::InvalidValue(format!(
                "display name {name:?} has an invalid length"
            )));
        }
        if name.trim() != name || name.chars().any(char::is_control) {
            return Err(Error::InvalidValue(format!(
                "display name {name:?} is not plain text"
            )));
        }
        Ok(Self(name.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The common name of an end-entity certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommonName {
    /// One of the certificate's alternative names, repeated.
    Name(AltName),
    /// A display name for the certificate's owner.
    ///
    /// Policy must take this from trusted identity data, such as the owner's
    /// account, and never from a request: a requester-chosen display name is
    /// how forged identities reach software that trusts the common name.
    DisplayName(DisplayName),
}

/// The subject of an end-entity certificate.
///
/// Attributes other than the common name come from the template, never from
/// a request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LeafSubject {
    pub common_name: Option<CommonName>,
    pub attributes: Vec<SubjectAttribute>,
}

/// Everything about an end-entity certificate except its key, issuer and
/// serial number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafProfile {
    pub subject: LeafSubject,
    pub alt_names: Vec<AltName>,
    pub key_usages: Vec<KeyUsage>,
    pub extended_key_usages: ExtendedKeyUsages,
    pub validity: Validity,
    /// The principal the certificate is bound to, carried in Microsoft's
    /// SID security extension when present.
    pub owner_sid: Option<Sid>,
    pub crl_distribution_points: Vec<String>,
}

/// The subject of a CA certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaSubject {
    pub common_name: String,
    pub attributes: Vec<SubjectAttribute>,
}

/// Everything about a CA certificate except its key, issuer and serial
/// number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaProfile {
    pub subject: CaSubject,
    pub validity: Validity,
    /// How many further CA levels may sit below this CA. `None` leaves the
    /// depth unlimited.
    pub path_length: Option<u8>,
    pub name_constraints: Option<NameConstraints>,
    /// The only extended key usages certificates below this CA may carry.
    /// `None` leaves them unconstrained.
    pub extended_key_usages: Option<ExtendedKeyUsages>,
    pub crl_distribution_points: Vec<String>,
}
