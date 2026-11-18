//! Key usages and extended key usages.

use std::fmt;

use crate::Error;

const ANY_EXTENDED_KEY_USAGE: &[u64] = &[2, 5, 29, 37, 0];
const OID_SERVER_AUTH: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 3, 1];
const OID_CLIENT_AUTH: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 3, 2];
const OID_CODE_SIGNING: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 3, 3];
const OID_EMAIL_PROTECTION: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 3, 4];
const OID_TIME_STAMPING: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 3, 8];
const OID_OCSP_SIGNING: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 3, 9];

/// An object identifier for an extended key usage other than Any Purpose.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UsageOid(Vec<u64>);

impl UsageOid {
    /// Parses dotted decimal, refusing Any Purpose (`2.5.29.37.0`), which
    /// would let a certificate act for every use.
    pub fn new(dotted: &str) -> Result<Self, Error> {
        let arcs: Option<Vec<u64>> = dotted.split('.').map(|arc| arc.parse().ok()).collect();
        let arcs = arcs
            .filter(|arcs| arcs.len() >= 2)
            .ok_or_else(|| Error::InvalidValue(format!("{dotted:?} is not an OID")))?;
        Self::from_arcs(arcs)
    }

    pub(crate) fn from_arcs(arcs: Vec<u64>) -> Result<Self, Error> {
        if arcs == ANY_EXTENDED_KEY_USAGE {
            return Err(Error::InvalidValue(
                "the Any Purpose usage is not allowed".into(),
            ));
        }
        Ok(Self(arcs))
    }

    pub fn arcs(&self) -> &[u64] {
        &self.0
    }
}

impl fmt::Display for UsageOid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let arcs: Vec<String> = self.0.iter().map(u64::to_string).collect();
        formatter.write_str(&arcs.join("."))
    }
}

/// A purpose a certificate's key may be used for.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ExtendedKeyUsage {
    ServerAuth,
    ClientAuth,
    CodeSigning,
    EmailProtection,
    TimeStamping,
    OcspSigning,
    Other(UsageOid),
}

impl ExtendedKeyUsage {
    /// The usage's object identifier.
    pub fn oid(&self) -> UsageOid {
        let arcs = match self {
            Self::ServerAuth => OID_SERVER_AUTH,
            Self::ClientAuth => OID_CLIENT_AUTH,
            Self::CodeSigning => OID_CODE_SIGNING,
            Self::EmailProtection => OID_EMAIL_PROTECTION,
            Self::TimeStamping => OID_TIME_STAMPING,
            Self::OcspSigning => OID_OCSP_SIGNING,
            Self::Other(oid) => return oid.clone(),
        };
        UsageOid(arcs.to_vec())
    }

    fn to_rcgen(&self) -> rcgen::ExtendedKeyUsagePurpose {
        match self {
            Self::ServerAuth => rcgen::ExtendedKeyUsagePurpose::ServerAuth,
            Self::ClientAuth => rcgen::ExtendedKeyUsagePurpose::ClientAuth,
            Self::CodeSigning => rcgen::ExtendedKeyUsagePurpose::CodeSigning,
            Self::EmailProtection => rcgen::ExtendedKeyUsagePurpose::EmailProtection,
            Self::TimeStamping => rcgen::ExtendedKeyUsagePurpose::TimeStamping,
            Self::OcspSigning => rcgen::ExtendedKeyUsagePurpose::OcspSigning,
            Self::Other(oid) => rcgen::ExtendedKeyUsagePurpose::Other(oid.arcs().to_vec()),
        }
    }
}

/// A non-empty set of extended key usages.
///
/// Certificates always state their purposes explicitly. An empty set would
/// mean "any purpose" to most verifiers, so it cannot be constructed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedKeyUsages(Vec<ExtendedKeyUsage>);

impl ExtendedKeyUsages {
    pub fn new(mut usages: Vec<ExtendedKeyUsage>) -> Result<Self, Error> {
        usages.sort();
        usages.dedup();
        if usages.is_empty() {
            return Err(Error::InvalidValue(
                "at least one extended key usage is required".into(),
            ));
        }
        Ok(Self(usages))
    }

    pub fn iter(&self) -> impl Iterator<Item = &ExtendedKeyUsage> {
        self.0.iter()
    }

    /// Whether every usage here is permitted by `allowed`, compared by OID.
    pub(crate) fn within(&self, allowed: &[UsageOid]) -> bool {
        self.0.iter().all(|usage| allowed.contains(&usage.oid()))
    }

    pub(crate) fn to_rcgen(&self) -> Vec<rcgen::ExtendedKeyUsagePurpose> {
        self.0.iter().map(ExtendedKeyUsage::to_rcgen).collect()
    }
}

/// A key usage an end-entity certificate may assert.
///
/// Certificate and CRL signing are reserved for CA certificates, so they
/// cannot be expressed here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyUsage {
    DigitalSignature,
    ContentCommitment,
    KeyEncipherment,
    DataEncipherment,
    KeyAgreement,
}

impl KeyUsage {
    pub(crate) fn to_rcgen(self) -> rcgen::KeyUsagePurpose {
        match self {
            Self::DigitalSignature => rcgen::KeyUsagePurpose::DigitalSignature,
            Self::ContentCommitment => rcgen::KeyUsagePurpose::ContentCommitment,
            Self::KeyEncipherment => rcgen::KeyUsagePurpose::KeyEncipherment,
            Self::DataEncipherment => rcgen::KeyUsagePurpose::DataEncipherment,
            Self::KeyAgreement => rcgen::KeyUsagePurpose::KeyAgreement,
        }
    }
}
