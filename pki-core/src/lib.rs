//! Portable certificate authority core for Peios PKI.
//!
//! This crate has no Registry, token or operating-system dependencies. The
//! native `pkid` daemon supplies policy decisions, key storage and persistence.
//!
//! Every certificate is built from a profile that policy has already
//! approved. Requests contribute only a public key and names for policy to
//! check ([`CertificateRequest`]). An [`IssuingCa`] refuses anything that
//! would break its own certificate's validity, path length, name or usage
//! constraints, and CA certificates can only be made by [`create_root`] and
//! [`IssuingCa::issue_ca`], never through ordinary issuance.

mod ca;
mod crl;
mod error;
mod extensions;
mod key;
mod names;
mod profile;
mod request;
mod usage;

pub use ca::{ca_request, create_root, leaf_request, Certificate, IssuingCa};
pub use crl::{CrlProfile, RevocationList, RevocationReason, RevokedCertificate};
pub use error::Error;
pub use key::{
    EcdsaCurve, KeyAlgorithm, RsaModulusBits, SubjectPublicKey, MAX_RSA_MODULUS_BITS,
    MIN_RSA_MODULUS_BITS,
};
pub use names::{
    AltName, DnsName, Mailbox, NameConstraints, NameSubtree, Sid, SubjectAttribute,
    SubjectAttributeKind, UserPrincipalName,
};
pub use profile::{
    CaProfile, CaSubject, CommonName, DisplayName, LeafProfile, LeafSubject, SerialNumber, Validity,
};
pub use request::{ca_request_key, CertificateRequest};
pub use usage::{ExtendedKeyUsage, ExtendedKeyUsages, KeyUsage, UsageOid};
