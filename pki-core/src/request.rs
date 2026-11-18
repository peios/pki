//! Certificate signing requests.

use std::net::IpAddr;

use x509_parser::certification_request::X509CertificationRequest;
use x509_parser::der_parser::der::parse_der_utf8string;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::FromDer;

use crate::key::{oid_arcs, SubjectPublicKey};
use crate::names::{AltName, DnsName, Mailbox, UserPrincipalName};
use crate::Error;

const PEM_LABEL: &str = "CERTIFICATE REQUEST";
const NEW_PEM_LABEL: &str = "NEW CERTIFICATE REQUEST";
pub(crate) const OID_USER_PRINCIPAL_NAME: &[u64] = &[1, 3, 6, 1, 4, 1, 311, 20, 2, 3];

/// A verified PKCS #10 certificate signing request.
///
/// Only the public key and the requested names are kept. Every other
/// attribute and extension a request carries is ignored: the CA builds
/// certificates from templates, never from what a requester asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateRequest {
    subject_key: SubjectPublicKey,
    names: Vec<AltName>,
}

impl CertificateRequest {
    /// Parses a DER request and verifies its signature, which proves the
    /// requester holds the private key.
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let (remainder, request) = X509CertificationRequest::from_der(der)
            .map_err(|error| Error::MalformedRequest(error.to_string()))?;
        if !remainder.is_empty() {
            return Err(Error::MalformedRequest(
                "trailing bytes after the request".into(),
            ));
        }
        request
            .verify_signature()
            .map_err(|_| Error::InvalidRequestSignature)?;
        let info = &request.certification_request_info;
        let subject_key = SubjectPublicKey::from_der(info.subject_pki.raw)?;

        let mut names = Vec::new();
        for extension in request.requested_extensions().into_iter().flatten() {
            if let ParsedExtension::SubjectAlternativeName(alternatives) = extension {
                for name in &alternatives.general_names {
                    push_unique(&mut names, alt_name(name)?);
                }
            }
        }
        let mut common_names = info.subject.iter_common_name();
        if let Some(common_name) = common_names.next() {
            if common_names.next().is_some() {
                return Err(Error::MalformedRequest("more than one common name".into()));
            }
            let common_name = common_name
                .as_str()
                .map_err(|_| Error::MalformedRequest("unreadable common name".into()))?;
            let common_name = common_name_as_alt_name(common_name, &names)?;
            push_unique(&mut names, common_name);
        }
        if names.is_empty() {
            return Err(Error::MalformedRequest("the request names nothing".into()));
        }
        Ok(Self { subject_key, names })
    }

    /// Parses a PEM request, with either the current or the legacy label.
    pub fn from_pem(text: &str) -> Result<Self, Error> {
        let block = pem::parse(text).map_err(|error| Error::MalformedRequest(error.to_string()))?;
        if block.tag() != PEM_LABEL && block.tag() != NEW_PEM_LABEL {
            return Err(Error::MalformedRequest(format!(
                "unexpected PEM label {}",
                block.tag()
            )));
        }
        Self::from_der(block.contents())
    }

    pub fn subject_key(&self) -> &SubjectPublicKey {
        &self.subject_key
    }

    /// Every name requested, from the alternative names and the common
    /// name, without duplicates. Policy must approve each before issuing.
    pub fn names(&self) -> &[AltName] {
        &self.names
    }
}

fn push_unique(names: &mut Vec<AltName>, name: AltName) {
    if !names.contains(&name) {
        names.push(name);
    }
}

fn alt_name(name: &GeneralName<'_>) -> Result<AltName, Error> {
    match name {
        GeneralName::DNSName(name) => Ok(AltName::Dns(DnsName::new(name)?)),
        GeneralName::RFC822Name(address) => Ok(AltName::Email(Mailbox::new(address)?)),
        GeneralName::IPAddress(bytes) => ip_address(bytes).map(AltName::Ip),
        GeneralName::OtherName(oid, value) if oid_arcs(oid)? == OID_USER_PRINCIPAL_NAME => {
            let upn = upn_value(value)?;
            Ok(AltName::Upn(UserPrincipalName::new(&upn)?))
        }
        other => Err(Error::UnsupportedName(format!("{other}"))),
    }
}

fn ip_address(bytes: &[u8]) -> Result<IpAddr, Error> {
    if let Ok(octets) = <[u8; 4]>::try_from(bytes) {
        return Ok(IpAddr::from(octets));
    }
    if let Ok(octets) = <[u8; 16]>::try_from(bytes) {
        return Ok(IpAddr::from(octets));
    }
    Err(Error::MalformedRequest(
        "an IP address of the wrong length".into(),
    ))
}

/// Decodes the `[0] EXPLICIT UTF8String` value of a UPN other-name.
fn upn_value(value: &[u8]) -> Result<String, Error> {
    let malformed = || Error::MalformedRequest("malformed user principal name".into());
    let (_, tagged) = x509_parser::der_parser::der::parse_der(value).map_err(|_| malformed())?;
    let inner = tagged.as_slice().map_err(|_| malformed())?;
    let (_, text) = parse_der_utf8string(inner).map_err(|_| malformed())?;
    text.as_str().map(str::to_owned).map_err(|_| malformed())
}

/// A common name is a name like any other: it either repeats a requested
/// alternative name or must itself be a valid DNS name.
fn common_name_as_alt_name(common_name: &str, names: &[AltName]) -> Result<AltName, Error> {
    if let Some(existing) = names.iter().find(|name| name.to_string() == common_name) {
        return Ok(existing.clone());
    }
    DnsName::new(common_name).map(AltName::Dns).map_err(|_| {
        Error::UnsupportedName(format!(
            "common name {common_name:?} is neither a requested alternative name nor a DNS name"
        ))
    })
}
