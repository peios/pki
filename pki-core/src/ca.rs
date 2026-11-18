//! Creating roots and issuing certificates from a CA.

use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::FromDer;

use crate::extensions::sid_extension;
use crate::key::{oid_arcs, RcgenSigner, Signer, SubjectPublicKey};
use crate::names::{AltName, DnsName, NameConstraints, NameSubtree};
use crate::profile::{CaProfile, CaSubject, CommonName, LeafProfile, SerialNumber, Validity};
use crate::request::OID_USER_PRINCIPAL_NAME;
use crate::usage::UsageOid;
use crate::Error;

const PEM_LABEL: &str = "CERTIFICATE";

/// A DER-encoded X.509 certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    der: Vec<u8>,
}

impl Certificate {
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    pub fn pem(&self) -> String {
        pem::encode(&pem::Pem::new(PEM_LABEL, self.der.clone()))
    }
}

/// Creates a self-signed root CA certificate for `signer`'s key.
pub fn create_root(
    signer: &dyn Signer,
    profile: &CaProfile,
    serial: &SerialNumber,
) -> Result<Certificate, Error> {
    let params = ca_params(profile, serial)?;
    let signer = RcgenSigner::new(signer);
    let certificate = params
        .self_signed(&signer)
        .map_err(|error| signer.error(error))?;
    Ok(Certificate {
        der: certificate.der().to_vec(),
    })
}

/// A CA certificate together with the signer for its key.
pub struct IssuingCa<'a> {
    certificate: Vec<u8>,
    signer: &'a dyn Signer,
    facts: IssuerFacts,
}

/// What an issuing CA's own certificate permits.
struct IssuerFacts {
    validity: Validity,
    path_length: Option<u32>,
    name_constraints: Option<NameConstraints>,
    extended_key_usages: Option<Vec<UsageOid>>,
    key_identifier: Vec<u8>,
}

impl<'a> IssuingCa<'a> {
    /// Accepts a CA certificate whose key is `signer`'s and which may sign
    /// certificates and CRLs.
    pub fn new(certificate_der: &[u8], signer: &'a dyn Signer) -> Result<Self, Error> {
        let (remainder, certificate) = X509Certificate::from_der(certificate_der)
            .map_err(|error| Error::InvalidIssuer(error.to_string()))?;
        if !remainder.is_empty() {
            return Err(Error::InvalidIssuer(
                "trailing bytes after the certificate".into(),
            ));
        }
        if certificate.public_key().raw != signer.public_key().der() {
            return Err(Error::InvalidIssuer(
                "the signer's key is not the certificate's".into(),
            ));
        }
        let facts = issuer_facts(&certificate)?;
        Ok(Self {
            certificate: certificate_der.to_vec(),
            signer,
            facts,
        })
    }

    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate
    }

    /// Issues an end-entity certificate for `subject_key`.
    ///
    /// The certificate is built only from `profile`. It is refused if it
    /// would outlive the CA or break the CA's name or usage constraints.
    pub fn issue(
        &self,
        subject_key: &SubjectPublicKey,
        profile: &LeafProfile,
        serial: &SerialNumber,
    ) -> Result<Certificate, Error> {
        self.check_validity(&profile.validity)?;
        if profile.alt_names.is_empty() {
            return Err(Error::InvalidValue(
                "a certificate must name its subject".into(),
            ));
        }
        if let Some(CommonName::Name(common_name)) = &profile.subject.common_name {
            if !profile.alt_names.contains(common_name) {
                return Err(Error::InvalidValue(format!(
                    "common name {common_name} is not one of the certificate's names"
                )));
            }
        }
        if let Some(constraints) = &self.facts.name_constraints {
            for name in &profile.alt_names {
                constraints.check(name)?;
            }
        }
        if let Some(allowed) = &self.facts.extended_key_usages {
            if !profile.extended_key_usages.within(allowed) {
                return Err(Error::ConstraintViolation(
                    "an extended key usage the issuing CA does not permit".into(),
                ));
            }
        }
        let params = leaf_params(profile, serial);
        self.sign(params, subject_key)
    }

    /// Issues a subordinate CA certificate for `subject_key`.
    ///
    /// This is the only way to create a CA certificate below a root, so it
    /// must stay separate from ordinary enrolment.
    pub fn issue_ca(
        &self,
        subject_key: &SubjectPublicKey,
        profile: &CaProfile,
        serial: &SerialNumber,
    ) -> Result<Certificate, Error> {
        self.check_validity(&profile.validity)?;
        if let Some(limit) = self.facts.path_length {
            let Some(requested) = profile.path_length else {
                return Err(Error::ConstraintViolation(format!(
                    "the issuing CA allows at most {limit} further levels, so the new CA \
                     needs an explicit path length"
                )));
            };
            if u32::from(requested) >= limit {
                return Err(Error::ConstraintViolation(format!(
                    "the issuing CA allows at most {limit} further levels"
                )));
            }
        }
        if let Some(allowed) = &self.facts.extended_key_usages {
            let within = profile
                .extended_key_usages
                .as_ref()
                .is_some_and(|usages| usages.within(allowed));
            if !within {
                return Err(Error::ConstraintViolation(
                    "a CA below a usage-constrained CA must be constrained to a subset".into(),
                ));
            }
        }
        let params = ca_params(profile, serial)?;
        self.sign(params, subject_key)
    }

    fn check_validity(&self, validity: &Validity) -> Result<(), Error> {
        if !validity.within(&self.facts.validity) {
            return Err(Error::ConstraintViolation(
                "the certificate would be valid outside the issuing CA's validity".into(),
            ));
        }
        Ok(())
    }

    fn sign(
        &self,
        mut params: rcgen::CertificateParams,
        subject_key: &SubjectPublicKey,
    ) -> Result<Certificate, Error> {
        params.use_authority_key_identifier_extension = true;
        let issuer = self.rcgen_issuer()?;
        let certificate = params
            .signed_by(subject_key, &issuer)
            .map_err(|error| issuer.key().error(error))?;
        Ok(Certificate {
            der: certificate.der().to_vec(),
        })
    }

    pub(crate) fn rcgen_issuer(&self) -> Result<rcgen::Issuer<'static, RcgenSigner<'a>>, Error> {
        let issuer = rcgen::Issuer::from_ca_cert_der(
            &self.certificate.as_slice().into(),
            RcgenSigner::new(self.signer),
        )?;
        Ok(issuer)
    }

    pub(crate) fn key_identifier(&self) -> &[u8] {
        &self.facts.key_identifier
    }
}

fn ca_params(
    profile: &CaProfile,
    serial: &SerialNumber,
) -> Result<rcgen::CertificateParams, Error> {
    let mut params = base_params(&profile.validity, serial);
    params.distinguished_name = ca_distinguished_name(&profile.subject)?;
    params.is_ca = rcgen::IsCa::Ca(match profile.path_length {
        Some(length) => rcgen::BasicConstraints::Constrained(length),
        None => rcgen::BasicConstraints::Unconstrained,
    });
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    params.name_constraints = profile
        .name_constraints
        .as_ref()
        .map(NameConstraints::to_rcgen);
    if let Some(usages) = &profile.extended_key_usages {
        params.extended_key_usages = usages.to_rcgen();
    }
    params.crl_distribution_points = distribution_points(&profile.crl_distribution_points);
    Ok(params)
}

fn ca_distinguished_name(subject: &CaSubject) -> Result<rcgen::DistinguishedName, Error> {
    if subject.common_name.trim().is_empty() {
        return Err(Error::InvalidValue("a CA needs a common name".into()));
    }
    let mut name = rcgen::DistinguishedName::new();
    for attribute in &subject.attributes {
        name.push(attribute.dn_type(), attribute.value.as_str());
    }
    name.push(rcgen::DnType::CommonName, subject.common_name.as_str());
    Ok(name)
}

fn leaf_params(profile: &LeafProfile, serial: &SerialNumber) -> rcgen::CertificateParams {
    let mut params = base_params(&profile.validity, serial);
    let mut name = rcgen::DistinguishedName::new();
    for attribute in &profile.subject.attributes {
        name.push(attribute.dn_type(), attribute.value.as_str());
    }
    match &profile.subject.common_name {
        Some(CommonName::Name(alt_name)) => {
            name.push(rcgen::DnType::CommonName, alt_name.to_string());
        }
        Some(CommonName::DisplayName(display)) => {
            name.push(rcgen::DnType::CommonName, display.as_str());
        }
        None => {}
    }
    params.distinguished_name = name;
    params.is_ca = rcgen::IsCa::ExplicitNoCa;
    params.subject_alt_names = profile.alt_names.iter().map(san).collect();
    params.key_usages = profile
        .key_usages
        .iter()
        .map(|usage| usage.to_rcgen())
        .collect();
    params.extended_key_usages = profile.extended_key_usages.to_rcgen();
    params.crl_distribution_points = distribution_points(&profile.crl_distribution_points);
    if let Some(sid) = &profile.owner_sid {
        params.custom_extensions.push(sid_extension(sid));
    }
    params
}

fn base_params(validity: &Validity, serial: &SerialNumber) -> rcgen::CertificateParams {
    let mut params = rcgen::CertificateParams::default();
    params.not_before = validity.not_before();
    params.not_after = validity.not_after();
    params.serial_number = Some(serial.to_rcgen());
    params
}

fn distribution_points(uris: &[String]) -> Vec<rcgen::CrlDistributionPoint> {
    if uris.is_empty() {
        return Vec::new();
    }
    vec![rcgen::CrlDistributionPoint {
        uris: uris.to_vec(),
    }]
}

fn san(name: &AltName) -> rcgen::SanType {
    // Every name here was validated as ASCII where IA5String requires it,
    // so the conversions cannot fail.
    let ia5 = |text: String| text.try_into().expect("validated names are ASCII");
    match name {
        AltName::Dns(name) => rcgen::SanType::DnsName(ia5(name.to_string())),
        AltName::Ip(address) => rcgen::SanType::IpAddress(*address),
        AltName::Email(mailbox) => rcgen::SanType::Rfc822Name(ia5(mailbox.to_string())),
        AltName::Upn(name) => rcgen::SanType::OtherName((
            OID_USER_PRINCIPAL_NAME.to_vec(),
            rcgen::OtherNameValue::Utf8String(name.to_string()),
        )),
    }
}

fn issuer_facts(certificate: &X509Certificate<'_>) -> Result<IssuerFacts, Error> {
    let invalid = |detail: &str| Error::InvalidIssuer(detail.to_owned());
    let basic = certificate
        .basic_constraints()
        .map_err(|_| invalid("malformed basic constraints"))?
        .filter(|basic| basic.value.ca)
        .ok_or_else(|| invalid("the certificate is not a CA"))?;
    let key_usage = certificate
        .key_usage()
        .map_err(|_| invalid("malformed key usage"))?
        .ok_or_else(|| invalid("the CA certificate states no key usage"))?;
    if !key_usage.value.key_cert_sign() || !key_usage.value.crl_sign() {
        return Err(invalid(
            "the CA certificate may not sign certificates and CRLs",
        ));
    }
    let key_identifier = match certificate
        .get_extension_unique(&x509_parser::oid_registry::OID_X509_EXT_SUBJECT_KEY_IDENTIFIER)
    {
        Ok(Some(extension)) => match extension.parsed_extension() {
            x509_parser::extensions::ParsedExtension::SubjectKeyIdentifier(id) => id.0.to_vec(),
            _ => return Err(invalid("malformed subject key identifier")),
        },
        _ => return Err(invalid("the CA certificate has no subject key identifier")),
    };
    let validity = Validity::new(
        certificate.validity().not_before.to_datetime(),
        certificate.validity().not_after.to_datetime(),
    )?;
    let extended_key_usages = match certificate.extended_key_usage() {
        Ok(None) => None,
        Ok(Some(usages)) => Some(usage_oids(usages.value)?),
        Err(_) => return Err(invalid("malformed extended key usage")),
    };
    let name_constraints = match certificate.name_constraints() {
        Ok(None) => None,
        Ok(Some(constraints)) => Some(name_constraints(constraints.value)?),
        Err(_) => return Err(invalid("malformed name constraints")),
    };
    Ok(IssuerFacts {
        validity,
        path_length: basic.value.path_len_constraint,
        name_constraints,
        extended_key_usages,
        key_identifier,
    })
}

fn usage_oids(
    usages: &x509_parser::extensions::ExtendedKeyUsage<'_>,
) -> Result<Vec<UsageOid>, Error> {
    if usages.any {
        return Err(Error::InvalidIssuer(
            "the CA certificate allows Any Purpose".into(),
        ));
    }
    let named = [
        (usages.server_auth, crate::ExtendedKeyUsage::ServerAuth),
        (usages.client_auth, crate::ExtendedKeyUsage::ClientAuth),
        (usages.code_signing, crate::ExtendedKeyUsage::CodeSigning),
        (
            usages.email_protection,
            crate::ExtendedKeyUsage::EmailProtection,
        ),
        (usages.time_stamping, crate::ExtendedKeyUsage::TimeStamping),
        (usages.ocsp_signing, crate::ExtendedKeyUsage::OcspSigning),
    ];
    let mut oids: Vec<UsageOid> = named
        .into_iter()
        .filter(|(present, _)| *present)
        .map(|(_, usage)| usage.oid())
        .collect();
    for other in &usages.other {
        oids.push(UsageOid::from_arcs(oid_arcs(other)?)?);
    }
    Ok(oids)
}

fn name_constraints(
    constraints: &x509_parser::extensions::NameConstraints<'_>,
) -> Result<NameConstraints, Error> {
    let subtrees = |list: &Option<Vec<x509_parser::extensions::GeneralSubtree<'_>>>| {
        list.iter()
            .flatten()
            .map(|subtree| name_subtree(&subtree.base))
            .collect::<Result<Vec<_>, Error>>()
    };
    Ok(NameConstraints {
        permitted: subtrees(&constraints.permitted_subtrees)?,
        excluded: subtrees(&constraints.excluded_subtrees)?,
    })
}

fn name_subtree(base: &GeneralName<'_>) -> Result<NameSubtree, Error> {
    let unsupported = || Error::InvalidIssuer(format!("unsupported name constraint {base}"));
    match base {
        GeneralName::DNSName(name) => {
            let name = name.strip_prefix('.').unwrap_or(name);
            DnsName::new(name)
                .map(NameSubtree::Dns)
                .map_err(|_| unsupported())
        }
        GeneralName::RFC822Name(host) if !host.contains('@') && !host.starts_with('.') => {
            DnsName::new(host)
                .map(NameSubtree::EmailDomain)
                .map_err(|_| unsupported())
        }
        GeneralName::IPAddress(bytes) => ip_subtree(bytes).ok_or_else(unsupported),
        _ => Err(unsupported()),
    }
}

/// Decodes an address-and-mask name constraint into a network and prefix.
fn ip_subtree(bytes: &[u8]) -> Option<NameSubtree> {
    let (address, mask) = bytes.split_at(bytes.len() / 2);
    let network = match address.len() {
        4 => std::net::IpAddr::from(<[u8; 4]>::try_from(address).ok()?),
        16 => std::net::IpAddr::from(<[u8; 16]>::try_from(address).ok()?),
        _ => return None,
    };
    // Left-align the mask in 128 bits; it must be ones followed only by zeros.
    let mask = mask
        .iter()
        .fold(0u128, |value, byte| (value << 8) | u128::from(*byte))
        << (128 - 8 * mask.len());
    let prefix_len = mask.leading_ones();
    if mask.checked_shl(prefix_len).unwrap_or(0) != 0 {
        return None;
    }
    NameSubtree::ip(network, u8::try_from(prefix_len).ok()?).ok()
}
