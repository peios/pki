//! Certificate templates: what each kind of certificate contains.

use pki_core::{
    AltName, EcdsaCurve, ExtendedKeyUsage, ExtendedKeyUsages, KeyAlgorithm, KeyUsage,
    SubjectPublicKey, UsageOid,
};
use time::Duration;

use crate::access::SecurityBlob;
use crate::values::Values;
use crate::PolicyError;

const SECONDS_PER_DAY: i64 = 86_400;
/// The longest lifetime a template may give, about 20 years. A leaf
/// certificate outliving that is a configuration mistake.
const MAX_LIFETIME_DAYS: u32 = 7305;

/// A key a template accepts in a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRequirement {
    EcdsaP256,
    EcdsaP384,
    /// RSA with at least this many modulus bits.
    Rsa {
        min_bits: u32,
    },
}

impl KeyRequirement {
    fn parse(text: &str) -> Result<Self, PolicyError> {
        match text {
            "ecdsa-p256" => Ok(Self::EcdsaP256),
            "ecdsa-p384" => Ok(Self::EcdsaP384),
            _ => {
                let bits = text
                    .strip_prefix("rsa-")
                    .and_then(|bits| bits.parse::<u32>().ok())
                    .ok_or_else(|| invalid(format!("unknown key algorithm {text:?}")))?;
                pki_core::RsaModulusBits::new(bits)?;
                Ok(Self::Rsa { min_bits: bits })
            }
        }
    }

    fn accepts(self, algorithm: KeyAlgorithm) -> bool {
        match (self, algorithm) {
            (Self::EcdsaP256, KeyAlgorithm::Ecdsa(EcdsaCurve::P256)) => true,
            (Self::EcdsaP384, KeyAlgorithm::Ecdsa(EcdsaCurve::P384)) => true,
            (Self::Rsa { min_bits }, KeyAlgorithm::Rsa(bits)) => bits.bits() >= min_bits,
            _ => false,
        }
    }
}

/// A kind of name a template allows in its certificates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameType {
    Dns,
    Email,
    Upn,
}

impl NameType {
    fn parse(text: &str) -> Result<Self, PolicyError> {
        match text {
            "dns" => Ok(Self::Dns),
            "email" => Ok(Self::Email),
            "upn" => Ok(Self::Upn),
            _ => Err(invalid(format!("unknown name type {text:?}"))),
        }
    }

    pub(crate) fn of(name: &AltName) -> Option<Self> {
        match name {
            AltName::Dns(_) => Some(Self::Dns),
            AltName::Email(_) => Some(Self::Email),
            AltName::Upn(_) => Some(Self::Upn),
            AltName::Ip(_) => None,
        }
    }
}

/// Where a certificate's common name comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommonNameRule {
    /// No common name; the names are in the alternative names only.
    None,
    /// The first approved name, repeated.
    FirstName,
    /// The display name of the names' owner, from identity data. A request
    /// that names no single owner can't use this template.
    OwnerDisplayName,
}

/// Whether an approved request is issued at once or held for an officer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Issuance {
    Immediate,
    Approval,
}

/// A named recipe for one kind of certificate. Requesters can't override
/// anything here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template {
    pub name: String,
    pub purposes: ExtendedKeyUsages,
    pub key_usages: Vec<KeyUsage>,
    pub lifetime: Duration,
    /// How long before expiry renewal becomes due.
    pub renewal_window: Duration,
    pub key_requirements: Vec<KeyRequirement>,
    pub name_types: Vec<NameType>,
    pub common_name: CommonNameRule,
    pub issuance: Issuance,
    /// Who may enrol (`TEMPLATE_ENROLL`) and auto-enrol.
    pub enroll_security: SecurityBlob,
}

impl Template {
    /// Reads a template from its Registry values, validating every one.
    pub fn from_values(values: &Values) -> Result<Self, PolicyError> {
        let name = values.required_sz("Name")?.trim();
        if name.is_empty() {
            return Err(invalid("Name is empty".into()));
        }
        let purposes = parse_list(values.multi_sz("Purposes")?, purpose)?;
        let key_usages = parse_list(values.multi_sz("KeyUsages")?, key_usage)?;
        let lifetime_days = values.required_dword("LifetimeDays")?;
        if lifetime_days == 0 || lifetime_days > MAX_LIFETIME_DAYS {
            return Err(invalid(format!(
                "LifetimeDays must be 1 to {MAX_LIFETIME_DAYS}"
            )));
        }
        let renewal_days = values.dword("RenewalWindowDays")?.unwrap_or(0);
        if renewal_days >= lifetime_days {
            return Err(invalid(
                "RenewalWindowDays must be less than LifetimeDays".into(),
            ));
        }
        let template = Self {
            name: name.to_owned(),
            purposes: ExtendedKeyUsages::new(purposes)?,
            key_usages,
            lifetime: days(lifetime_days),
            renewal_window: days(renewal_days),
            key_requirements: parse_list(values.multi_sz("KeyAlgorithms")?, KeyRequirement::parse)?,
            name_types: parse_list(values.multi_sz("NameTypes")?, NameType::parse)?,
            common_name: common_name_rule(values.sz("CommonName")?.unwrap_or("first-name"))?,
            issuance: issuance(values.sz("Issuance")?.unwrap_or("immediate"))?,
            enroll_security: SecurityBlob::new(
                values
                    .binary("EnrollSecurity")?
                    .ok_or_else(|| invalid("EnrollSecurity is required".into()))?
                    .to_vec(),
            ),
        };
        Ok(template)
    }

    pub(crate) fn accepts_key(&self, key: &SubjectPublicKey) -> bool {
        self.key_requirements
            .iter()
            .any(|requirement| requirement.accepts(key.algorithm()))
    }

    pub(crate) fn accepts_name(&self, name: &AltName) -> bool {
        NameType::of(name).is_some_and(|kind| self.name_types.contains(&kind))
    }
}

fn days(count: u32) -> Duration {
    Duration::seconds(i64::from(count) * SECONDS_PER_DAY)
}

fn parse_list<T>(
    items: &[String],
    parse: impl Fn(&str) -> Result<T, PolicyError>,
) -> Result<Vec<T>, PolicyError> {
    if items.is_empty() {
        return Err(invalid("a list value is empty".into()));
    }
    items.iter().map(|item| parse(item)).collect()
}

fn purpose(text: &str) -> Result<ExtendedKeyUsage, PolicyError> {
    Ok(match text {
        "server-auth" => ExtendedKeyUsage::ServerAuth,
        "client-auth" => ExtendedKeyUsage::ClientAuth,
        "code-signing" => ExtendedKeyUsage::CodeSigning,
        "email-protection" => ExtendedKeyUsage::EmailProtection,
        "time-stamping" => ExtendedKeyUsage::TimeStamping,
        "ocsp-signing" => ExtendedKeyUsage::OcspSigning,
        oid => ExtendedKeyUsage::Other(UsageOid::new(oid)?),
    })
}

fn key_usage(text: &str) -> Result<KeyUsage, PolicyError> {
    match text {
        "digital-signature" => Ok(KeyUsage::DigitalSignature),
        "content-commitment" => Ok(KeyUsage::ContentCommitment),
        "key-encipherment" => Ok(KeyUsage::KeyEncipherment),
        "data-encipherment" => Ok(KeyUsage::DataEncipherment),
        "key-agreement" => Ok(KeyUsage::KeyAgreement),
        _ => Err(invalid(format!("unknown key usage {text:?}"))),
    }
}

fn common_name_rule(text: &str) -> Result<CommonNameRule, PolicyError> {
    match text {
        "none" => Ok(CommonNameRule::None),
        "first-name" => Ok(CommonNameRule::FirstName),
        "owner-display-name" => Ok(CommonNameRule::OwnerDisplayName),
        _ => Err(invalid(format!("unknown CommonName rule {text:?}"))),
    }
}

fn issuance(text: &str) -> Result<Issuance, PolicyError> {
    match text {
        "immediate" => Ok(Issuance::Immediate),
        "approval" => Ok(Issuance::Approval),
        _ => Err(invalid(format!("unknown Issuance {text:?}"))),
    }
}

fn invalid(detail: String) -> PolicyError {
    PolicyError::InvalidConfiguration(detail)
}
