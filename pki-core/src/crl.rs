//! Certificate revocation lists.

use time::OffsetDateTime;

use crate::ca::IssuingCa;
use crate::profile::SerialNumber;
use crate::Error;

const PEM_LABEL: &str = "X509 CRL";

/// Why a certificate was revoked (RFC 5280 §5.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RevocationReason {
    Unspecified,
    KeyCompromise,
    CaCompromise,
    AffiliationChanged,
    Superseded,
    CessationOfOperation,
    CertificateHold,
    PrivilegeWithdrawn,
}

impl RevocationReason {
    fn to_rcgen(self) -> rcgen::RevocationReason {
        match self {
            Self::Unspecified => rcgen::RevocationReason::Unspecified,
            Self::KeyCompromise => rcgen::RevocationReason::KeyCompromise,
            Self::CaCompromise => rcgen::RevocationReason::CaCompromise,
            Self::AffiliationChanged => rcgen::RevocationReason::AffiliationChanged,
            Self::Superseded => rcgen::RevocationReason::Superseded,
            Self::CessationOfOperation => rcgen::RevocationReason::CessationOfOperation,
            Self::CertificateHold => rcgen::RevocationReason::CertificateHold,
            Self::PrivilegeWithdrawn => rcgen::RevocationReason::PrivilegeWithdrawn,
        }
    }
}

/// One revoked certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokedCertificate {
    pub serial: SerialNumber,
    pub revoked_at: OffsetDateTime,
    pub reason: Option<RevocationReason>,
}

/// The contents of one CRL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrlProfile {
    pub this_update: OffsetDateTime,
    /// When the next CRL is due. Verifiers may reject everything under the
    /// CA once this passes, so CRLs must be re-signed before it.
    pub next_update: OffsetDateTime,
    /// Increases with every CRL the CA signs.
    pub number: u64,
    pub revoked: Vec<RevokedCertificate>,
}

/// A DER-encoded X.509 CRL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationList {
    der: Vec<u8>,
}

impl RevocationList {
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    pub fn pem(&self) -> String {
        pem::encode(&pem::Pem::new(PEM_LABEL, self.der.clone()))
    }
}

impl IssuingCa<'_> {
    /// Signs a CRL listing `profile`'s revoked certificates.
    pub fn sign_crl(&self, profile: &CrlProfile) -> Result<RevocationList, Error> {
        if profile.next_update <= profile.this_update {
            return Err(Error::InvalidValue(
                "a CRL's next update must follow this one".into(),
            ));
        }
        let params = rcgen::CertificateRevocationListParams {
            this_update: profile.this_update,
            next_update: profile.next_update,
            crl_number: crl_number(profile.number),
            issuing_distribution_point: None,
            revoked_certs: profile
                .revoked
                .iter()
                .map(|revoked| rcgen::RevokedCertParams {
                    serial_number: revoked.serial.to_rcgen(),
                    revocation_time: revoked.revoked_at,
                    reason_code: revoked.reason.map(RevocationReason::to_rcgen),
                    invalidity_date: None,
                })
                .collect(),
            key_identifier_method: rcgen::KeyIdMethod::PreSpecified(self.key_identifier().to_vec()),
        };
        let issuer = self.rcgen_issuer()?;
        let list = params
            .signed_by(&issuer)
            .map_err(|error| issuer.key().error(error))?;
        Ok(RevocationList {
            der: list.der().to_vec(),
        })
    }
}

/// Encodes a CRL number as a positive big-endian integer.
fn crl_number(number: u64) -> rcgen::SerialNumber {
    let mut bytes = vec![0];
    bytes.extend(number.to_be_bytes());
    rcgen::SerialNumber::from_slice(&bytes)
}
