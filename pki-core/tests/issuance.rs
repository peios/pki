//! Behaviour of issued chains, checked with an independent verifier.

use peios_crypto::{KeyAlgorithm, PrivateKey, PublicKey, SignatureScheme, Signer};
use pki_core::{
    create_root, AltName, CaProfile, CaSubject, Certificate, CertificateRequest, CommonName,
    CrlProfile, DisplayName, DnsName, Error, ExtendedKeyUsage, ExtendedKeyUsages, IssuingCa,
    KeyUsage, LeafProfile, LeafSubject, NameConstraints, NameSubtree, RevocationReason,
    RevokedCertificate, SerialNumber, Sid, SubjectPublicKey, UsageOid, Validity,
};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use time::macros::datetime;
use time::OffsetDateTime;
use x509_parser::prelude::{FromDer, X509Certificate};

/// A software key, with its public key as pki-core reads a request's.
struct TestKey {
    key: PrivateKey,
    subject: SubjectPublicKey,
}

impl TestKey {
    fn generate(algorithm: KeyAlgorithm) -> Self {
        let key = PrivateKey::generate(algorithm).unwrap();
        let subject = SubjectPublicKey::from_der(key.public_key().spki()).unwrap();
        Self { key, subject }
    }

    fn subject(&self) -> &SubjectPublicKey {
        &self.subject
    }
}

impl Signer for TestKey {
    fn public_key(&self) -> &PublicKey {
        self.key.public_key()
    }

    fn sign(&self, scheme: SignatureScheme, message: &[u8]) -> peios_crypto::Result<Vec<u8>> {
        self.key.sign(scheme, message)
    }
}

/// Verification happens at a fixed time inside every test validity period.
const VERIFY_AT: OffsetDateTime = datetime!(2027-06-01 0:00 UTC);

fn validity(from: OffsetDateTime, to: OffsetDateTime) -> Validity {
    Validity::new(from, to).unwrap()
}

fn ca_profile(name: &str, path_length: Option<u8>) -> CaProfile {
    CaProfile {
        subject: CaSubject {
            common_name: name.into(),
            attributes: Vec::new(),
        },
        validity: validity(
            datetime!(2026-01-01 0:00 UTC),
            datetime!(2036-01-01 0:00 UTC),
        ),
        path_length,
        name_constraints: None,
        extended_key_usages: None,
        crl_distribution_points: Vec::new(),
    }
}

fn dns(name: &str) -> AltName {
    AltName::Dns(DnsName::new(name).unwrap())
}

fn server_profile(names: &[&str]) -> LeafProfile {
    let alt_names: Vec<AltName> = names.iter().map(|name| dns(name)).collect();
    LeafProfile {
        subject: LeafSubject {
            common_name: alt_names.first().cloned().map(CommonName::Name),
            attributes: Vec::new(),
        },
        alt_names,
        key_usages: vec![KeyUsage::DigitalSignature],
        extended_key_usages: ExtendedKeyUsages::new(vec![ExtendedKeyUsage::ServerAuth]).unwrap(),
        validity: validity(
            datetime!(2027-01-01 0:00 UTC),
            datetime!(2027-12-01 0:00 UTC),
        ),
        owner_sid: None,
        crl_distribution_points: vec!["http://pki.home/issuing.crl".into()],
    }
}

fn serial() -> SerialNumber {
    SerialNumber::random().unwrap()
}

/// A two-tier hierarchy: a root and an issuing CA below it.
struct Hierarchy {
    root_key: TestKey,
    root: Certificate,
    issuing_key: TestKey,
    issuing: Certificate,
}

impl Hierarchy {
    fn new(root_key: TestKey, issuing_profile: CaProfile) -> Self {
        let root = create_root(&root_key, &ca_profile("Test Root", Some(1)), &serial()).unwrap();
        let issuing_key = TestKey::generate(KeyAlgorithm::EcdsaP256);
        let issuing = IssuingCa::new(root.der(), &root_key)
            .unwrap()
            .issue_ca(issuing_key.subject(), &issuing_profile, &serial())
            .unwrap();
        Self {
            root_key,
            root,
            issuing_key,
            issuing,
        }
    }

    fn ecdsa() -> Self {
        let root_key = TestKey::generate(KeyAlgorithm::EcdsaP384);
        Self::new(root_key, ca_profile("Test Issuing CA", Some(0)))
    }

    fn issuing_ca(&self) -> IssuingCa<'_> {
        IssuingCa::new(self.issuing.der(), &self.issuing_key).unwrap()
    }

    fn verify_server(&self, leaf: &Certificate, name: &str) -> Result<(), webpki::Error> {
        let root = CertificateDer::from(self.root.der());
        let anchors = [webpki::anchor_from_trusted_cert(&root).unwrap()];
        let intermediates = [CertificateDer::from(self.issuing.der())];
        let leaf = CertificateDer::from(leaf.der());
        let end_entity = webpki::EndEntityCert::try_from(&leaf)?;
        end_entity.verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &anchors,
            &intermediates,
            UnixTime::since_unix_epoch(std::time::Duration::from_secs(
                VERIFY_AT.unix_timestamp() as u64
            )),
            webpki::KeyUsage::server_auth(),
            None,
            None,
        )?;
        end_entity.verify_is_valid_for_subject_name(&ServerName::try_from(name).unwrap())
    }
}

fn leaf_key() -> TestKey {
    TestKey::generate(KeyAlgorithm::EcdsaP256)
}

#[test]
fn two_tier_server_certificate_verifies() {
    let hierarchy = Hierarchy::ecdsa();
    let key = leaf_key();
    let leaf = hierarchy
        .issuing_ca()
        .issue(key.subject(), &server_profile(&["radius.home"]), &serial())
        .unwrap();
    hierarchy.verify_server(&leaf, "radius.home").unwrap();
    assert!(hierarchy.verify_server(&leaf, "other.home").is_err());
}

#[test]
fn rsa_root_with_ecdsa_issuing_ca_verifies() {
    let root_key = TestKey::generate(KeyAlgorithm::Rsa3072);
    let hierarchy = Hierarchy::new(root_key, ca_profile("Test Issuing CA", Some(0)));
    let key = leaf_key();
    let leaf = hierarchy
        .issuing_ca()
        .issue(key.subject(), &server_profile(&["radius.home"]), &serial())
        .unwrap();
    hierarchy.verify_server(&leaf, "radius.home").unwrap();
}

#[test]
fn rsa_subject_keys_are_certified() {
    let hierarchy = Hierarchy::ecdsa();
    let key = TestKey::generate(KeyAlgorithm::Rsa3072);
    let leaf = hierarchy
        .issuing_ca()
        .issue(key.subject(), &server_profile(&["printer.home"]), &serial())
        .unwrap();
    hierarchy.verify_server(&leaf, "printer.home").unwrap();
}

#[test]
fn common_name_must_be_one_of_the_names() {
    let hierarchy = Hierarchy::ecdsa();
    let mut profile = server_profile(&["radius.home"]);
    profile.subject.common_name = Some(CommonName::Name(dns("administrator.home")));
    let result = hierarchy
        .issuing_ca()
        .issue(leaf_key().subject(), &profile, &serial());
    assert!(matches!(result, Err(Error::InvalidValue(_))), "{result:?}");
}

#[test]
fn display_name_becomes_the_common_name() {
    let hierarchy = Hierarchy::ecdsa();
    let mut profile = server_profile(&["radius.home"]);
    profile.alt_names = vec![AltName::Upn(
        pki_core::UserPrincipalName::new("jack@home").unwrap(),
    )];
    profile.extended_key_usages =
        ExtendedKeyUsages::new(vec![ExtendedKeyUsage::ClientAuth]).unwrap();
    profile.subject.common_name = Some(CommonName::DisplayName(
        DisplayName::new("Jack Palfrey").unwrap(),
    ));
    let leaf = hierarchy
        .issuing_ca()
        .issue(leaf_key().subject(), &profile, &serial())
        .unwrap();
    let parsed = parse(&leaf);
    let common_name = parsed.subject().iter_common_name().next().unwrap();
    assert_eq!(common_name.as_str().unwrap(), "Jack Palfrey");
}

#[test]
fn display_names_are_plain_text() {
    assert!(DisplayName::new("Jack Palfrey").is_ok());
    for invalid in ["", " Jack", "Jack\nAdministrator", &"x".repeat(65)] {
        assert!(DisplayName::new(invalid).is_err(), "{invalid:?} accepted");
    }
}

#[test]
fn certificate_without_names_is_refused() {
    let hierarchy = Hierarchy::ecdsa();
    let mut profile = server_profile(&["radius.home"]);
    profile.alt_names.clear();
    profile.subject.common_name = None;
    let result = hierarchy
        .issuing_ca()
        .issue(leaf_key().subject(), &profile, &serial());
    assert!(matches!(result, Err(Error::InvalidValue(_))), "{result:?}");
}

#[test]
fn extended_key_usages_must_be_explicit() {
    assert!(ExtendedKeyUsages::new(Vec::new()).is_err());
    assert!(UsageOid::new("2.5.29.37.0").is_err());
    assert!(UsageOid::new("1.3.6.1.4.1.311.20.2.2").is_ok());
}

#[test]
fn certificate_outliving_its_issuer_is_refused() {
    let hierarchy = Hierarchy::ecdsa();
    let mut profile = server_profile(&["radius.home"]);
    profile.validity = validity(
        datetime!(2027-01-01 0:00 UTC),
        datetime!(2040-01-01 0:00 UTC),
    );
    let result = hierarchy
        .issuing_ca()
        .issue(leaf_key().subject(), &profile, &serial());
    assert!(
        matches!(result, Err(Error::ConstraintViolation(_))),
        "{result:?}"
    );
}

#[test]
fn path_length_limits_further_cas() {
    let hierarchy = Hierarchy::ecdsa();
    let key = leaf_key();
    let below_zero =
        hierarchy
            .issuing_ca()
            .issue_ca(key.subject(), &ca_profile("Too Deep", None), &serial());
    assert!(
        matches!(below_zero, Err(Error::ConstraintViolation(_))),
        "{below_zero:?}"
    );

    let root = IssuingCa::new(hierarchy.root.der(), &hierarchy.root_key).unwrap();
    let unlimited = root.issue_ca(key.subject(), &ca_profile("Unlimited", None), &serial());
    assert!(
        matches!(unlimited, Err(Error::ConstraintViolation(_))),
        "{unlimited:?}"
    );
    let equal = root.issue_ca(key.subject(), &ca_profile("Equal", Some(1)), &serial());
    assert!(
        matches!(equal, Err(Error::ConstraintViolation(_))),
        "{equal:?}"
    );
}

#[test]
fn three_tier_hierarchy_verifies() {
    let root_key = TestKey::generate(KeyAlgorithm::EcdsaP384);
    let root = create_root(&root_key, &ca_profile("Root", Some(2)), &serial()).unwrap();
    let policy_key = TestKey::generate(KeyAlgorithm::EcdsaP384);
    let policy = IssuingCa::new(root.der(), &root_key)
        .unwrap()
        .issue_ca(
            policy_key.subject(),
            &ca_profile("Policy", Some(1)),
            &serial(),
        )
        .unwrap();
    let issuing_key = TestKey::generate(KeyAlgorithm::EcdsaP256);
    let issuing = IssuingCa::new(policy.der(), &policy_key)
        .unwrap()
        .issue_ca(
            issuing_key.subject(),
            &ca_profile("Issuing", Some(0)),
            &serial(),
        )
        .unwrap();
    let key = leaf_key();
    let leaf = IssuingCa::new(issuing.der(), &issuing_key)
        .unwrap()
        .issue(key.subject(), &server_profile(&["radius.home"]), &serial())
        .unwrap();

    let root_der = CertificateDer::from(root.der());
    let anchors = [webpki::anchor_from_trusted_cert(&root_der).unwrap()];
    let intermediates = [
        CertificateDer::from(policy.der()),
        CertificateDer::from(issuing.der()),
    ];
    let leaf = CertificateDer::from(leaf.der());
    webpki::EndEntityCert::try_from(&leaf)
        .unwrap()
        .verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &anchors,
            &intermediates,
            UnixTime::since_unix_epoch(std::time::Duration::from_secs(
                VERIFY_AT.unix_timestamp() as u64
            )),
            webpki::KeyUsage::server_auth(),
            None,
            None,
        )
        .unwrap();
}

#[test]
fn name_constraints_bind_the_issuing_ca() {
    let mut profile = ca_profile("Lab Issuing CA", Some(0));
    profile.name_constraints = Some(NameConstraints {
        permitted: vec![NameSubtree::Dns(DnsName::new("lab.home").unwrap())],
        excluded: Vec::new(),
    });
    let root_key = TestKey::generate(KeyAlgorithm::EcdsaP384);
    let hierarchy = Hierarchy::new(root_key, profile);
    let key = leaf_key();

    let inside = hierarchy
        .issuing_ca()
        .issue(
            key.subject(),
            &server_profile(&["printer.lab.home"]),
            &serial(),
        )
        .unwrap();
    hierarchy
        .verify_server(&inside, "printer.lab.home")
        .unwrap();

    let outside =
        hierarchy
            .issuing_ca()
            .issue(key.subject(), &server_profile(&["radius.home"]), &serial());
    assert!(
        matches!(outside, Err(Error::ConstraintViolation(_))),
        "{outside:?}"
    );
}

#[test]
fn usage_constrained_issuing_ca_refuses_other_usages() {
    let mut profile = ca_profile("Servers Only", Some(0));
    profile.extended_key_usages =
        Some(ExtendedKeyUsages::new(vec![ExtendedKeyUsage::ServerAuth]).unwrap());
    let root_key = TestKey::generate(KeyAlgorithm::EcdsaP384);
    let hierarchy = Hierarchy::new(root_key, profile);
    let mut leaf = server_profile(&["radius.home"]);
    leaf.extended_key_usages = ExtendedKeyUsages::new(vec![ExtendedKeyUsage::CodeSigning]).unwrap();
    let result = hierarchy
        .issuing_ca()
        .issue(leaf_key().subject(), &leaf, &serial());
    assert!(
        matches!(result, Err(Error::ConstraintViolation(_))),
        "{result:?}"
    );
}

#[test]
fn issuer_refuses_a_signer_for_another_key() {
    let hierarchy = Hierarchy::ecdsa();
    let other = leaf_key();
    let result = IssuingCa::new(hierarchy.issuing.der(), &other);
    assert!(
        matches!(result, Err(Error::InvalidIssuer(_))),
        "{:?}",
        result.err()
    );
}

#[test]
fn leaf_certificate_cannot_issue() {
    let hierarchy = Hierarchy::ecdsa();
    let key = leaf_key();
    let leaf = hierarchy
        .issuing_ca()
        .issue(key.subject(), &server_profile(&["radius.home"]), &serial())
        .unwrap();
    let result = IssuingCa::new(leaf.der(), &key);
    assert!(
        matches!(result, Err(Error::InvalidIssuer(_))),
        "{:?}",
        result.err()
    );
}

fn parse(certificate: &Certificate) -> X509Certificate<'_> {
    X509Certificate::from_der(certificate.der()).unwrap().1
}

#[test]
fn owner_sid_is_embedded_when_present() {
    let hierarchy = Hierarchy::ecdsa();
    let key = leaf_key();
    let mut profile = server_profile(&["radius.home"]);
    profile.owner_sid = Some(Sid::new("S-1-5-21-1-2-3-1001").unwrap());
    let with_sid = hierarchy
        .issuing_ca()
        .issue(key.subject(), &profile, &serial())
        .unwrap();
    let extension = parse(&with_sid)
        .extensions()
        .iter()
        .find(|extension| extension.oid.to_id_string() == "1.3.6.1.4.1.311.25.2")
        .map(|extension| (extension.critical, extension.value.to_vec()))
        .expect("SID extension present");
    assert!(!extension.0);
    assert!(extension.1.ends_with(b"S-1-5-21-1-2-3-1001"));

    profile.owner_sid = None;
    let without = hierarchy
        .issuing_ca()
        .issue(key.subject(), &profile, &serial())
        .unwrap();
    assert!(parse(&without)
        .extensions()
        .iter()
        .all(|extension| extension.oid.to_id_string() != "1.3.6.1.4.1.311.25.2"));
}

#[test]
fn request_contributes_only_its_key_and_names() {
    let requester = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut asked = rcgen::CertificateParams::new(vec!["radius.home".to_string()]).unwrap();
    asked.distinguished_name = rcgen::DistinguishedName::new();
    asked
        .distinguished_name
        .push(rcgen::DnType::CommonName, "radius.home");
    asked
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, "Requested Org");
    asked.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    asked.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::CodeSigning];
    let csr = asked.serialize_request(&requester).unwrap();

    let csr_pem = pem::encode(&pem::Pem::new("CERTIFICATE REQUEST", csr.der().to_vec()));
    let request = CertificateRequest::from_pem(&csr_pem).unwrap();
    assert_eq!(request.names(), &[dns("radius.home")]);
    let requester_spki = rcgen::PublicKeyData::subject_public_key_info(&requester);
    assert_eq!(request.subject_key().der(), requester_spki.as_slice());

    let hierarchy = Hierarchy::ecdsa();
    let leaf = hierarchy
        .issuing_ca()
        .issue(
            request.subject_key(),
            &server_profile(&["radius.home"]),
            &serial(),
        )
        .unwrap();
    hierarchy.verify_server(&leaf, "radius.home").unwrap();
    let parsed = parse(&leaf);
    assert!(!parsed.is_ca());
    assert!(parsed.subject().iter_organization().next().is_none());
    let usages = parsed.extended_key_usage().unwrap().unwrap().value;
    assert!(usages.server_auth && !usages.code_signing);
}

#[test]
fn request_common_name_becomes_a_requested_name() {
    let requester = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut asked = rcgen::CertificateParams::new(vec!["radius.home".to_string()]).unwrap();
    asked.distinguished_name = rcgen::DistinguishedName::new();
    asked
        .distinguished_name
        .push(rcgen::DnType::CommonName, "administrator.home");
    let csr = asked.serialize_request(&requester).unwrap();
    let request = CertificateRequest::from_der(csr.der()).unwrap();
    assert_eq!(
        request.names(),
        &[dns("radius.home"), dns("administrator.home")]
    );
}

#[test]
fn request_common_name_that_is_not_a_name_is_refused() {
    let requester = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut asked = rcgen::CertificateParams::new(vec!["radius.home".to_string()]).unwrap();
    asked.distinguished_name = rcgen::DistinguishedName::new();
    asked
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Domain Administrator");
    let csr = asked.serialize_request(&requester).unwrap();
    let result = CertificateRequest::from_der(csr.der());
    assert!(
        matches!(result, Err(Error::UnsupportedName(_))),
        "{result:?}"
    );
}

/// A CSR with no subject, asking for the given alternative names.
fn request_for(names: Vec<rcgen::SanType>) -> Result<CertificateRequest, Error> {
    let requester = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut asked = rcgen::CertificateParams::default();
    asked.distinguished_name = rcgen::DistinguishedName::new();
    asked.subject_alt_names = names;
    let csr = asked.serialize_request(&requester).unwrap();
    CertificateRequest::from_der(csr.der())
}

#[test]
fn request_device_names_are_parsed() {
    const UPN: &[u64] = &[1, 3, 6, 1, 4, 1, 311, 20, 2, 3];
    let request = request_for(vec![
        rcgen::SanType::OtherName((
            UPN.to_vec(),
            rcgen::OtherNameValue::Utf8String("jack@home".into()),
        )),
        rcgen::SanType::Rfc822Name("jack@home".try_into().unwrap()),
        rcgen::SanType::IpAddress("10.1.2.3".parse().unwrap()),
        rcgen::SanType::IpAddress("fd00::1".parse().unwrap()),
    ])
    .unwrap();
    assert_eq!(
        request.names(),
        &[
            AltName::Upn(pki_core::UserPrincipalName::new("jack@home").unwrap()),
            AltName::Email(pki_core::Mailbox::new("jack@home").unwrap()),
            AltName::Ip("10.1.2.3".parse().unwrap()),
            AltName::Ip("fd00::1".parse().unwrap()),
        ]
    );
}

#[test]
fn request_for_unsupported_name_types_is_refused() {
    let uri = request_for(vec![rcgen::SanType::URI(
        "https://radius.home/".try_into().unwrap(),
    )]);
    assert!(matches!(uri, Err(Error::UnsupportedName(_))), "{uri:?}");

    let other = request_for(vec![rcgen::SanType::OtherName((
        vec![1, 3, 6, 1, 4, 1, 99999, 1],
        rcgen::OtherNameValue::Utf8String("anything".into()),
    ))]);
    assert!(matches!(other, Err(Error::UnsupportedName(_))), "{other:?}");
}

#[test]
fn request_without_names_is_refused() {
    let result = request_for(Vec::new());
    assert!(
        matches!(result, Err(Error::MalformedRequest(_))),
        "{result:?}"
    );
}

#[test]
fn tampered_request_is_refused() {
    let requester = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let asked = rcgen::CertificateParams::new(vec!["radius.home".to_string()]).unwrap();
    let mut der = asked.serialize_request(&requester).unwrap().der().to_vec();
    let position = der
        .windows(11)
        .position(|window| window == b"radius.home")
        .unwrap();
    der[position] = b'R';
    let result = CertificateRequest::from_der(&der);
    assert!(
        matches!(result, Err(Error::InvalidRequestSignature)),
        "{result:?}"
    );
}

#[test]
fn small_rsa_keys_are_refused() {
    let spki = include_bytes!("data/rsa-1024-test-public-key.der");
    let result = SubjectPublicKey::from_der(spki);
    assert!(
        matches!(result, Err(Error::UnsupportedKey(_))),
        "{result:?}"
    );
}

#[test]
fn crl_lists_revoked_serials_and_verifies() {
    let hierarchy = Hierarchy::ecdsa();
    let revoked = serial();
    let crl = hierarchy
        .issuing_ca()
        .sign_crl(&CrlProfile {
            this_update: datetime!(2027-05-01 0:00 UTC),
            next_update: datetime!(2027-08-01 0:00 UTC),
            number: 7,
            revoked: vec![RevokedCertificate {
                serial: revoked.clone(),
                revoked_at: datetime!(2027-04-30 12:00 UTC),
                reason: Some(RevocationReason::KeyCompromise),
            }],
        })
        .unwrap();

    let (_, parsed) =
        x509_parser::revocation_list::CertificateRevocationList::from_der(crl.der()).unwrap();
    let serials: Vec<Vec<u8>> = parsed
        .iter_revoked_certificates()
        .map(|entry| entry.raw_serial().to_vec())
        .collect();
    assert_eq!(serials, vec![revoked.as_bytes().to_vec()]);
    let issuer = parse(&hierarchy.issuing);
    parsed.verify_signature(issuer.public_key()).unwrap();
}

#[test]
fn serial_numbers_round_trip_through_storage() {
    let generated = serial();
    assert_eq!(
        SerialNumber::from_bytes(generated.as_bytes()).unwrap(),
        generated
    );
    assert!(SerialNumber::from_bytes(&[0]).is_err());
    assert!(SerialNumber::from_bytes(&[0x80]).is_err());
    assert!(SerialNumber::from_bytes(&[0, 0x01]).is_err());
    assert!(SerialNumber::from_bytes(&[0, 0x80]).is_ok());
}

#[test]
fn signer_failures_are_reported() {
    struct FailingSigner(TestKey);
    impl Signer for FailingSigner {
        fn public_key(&self) -> &PublicKey {
            self.0.public_key()
        }
        fn sign(&self, _: SignatureScheme, _: &[u8]) -> peios_crypto::Result<Vec<u8>> {
            Err(peios_crypto::Error::PolicyRejected {
                algorithm: "ecdsa-p256",
                operation: "sign",
            })
        }
    }
    let signer = FailingSigner(leaf_key());
    let result = create_root(&signer, &ca_profile("Offline", None), &serial());
    assert_eq!(
        result.unwrap_err(),
        Error::Crypto(peios_crypto::Error::PolicyRejected {
            algorithm: "ecdsa-p256",
            operation: "sign",
        })
    );
}

#[test]
fn ip_and_email_name_constraints_round_trip() {
    let mut profile = ca_profile("Lab Network CA", Some(0));
    profile.name_constraints = Some(NameConstraints {
        permitted: vec![
            NameSubtree::ip("10.0.0.0".parse().unwrap(), 8).unwrap(),
            NameSubtree::EmailDomain(DnsName::new("lab.home").unwrap()),
        ],
        excluded: vec![NameSubtree::ip("10.9.0.0".parse().unwrap(), 16).unwrap()],
    });
    let root_key = TestKey::generate(KeyAlgorithm::EcdsaP384);
    let hierarchy = Hierarchy::new(root_key, profile);
    let ca = hierarchy.issuing_ca();
    let key = leaf_key();
    let issue = |name: AltName| {
        let mut profile = server_profile(&["radius.home"]);
        profile.subject.common_name = None;
        profile.alt_names = vec![name];
        ca.issue(key.subject(), &profile, &serial())
    };

    assert!(issue(AltName::Ip("10.1.2.3".parse().unwrap())).is_ok());
    assert!(issue(AltName::Ip("192.168.1.1".parse().unwrap())).is_err());
    assert!(issue(AltName::Ip("10.9.1.1".parse().unwrap())).is_err());
    assert!(issue(AltName::Email(
        pki_core::Mailbox::new("jack@lab.home").unwrap()
    ))
    .is_ok());
    assert!(issue(AltName::Email(pki_core::Mailbox::new("jack@home").unwrap())).is_err());
}
