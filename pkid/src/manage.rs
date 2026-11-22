//! Creating and maintaining CAs.
//!
//! Creating or importing a CA needs Manage CA in `Settings ManageSecurity`;
//! changing one needs Manage CA in its own `CaSecurity`. pkid makes the key
//! and the certificate, writes the CA's record under `Authorities` (the only
//! configuration it may write), and takes up the new configuration before
//! replying, so the caller's next request finds the CA.
//!
//! A key sealed under a passphrase is never kept open: an operation that
//! signs with one takes its passphrase in the same request.

use pki_core::{
    ca_request, ca_request_key, create_root, CaProfile, CaSubject, IssuingCa, SerialNumber,
    SubjectPublicKey, Validity,
};
use pki_keys::{
    open_sealed_key, KeyAlgorithm, KeyOptions, KeyProvider, KeyReference, NewPassphrase, OpenKey,
    Passphrase, PrivateKey, PublicKey, Signer,
};
use pki_pipeline::{Principal, CA_MANAGE};
use pki_policy::{RegData, SecurityBlob, Values};
use pki_store::{NewCertificate, NewRequest};
use pkid_core::{ErrorCode, Issuer, KeySpec, Reply, Request, WireError};
use time::{Duration, OffsetDateTime};

use crate::config::{AuthorityConfig, Loaded, MAX_CRL_LIFETIME_DAYS};
use crate::dispatch::{authority_info, key_error, Event, Services, State};

/// How far before now a CA certificate becomes valid, so verifiers with
/// slightly slow clocks accept it at once.
const CLOCK_SKEW_ALLOWANCE: Duration = Duration::minutes(5);

/// The template recorded for subordinate CA certificates in the CA
/// database, which no configured template can be named.
const SUBORDINATE_TEMPLATE: &str = "subordinate-ca";

fn bad(message: impl Into<String>) -> WireError {
    WireError::new(ErrorCode::BadRequest, message)
}

fn internal(message: impl ToString) -> WireError {
    WireError::new(ErrorCode::Internal, message.to_string())
}

fn loaded(state: &State) -> &Loaded {
    state
        .loaded
        .as_ref()
        .expect("handle checks the configuration first")
}

fn require(caller: &dyn Principal, security: &SecurityBlob, right: u32) -> Result<(), WireError> {
    let granted = caller
        .checker()
        .granted(security, right, None)
        .map_err(internal)?;
    if granted & right == right {
        Ok(())
    } else {
        Err(WireError::new(ErrorCode::AccessDenied, "access denied"))
    }
}

fn configured<'a>(state: &'a State, ca: &str) -> Result<&'a AuthorityConfig, WireError> {
    loaded(state)
        .authority(ca)
        .ok_or_else(|| WireError::new(ErrorCode::NotFound, format!("no CA {ca}")))
}

fn text(passphrase: &pkid_core::Passphrase) -> Result<&str, WireError> {
    std::str::from_utf8(passphrase.expose()).map_err(|_| bad("a passphrase must be UTF-8 text"))
}

fn existing(passphrase: Option<&pkid_core::Passphrase>) -> Result<Option<Passphrase>, WireError> {
    passphrase.map(|p| text(p).map(Passphrase::new)).transpose()
}

fn new_passphrase(passphrase: &pkid_core::Passphrase) -> Result<NewPassphrase, WireError> {
    NewPassphrase::new(text(passphrase)?).map_err(key_error)
}

fn algorithm(name: &str) -> Result<KeyAlgorithm, WireError> {
    Ok(match name {
        "ecdsa-p256" => KeyAlgorithm::EcdsaP256,
        "ecdsa-p384" => KeyAlgorithm::EcdsaP384,
        "rsa-2048" => KeyAlgorithm::Rsa2048,
        "rsa-3072" => KeyAlgorithm::Rsa3072,
        "rsa-4096" => KeyAlgorithm::Rsa4096,
        other => return Err(bad(format!("{other} is not a key algorithm"))),
    })
}

/// A new CA's identifier.
fn new_id() -> Result<String, WireError> {
    let mut bytes = [0u8; 16];
    peios_crypto::random::fill(&mut bytes).map_err(internal)?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    ))
}

/// Where a CA's key is to be kept, and how.
struct Placement<'a> {
    provider: &'a dyn KeyProvider,
    locator: String,
    exportable: bool,
    /// For a file key, the passphrase it is sealed under, as a new one and
    /// as one to open it again with.
    seal: Option<(NewPassphrase, Passphrase)>,
}

impl Placement<'_> {
    fn options(&self) -> KeyOptions<'_> {
        KeyOptions {
            exportable: self.exportable,
            passphrase: self.seal.as_ref().map(|(new, _)| new),
        }
    }

    fn opening(&self) -> Option<&Passphrase> {
        self.seal.as_ref().map(|(_, open)| open)
    }
}

fn placement<'a>(
    spec: &KeySpec,
    id: &str,
    services: &'a Services<'_>,
) -> Result<Placement<'a>, WireError> {
    let provider = services
        .providers
        .get(&spec.provider)
        .ok_or_else(|| bad(format!("no key provider {}", spec.provider)))?;
    let locator = match spec.provider.as_str() {
        "service" => id.to_string(),
        _ => spec
            .locator
            .clone()
            .ok_or_else(|| bad(format!("a {} key needs a locator", spec.provider)))?,
    };
    let seal = spec
        .passphrase
        .as_ref()
        .map(|passphrase| -> Result<_, WireError> {
            Ok((
                new_passphrase(passphrase)?,
                Passphrase::new(text(passphrase)?),
            ))
        })
        .transpose()?;
    Ok(Placement {
        provider,
        locator,
        exportable: spec.exportable,
        seal,
    })
}

/// A signer that holds only a public key, to check a certificate against a
/// key without opening it.
struct PublicOnly(PublicKey);

impl Signer for PublicOnly {
    fn public_key(&self) -> &PublicKey {
        &self.0
    }

    fn sign(&self, _: peios_crypto::SignatureScheme, _: &[u8]) -> peios_crypto::Result<Vec<u8>> {
        Err(peios_crypto::Error::Unsupported)
    }
}

fn subject_key(signer: &dyn Signer) -> Result<SubjectPublicKey, WireError> {
    SubjectPublicKey::from_der(signer.public_key().spki()).map_err(internal)
}

fn ca_profile(
    name: &str,
    lifetime_days: u32,
    path_length: Option<u8>,
    now: OffsetDateTime,
    limit: Option<OffsetDateTime>,
    crl_distribution_points: Vec<String>,
) -> Result<CaProfile, WireError> {
    if lifetime_days == 0 {
        return Err(bad("a CA must be valid for at least a day"));
    }
    let mut not_after = now + Duration::days(i64::from(lifetime_days));
    if let Some(limit) = limit {
        not_after = not_after.min(limit);
    }
    Ok(CaProfile {
        subject: CaSubject {
            common_name: name.trim().to_string(),
            attributes: Vec::new(),
        },
        validity: Validity::new(now - CLOCK_SKEW_ALLOWANCE, not_after)
            .map_err(|_| bad("the issuing CA expires too soon"))?,
        path_length,
        name_constraints: None,
        extended_key_usages: None,
        crl_distribution_points,
    })
}

/// The signer of a CA on this pkid, opened for this operation alone: a
/// service key as it is, a sealed key with `passphrase`.
pub(crate) fn signer_of(
    config: &AuthorityConfig,
    passphrase: Option<&pkid_core::Passphrase>,
    services: &Services<'_>,
) -> Result<OpenKey, WireError> {
    let passphrase = existing(passphrase)?;
    services
        .providers
        .for_key(&config.key)
        .and_then(|provider| provider.open(&config.key, passphrase.as_ref()))
        .map_err(key_error)
}

/// A subordinate CA certificate a CA on this pkid issued.
struct Subordinate<'a> {
    parent: &'a str,
    /// The subordinate's own request for it.
    request: Vec<u8>,
    name: &'a str,
    certificate: &'a [u8],
    profile: &'a CaProfile,
    serial: SerialNumber,
}

/// Records a subordinate CA certificate in its issuer's database, so that
/// it can be found and revoked like any other.
fn record_subordinate(
    state: &mut State,
    subordinate: Subordinate<'_>,
    caller: &dyn Principal,
    now: OffsetDateTime,
) -> Result<(), WireError> {
    let store = state
        .store
        .as_mut()
        .map_err(|reason| WireError::new(ErrorCode::Unavailable, reason.clone()))?;
    let new = NewRequest {
        ca: subordinate.parent.to_string(),
        template: SUBORDINATE_TEMPLATE.to_string(),
        csr: subordinate.request,
        names: vec![subordinate.name.to_string()],
        requester: caller.sid().clone(),
        subject: caller.snapshot().map_err(internal)?,
        submitted: now,
    };
    let issued = NewCertificate {
        serial: subordinate.serial,
        der: subordinate.certificate.to_vec(),
        not_before: subordinate.profile.validity.not_before(),
        not_after: subordinate.profile.validity.not_after(),
        owner: None,
    };
    store.record_issued(&new, &issued).map_err(internal)?;
    Ok(())
}

fn check_templates(state: &State, templates: &[String]) -> Result<Vec<String>, WireError> {
    let loaded = loaded(state);
    templates
        .iter()
        .map(|template| {
            let template = template.to_ascii_lowercase();
            if loaded.configuration.templates.contains_key(&template) {
                Ok(template)
            } else {
                Err(bad(format!("template {template} does not exist")))
            }
        })
        .collect()
}

fn record(
    name: &str,
    key: &KeyReference,
    certificate: Option<&[u8]>,
    request: Option<&[u8]>,
    templates: &[String],
    crl_distribution_points: &[String],
) -> Values {
    let mut values = Values::new();
    values.insert("Name", RegData::Sz(name.trim().to_string()));
    values.insert("Key", RegData::Sz(key.to_string()));
    if let Some(certificate) = certificate {
        values.insert("Certificate", RegData::Binary(certificate.to_vec()));
    }
    if let Some(request) = request {
        values.insert("Request", RegData::Binary(request.to_vec()));
    }
    values.insert("Templates", RegData::MultiSz(templates.to_vec()));
    values.insert(
        "CrlDistributionPoints",
        RegData::MultiSz(crl_distribution_points.to_vec()),
    );
    values
}

/// A key made for a CA that isn't recorded yet. It is destroyed unless the
/// CA's record is written, so a failed creation leaves behind no key that
/// nothing refers to, and that, if it isn't exportable, nobody could reach.
struct Provisional<'a> {
    provider: &'a dyn KeyProvider,
    key: Option<KeyReference>,
}

impl<'a> Provisional<'a> {
    fn new(provider: &'a dyn KeyProvider, key: KeyReference) -> Self {
        Self {
            provider,
            key: Some(key),
        }
    }

    fn key(&self) -> &KeyReference {
        self.key
            .as_ref()
            .expect("a provisional key is held until kept")
    }

    /// The CA's record refers to the key now: keep it.
    fn keep(mut self) {
        self.key = None;
    }
}

impl Drop for Provisional<'_> {
    fn drop(&mut self) {
        if let Some(key) = self.key.take() {
            if let Err(error) = self.provider.delete(&key) {
                eprintln!("pkid: can't remove {key}, made for a CA that wasn't created: {error}");
            }
        }
    }
}

/// A change to one CA's record.
struct Change<'a> {
    id: &'a str,
    values: Values,
    remove: &'a [&'a str],
    action: &'static str,
}

/// Writes a CA's record and takes up the configuration it makes, replying
/// with the CA as it now stands. A `provisional` key is kept once the
/// record that refers to it is written.
fn commit(
    state: &mut State,
    services: &Services<'_>,
    caller: &dyn Principal,
    change: Change<'_>,
    provisional: Option<Provisional<'_>>,
) -> Result<Reply, WireError> {
    let Change {
        id,
        values,
        remove,
        action,
    } = change;
    services
        .configurator
        .write_authority(id, &values, remove)
        .map_err(internal)?;
    if let Some(provisional) = provisional {
        provisional.keep();
    }
    crate::dispatch::apply(state, services.configurator.read(), services);
    services.audit.record(Event::Managed {
        ca: id.to_string(),
        action,
        operator: caller.sid().clone(),
    });
    let loaded = state.loaded.as_ref().map_err(|reason| {
        WireError::new(
            ErrorCode::Unavailable,
            format!("the configuration is now invalid: {reason}"),
        )
    })?;
    let config = loaded
        .authority(id)
        .ok_or_else(|| internal(format!("CA {id} was written but isn't configured")))?;
    Ok(Reply::Authority(authority_info(
        loaded,
        &state.keys,
        state.store.as_ref().ok(),
        config,
        caller,
    )?))
}

pub fn handle(
    state: &mut State,
    request: Request,
    caller: &dyn Principal,
    services: &Services<'_>,
    now: OffsetDateTime,
) -> Result<Reply, WireError> {
    match request {
        Request::CreateAuthority {
            name,
            key,
            issuer,
            lifetime_days,
            path_length,
            templates,
            crl_distribution_points,
        } => {
            require(caller, &loaded(state).manage_security, CA_MANAGE)?;
            let parent = match &issuer {
                Issuer::Authority { ca, passphrase } => {
                    let parent = configured(state, ca)?.clone();
                    require(caller, &parent.security, CA_MANAGE)?;
                    let certificate = parent
                        .certificate
                        .clone()
                        .ok_or_else(|| bad(format!("CA {ca} awaits its certificate")))?;
                    let signer = signer_of(&parent, passphrase.as_ref(), services)?;
                    Some((parent, certificate, signer))
                }
                _ => None,
            };
            let templates = check_templates(state, &templates)?;
            let algorithm = algorithm(
                key.algorithm
                    .as_deref()
                    .ok_or_else(|| bad("a new key needs an algorithm"))?,
            )?;
            let id = new_id()?;
            let place = placement(&key, &id, services)?;
            let reference = place
                .provider
                .generate(&place.locator, algorithm, &place.options())
                .map_err(key_error)?;
            let provisional = Provisional::new(place.provider, reference);
            let signer = place
                .provider
                .open(provisional.key(), place.opening())
                .map_err(key_error)?;

            let (certificate, request) = match (&issuer, parent) {
                (Issuer::SelfSigned, _) => {
                    let profile =
                        ca_profile(&name, lifetime_days, path_length, now, None, Vec::new())?;
                    let serial = SerialNumber::random().map_err(internal)?;
                    let root = create_root(signer.as_ref(), &profile, &serial).map_err(internal)?;
                    (Some(root.der().to_vec()), None)
                }
                (Issuer::Offline, _) => {
                    let subject = CaSubject {
                        common_name: name.trim().to_string(),
                        attributes: Vec::new(),
                    };
                    let request = ca_request(signer.as_ref(), &subject).map_err(internal)?;
                    (None, Some(request))
                }
                (Issuer::Authority { .. }, Some((parent, parent_certificate, parent_signer))) => {
                    let issuing = IssuingCa::new(&parent_certificate, parent_signer.as_ref())
                        .map_err(internal)?;
                    let profile = ca_profile(
                        &name,
                        lifetime_days,
                        path_length,
                        now,
                        Some(issuing.validity().not_after()),
                        parent.crl_distribution_points.clone(),
                    )?;
                    let serial = SerialNumber::random().map_err(internal)?;
                    let certificate = issuing
                        .issue_ca(&subject_key(signer.as_ref())?, &profile, &serial)
                        .map_err(|error| bad(error.to_string()))?;
                    let request =
                        ca_request(signer.as_ref(), &profile.subject).map_err(internal)?;
                    record_subordinate(
                        state,
                        Subordinate {
                            parent: &parent.id,
                            request,
                            name: &name,
                            certificate: certificate.der(),
                            profile: &profile,
                            serial,
                        },
                        caller,
                        now,
                    )?;
                    (Some(certificate.der().to_vec()), None)
                }
                (Issuer::Authority { .. }, None) => unreachable!("the parent was resolved"),
            };
            let values = record(
                &name,
                provisional.key(),
                certificate.as_deref(),
                request.as_deref(),
                &templates,
                &crl_distribution_points,
            );
            let change = Change {
                id: &id,
                values,
                remove: &[],
                action: "created",
            };
            commit(state, services, caller, change, Some(provisional))
        }

        Request::SignSubordinate {
            ca,
            csr,
            name,
            lifetime_days,
            path_length,
            passphrase,
        } => {
            let parent = configured(state, &ca)?.clone();
            require(caller, &parent.security, CA_MANAGE)?;
            let parent_certificate = parent
                .certificate
                .clone()
                .ok_or_else(|| bad(format!("CA {ca} awaits its certificate")))?;
            let key = ca_request_key(&csr).map_err(|error| bad(error.to_string()))?;
            let signer = signer_of(&parent, passphrase.as_ref(), services)?;
            let issuing = IssuingCa::new(&parent_certificate, signer.as_ref()).map_err(internal)?;
            let profile = ca_profile(
                &name,
                lifetime_days,
                path_length,
                now,
                Some(issuing.validity().not_after()),
                parent.crl_distribution_points.clone(),
            )?;
            let serial = SerialNumber::random().map_err(internal)?;
            let certificate = issuing
                .issue_ca(&key, &profile, &serial)
                .map_err(|error| bad(error.to_string()))?;
            record_subordinate(
                state,
                Subordinate {
                    parent: &ca,
                    request: csr,
                    name: &name,
                    certificate: certificate.der(),
                    profile: &profile,
                    serial,
                },
                caller,
                now,
            )?;
            services.audit.record(Event::Managed {
                ca,
                action: "signed-subordinate",
                operator: caller.sid().clone(),
            });
            Ok(Reply::Signed(certificate.der().to_vec()))
        }

        Request::InstallAuthority { ca, certificate } => {
            let config = configured(state, &ca)?.clone();
            require(caller, &config.security, CA_MANAGE)?;
            if config.certificate.is_some() {
                return Err(WireError::new(
                    ErrorCode::Conflict,
                    format!("CA {ca} already has its certificate"),
                ));
            }
            let provider = services.providers.for_key(&config.key).map_err(key_error)?;
            let public = provider
                .describe(&config.key)
                .map_err(key_error)?
                .public_key;
            IssuingCa::new(&certificate, &PublicOnly(public))
                .map_err(|error| bad(format!("not this CA's certificate: {error}")))?;
            let values = record(
                &config.name,
                &config.key,
                Some(&certificate),
                None,
                &config.templates,
                &config.crl_distribution_points,
            );
            let change = Change {
                id: &ca,
                values,
                remove: &["Request"],
                action: "installed",
            };
            commit(state, services, caller, change, None)
        }

        Request::ImportAuthority {
            name,
            certificate,
            sealed_key,
            passphrase,
            key,
            templates,
            crl_distribution_points,
        } => {
            require(caller, &loaded(state).manage_security, CA_MANAGE)?;
            let templates = check_templates(state, &templates)?;
            let private: PrivateKey =
                open_sealed_key(&sealed_key, &Passphrase::new(text(&passphrase)?))
                    .map_err(key_error)?;
            IssuingCa::new(&certificate, &private)
                .map_err(|error| bad(format!("not this key's CA certificate: {error}")))?;
            let id = new_id()?;
            let place = placement(&key, &id, services)?;
            let reference = place
                .provider
                .import(&place.locator, &private, &place.options())
                .map_err(key_error)?;
            let provisional = Provisional::new(place.provider, reference);
            let values = record(
                &name,
                provisional.key(),
                Some(&certificate),
                None,
                &templates,
                &crl_distribution_points,
            );
            let change = Change {
                id: &id,
                values,
                remove: &[],
                action: "imported",
            };
            commit(state, services, caller, change, Some(provisional))
        }

        Request::ExportKey {
            ca,
            current,
            passphrase,
        } => {
            let config = configured(state, &ca)?.clone();
            require(caller, &config.security, CA_MANAGE)?;
            let provider = services.providers.for_key(&config.key).map_err(key_error)?;
            let sealed = provider
                .export(
                    &config.key,
                    existing(current.as_ref())?.as_ref(),
                    &new_passphrase(&passphrase)?,
                )
                .map_err(key_error)?;
            services.audit.record(Event::Managed {
                ca,
                action: "exported-key",
                operator: caller.sid().clone(),
            });
            Ok(Reply::SealedKey(sealed))
        }

        Request::ConfigureAuthority {
            ca,
            templates,
            crl_distribution_points,
            crl_lifetime_days,
        } => {
            let config = configured(state, &ca)?.clone();
            require(caller, &config.security, CA_MANAGE)?;
            let templates = match templates {
                Some(templates) => check_templates(state, &templates)?,
                None => config.templates.clone(),
            };
            let mut values = record(
                &config.name,
                &config.key,
                config.certificate.as_deref(),
                config.request.as_deref(),
                &templates,
                crl_distribution_points
                    .as_deref()
                    .unwrap_or(&config.crl_distribution_points),
            );
            if let Some(days) = crl_lifetime_days {
                if !(1..=MAX_CRL_LIFETIME_DAYS).contains(&days) {
                    return Err(bad(format!(
                        "a CRL lifetime is 1 to {MAX_CRL_LIFETIME_DAYS} days"
                    )));
                }
                values.insert("CrlLifetimeDays", RegData::Dword(days));
            }
            let change = Change {
                id: &ca,
                values,
                remove: &[],
                action: "configured",
            };
            commit(state, services, caller, change, None)
        }

        Request::SetAuthoritySecurity { ca, security } => {
            let config = configured(state, &ca)?.clone();
            require(caller, &config.security, CA_MANAGE)?;
            let security = SecurityBlob::new(security);
            caller
                .checker()
                .validate(&security)
                .map_err(|error| bad(error.to_string()))?;
            let mut values = Values::new();
            values.insert("CaSecurity", RegData::Binary(security.as_bytes().to_vec()));
            let change = Change {
                id: &ca,
                values,
                remove: &[],
                action: "secured",
            };
            commit(state, services, caller, change, None)
        }

        _ => unreachable!("routed by dispatch::handle"),
    }
}
