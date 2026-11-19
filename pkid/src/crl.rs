//! CRLs: when each CA's is due, signing it, and publishing it.
//!
//! A CA whose key pkid keeps signs a new CRL after every revocation and at
//! half its lifetime. A CA whose key is in a sealed file can't sign
//! unattended: an officer brings its passphrase with `publish-crl`, and pkid
//! warns well before its CRL expires. Each CRL signed is recorded in the
//! database, which numbers them, and handed to every publisher.

use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use pki_pipeline::{Authority, Pipeline, Principal};
use pki_store::{Crl, Store};
use pkid_core::{CrlInfo, ErrorCode, Passphrase, Reply, WireError};
use time::{Duration, OffsetDateTime};

use crate::config::{AuthorityConfig, Loaded};
use crate::dispatch::{authority, wire, Event, Services, State};

/// How long before a CRL expires pkid starts warning.
pub const WARN_BEFORE: Duration = Duration::days(30);
/// How often a warning about the same CA is repeated.
const WARN_EVERY: Duration = Duration::days(1);

/// Where a CA's CRLs go once signed.
pub trait Publisher: Send + Sync {
    /// Publishes `crl`, the CA's latest, for its distribution points.
    fn publish(&self, ca: &AuthorityConfig, crl: &[u8]) -> Result<(), String>;
}

/// pkid's memory of what it has published and warned about, which is only
/// needed while it runs: a restart publishes everything again.
#[derive(Debug, Default)]
pub struct Publication {
    /// The number of each CA's CRL last handed to every publisher.
    published: HashMap<String, u64>,
    /// When each CA was last warned about.
    warned: HashMap<String, OffsetDateTime>,
}

/// The URL path of an `http` distribution point, as a relative file path,
/// or nothing for one this publisher can't serve. Only plain path segments
/// are accepted, so a path can never leave the folder it is served from.
pub fn http_path(url: &str) -> Option<PathBuf> {
    let rest = url
        .get(..7)
        .filter(|scheme| scheme.eq_ignore_ascii_case("http://"))
        .map(|_| &url[7..])?;
    let (_, path) = rest.split_once('/')?;
    if path.is_empty() || path.contains(['?', '#', '%', '\\']) {
        return None;
    }
    let mut relative = PathBuf::new();
    for segment in path.split('/') {
        let plain = !segment.is_empty()
            && segment != "."
            && segment != ".."
            && !segment.starts_with('.')
            && segment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-~".contains(&byte));
        if !plain {
            return None;
        }
        relative.push(segment);
    }
    Some(relative)
}

/// Publishes CRLs as files under a folder, at the URL paths of their CAs'
/// `http` distribution points, for pki-httpd to serve.
pub struct HttpFolder {
    root: PathBuf,
}

impl HttpFolder {
    pub fn new(root: &Path) -> Self {
        Self {
            root: root.to_owned(),
        }
    }

    /// Replaces `relative`'s contents whole, so a reader never sees half a
    /// CRL.
    fn write(&self, relative: &Path, contents: &[u8]) -> io::Result<()> {
        let path = self.root.join(relative);
        let directory = path.parent().unwrap_or(&self.root);
        fs::create_dir_all(directory)?;
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        let staging = directory.join(format!(".{name}.{}", std::process::id()));
        let written = fs::File::create(&staging).and_then(|mut file| {
            file.write_all(contents)?;
            file.sync_all()
        });
        if let Err(error) = written.and_then(|()| fs::rename(&staging, &path)) {
            let _ = fs::remove_file(&staging);
            return Err(error);
        }
        Ok(())
    }
}

impl Publisher for HttpFolder {
    fn publish(&self, ca: &AuthorityConfig, crl: &[u8]) -> Result<(), String> {
        let mut failures = Vec::new();
        for url in &ca.crl_distribution_points {
            let Some(relative) = http_path(url) else {
                continue;
            };
            if let Err(error) = self.write(&relative, crl) {
                failures.push(format!("{url}: {error}"));
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("; "))
        }
    }
}

fn info(crl: &Crl) -> CrlInfo {
    CrlInfo {
        number: crl.number,
        this_update: crl.this_update.unix_timestamp(),
        next_update: crl.next_update.unix_timestamp(),
    }
}

/// The CA's latest CRL, as the wire describes it.
pub fn latest(store: Option<&Store>, ca: &str) -> Option<CrlInfo> {
    store?.crl(ca).ok().flatten().as_ref().map(info)
}

fn lifetime(config: &AuthorityConfig) -> Duration {
    Duration::days(i64::from(config.crl_lifetime_days))
}

/// Whether the CA needs a new CRL: it has none, it has revoked something
/// since its last, or its last is half way through its life.
fn due(store: &Store, ca: &str, current: Option<&Crl>, now: OffsetDateTime) -> bool {
    let Some(crl) = current else {
        return true;
    };
    let half = crl.this_update + (crl.next_update - crl.this_update) / 2;
    now >= half || store.revoked_since(ca, crl.this_update).unwrap_or(true)
}

/// Hands `crl` to every publisher, and remembers it unless one failed, so
/// that the next round tries again.
fn publish(
    publication: &mut Publication,
    config: &AuthorityConfig,
    crl: &Crl,
    services: &Services<'_>,
) {
    let mut published = true;
    for publisher in services.publishers {
        if let Err(error) = publisher.publish(config, &crl.der) {
            eprintln!(
                "pkid: publishing CA {}'s CRL {}: {error}",
                config.id, crl.number
            );
            published = false;
        }
    }
    if published {
        publication.published.insert(config.id.clone(), crl.number);
    }
}

/// Signs, records and publishes a CRL for `config` with `ca`'s signer.
#[allow(clippy::too_many_arguments)]
fn sign(
    store: &mut Store,
    loaded: &Loaded,
    publication: &mut Publication,
    config: &AuthorityConfig,
    ca: &Authority<'_>,
    officer: Option<&dyn Principal>,
    services: &Services<'_>,
    now: OffsetDateTime,
) -> Result<Crl, WireError> {
    let mut pipeline = Pipeline::new(store, &loaded.configuration, services.directory);
    let crl = match officer {
        Some(officer) => pipeline.publish_crl(ca, officer, now, lifetime(config)),
        None => pipeline.issue_crl(ca, now, lifetime(config)),
    }
    .map_err(wire)?;
    services.audit.record(Event::CrlPublished {
        ca: config.id.clone(),
        number: crl.number,
        next_update: crl.next_update.unix_timestamp(),
        officer: officer.map(|officer| officer.sid().clone()),
    });
    publish(publication, config, &crl, services);
    Ok(crl)
}

/// Brings every CA's CRL up to date, as pkid's schedule does: signs those
/// due whose keys pkid keeps, publishes again any not yet published, and
/// warns about those close to expiry.
pub fn maintain(state: &mut State, services: &Services<'_>, now: OffsetDateTime) {
    let State {
        store,
        loaded,
        keys,
        publication,
        ..
    } = state;
    let (Ok(store), Ok(loaded)) = (store.as_mut(), loaded.as_ref()) else {
        return;
    };
    for config in &loaded.authorities {
        let Ok(ca) = authority(config, keys) else {
            // Awaiting its certificate: it has issued nothing to revoke.
            continue;
        };
        let mut current = store.crl(&config.id).ok().flatten();
        if ca.signer.is_some() && due(store, &config.id, current.as_ref(), now) {
            match sign(store, loaded, publication, config, &ca, None, services, now) {
                Ok(crl) => current = Some(crl),
                Err(error) => {
                    eprintln!("pkid: CA {}'s CRL: {}", config.id, error.message);
                }
            }
        } else if let Some(crl) = &current {
            if publication.published.get(&config.id) != Some(&crl.number) {
                publish(publication, config, crl, services);
            }
        }
        let renews_itself = ca.signer.is_some();
        warn(
            publication,
            config,
            current.as_ref(),
            renews_itself,
            services,
            now,
        );
    }
}

/// Warns, at most daily, about a CA whose CRL is running out. A CA whose
/// key pkid keeps renews its own at half its life, so it is warned about
/// only once renewal has evidently failed, three quarters of the way. A CA
/// whose key is sealed is warned about from [`WARN_BEFORE`] its expiry, so
/// that an officer has time to bring its passphrase. Either is warned about
/// if it has distribution points but no CRL.
fn warn(
    publication: &mut Publication,
    config: &AuthorityConfig,
    current: Option<&Crl>,
    renews_itself: bool,
    services: &Services<'_>,
    now: OffsetDateTime,
) {
    let next_update = match current {
        Some(crl) => {
            let warn_from = if renews_itself {
                crl.next_update - (crl.next_update - crl.this_update) / 4
            } else {
                crl.next_update - WARN_BEFORE
            };
            if now < warn_from {
                publication.warned.remove(&config.id);
                return;
            }
            Some(crl.next_update.unix_timestamp())
        }
        None if config.crl_distribution_points.is_empty() => return,
        None => None,
    };
    let recent = publication
        .warned
        .get(&config.id)
        .is_some_and(|last| now - *last < WARN_EVERY);
    if recent {
        return;
    }
    publication.warned.insert(config.id.clone(), now);
    services.audit.record(Event::CrlExpiring {
        ca: config.id.clone(),
        next_update,
    });
}

/// An officer's `publish-crl`: signs a new CRL now, opening a sealed key
/// with `passphrase` for this operation alone.
pub fn handle_publish(
    state: &mut State,
    ca_id: &str,
    passphrase: Option<&Passphrase>,
    caller: &dyn Principal,
    services: &Services<'_>,
    now: OffsetDateTime,
) -> Result<Reply, WireError> {
    let State {
        store,
        loaded,
        keys,
        publication,
        ..
    } = state;
    let (Ok(store), Ok(loaded)) = (store.as_mut(), loaded.as_ref()) else {
        unreachable!("checked by handle");
    };
    let config = loaded
        .authority(ca_id)
        .ok_or_else(|| WireError::new(ErrorCode::NotFound, format!("no CA {ca_id}")))?;
    // A key pkid keeps is used as it is; a sealed one is opened now.
    let opened = if keys.contains_key(ca_id) {
        None
    } else {
        Some(crate::manage::signer_of(config, passphrase, services)?)
    };
    let mut ca = authority(config, keys)?;
    if let Some(key) = &opened {
        ca.signer = Some(key.as_ref() as &dyn peios_crypto::Signer);
    }
    let crl = sign(
        store,
        loaded,
        publication,
        config,
        &ca,
        Some(caller),
        services,
        now,
    )?;
    Ok(Reply::Crl(info(&crl)))
}

/// Signs and publishes a CRL straight after a revocation, when the CA's
/// key is to hand; otherwise the CA's officers renew it with `publish-crl`.
pub fn after_revocation(
    state: &mut State,
    ca_id: &str,
    services: &Services<'_>,
    now: OffsetDateTime,
) {
    let State {
        store,
        loaded,
        keys,
        publication,
        ..
    } = state;
    let (Ok(store), Ok(loaded)) = (store.as_mut(), loaded.as_ref()) else {
        return;
    };
    let Some(config) = loaded.authority(ca_id) else {
        return;
    };
    let Ok(ca) = authority(config, keys) else {
        return;
    };
    if ca.signer.is_none() {
        return;
    }
    if let Err(error) = sign(store, loaded, publication, config, &ca, None, services, now) {
        // The schedule tries again: the revocation is newer than any CRL.
        eprintln!(
            "pkid: CA {ca_id}'s CRL after a revocation: {}",
            error.message
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_plain_http_paths_are_published() {
        assert_eq!(
            http_path("http://pki.home/crl/issuing.crl"),
            Some(PathBuf::from("crl/issuing.crl"))
        );
        assert_eq!(
            http_path("HTTP://pki.home:8080/root.crl"),
            Some(PathBuf::from("root.crl"))
        );
        for refused in [
            "https://pki.home/root.crl",
            "ldap://pki.home/cn=root",
            "http://pki.home",
            "http://pki.home/",
            "http://pki.home/../etc/passwd",
            "http://pki.home/crl/./root.crl",
            "http://pki.home/crl//root.crl",
            "http://pki.home/.hidden",
            "http://pki.home/root.crl?x=1",
            "http://pki.home/root%2Ecrl",
            "http://pki.home/a\\b.crl",
        ] {
            assert_eq!(http_path(refused), None, "{refused}");
        }
    }
}
