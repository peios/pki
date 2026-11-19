//! Starting pkid, keeping its configuration current, and telling peinit
//! it is ready.

use std::collections::HashMap;
use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use peios::security::sddl;
use pki_keys::{KeyFileProvider, KeyProviders, OpenKey, ServiceKeyProvider};
use pki_pipeline::DEFAULT_CA_SDDL;
use pki_policy::SecurityBlob;
use pki_store::Store;
use pkid_core::SERVICE_SID;

use crate::config::{self, Loaded};
use crate::dispatch::State;
use crate::events;
use crate::keystore::ServiceKeyFiles;
use crate::registry;

/// pkid's persistent state. An administrator provisions it; pkid doesn't
/// create it, since peinit gives services no state directory of their own.
pub const STATE_DIR: &str = "/var/state/pki";
/// The CA database.
pub const DATABASE: &str = "/var/state/pki/pkid.db";
/// Online CA keys, readable by pkid's service identity alone.
pub const KEYS_DIR: &str = "/var/state/pki/keys";

/// How often pkid re-reads its configuration even without a change notice,
/// in case a notice was lost.
const REVALIDATE: Duration = Duration::from_secs(60);

/// The binary form of `DEFAULT_CA_SDDL`.
pub fn default_ca_security() -> SecurityBlob {
    let sd = sddl::parse(DEFAULT_CA_SDDL).expect("the default CA descriptor parses");
    SecurityBlob::new(sd.as_bytes().to_vec())
}

/// The key providers pkid knows.
pub fn providers() -> KeyProviders {
    let mut providers = KeyProviders::new();
    providers
        .add(Box::new(KeyFileProvider::new()))
        .expect("provider names are distinct");
    providers
        .add(Box::new(ServiceKeyProvider::new(ServiceKeyFiles::new(
            Path::new(KEYS_DIR),
            SERVICE_SID,
        ))))
        .expect("provider names are distinct");
    providers
}

fn read_configuration() -> Result<Loaded, String> {
    let snapshot = registry::read().map_err(|error| format!("reading the Registry: {error}"))?;
    config::load(&snapshot, &default_ca_security()).map_err(|error| error.to_string())
}

/// Opens the keys of `loaded`'s CAs that need no passphrase, keeping those
/// in `previous` whose CA still uses the same key: a key an administrator
/// unlocked stays unlocked across a configuration change.
fn open_keys(
    loaded: &Loaded,
    previous_config: Option<&Loaded>,
    mut previous: HashMap<String, OpenKey>,
    providers: &KeyProviders,
) -> HashMap<String, OpenKey> {
    let mut keys = HashMap::new();
    for authority in &loaded.authorities {
        let unchanged = previous_config
            .and_then(|config| config.authority(&authority.id))
            .is_some_and(|old| old.key == authority.key);
        if unchanged {
            if let Some(key) = previous.remove(&authority.id) {
                keys.insert(authority.id.clone(), key);
                continue;
            }
        }
        let opened = providers
            .for_key(&authority.key)
            .and_then(|provider| provider.open(&authority.key, None));
        match opened {
            Ok(key) => {
                keys.insert(authority.id.clone(), key);
            }
            Err(pki_keys::KeyError::Locked) => {}
            Err(error) => eprintln!("pkid: CA {}: its key: {error}", authority.id),
        }
    }
    keys
}

/// pkid's state as it starts.
pub fn start(providers: &KeyProviders) -> State {
    let store = Store::open(Path::new(DATABASE)).map_err(|error| error.to_string());
    if let Err(error) = &store {
        eprintln!("pkid: the CA database: {error}");
    }
    let loaded = read_configuration();
    events::configuration_loaded(loaded.as_ref().err().map(String::as_str));
    let keys = match &loaded {
        Ok(loaded) => open_keys(loaded, None, HashMap::new(), providers),
        Err(error) => {
            eprintln!("pkid: configuration: {error}");
            HashMap::new()
        }
    };
    State {
        store,
        loaded,
        keys,
    }
}

/// Re-reads the configuration and replaces it in `state`, whether or not it
/// is valid: an invalid configuration stops issuing rather than leaving the
/// last valid one in force.
pub fn reload(state: &Mutex<State>, providers: &KeyProviders) {
    let loaded = read_configuration();
    events::configuration_loaded(loaded.as_ref().err().map(String::as_str));
    let Ok(mut state) = state.lock() else {
        return;
    };
    let previous_keys = std::mem::take(&mut state.keys);
    state.keys = match &loaded {
        Ok(loaded) => open_keys(loaded, state.loaded.as_ref().ok(), previous_keys, providers),
        Err(error) => {
            eprintln!("pkid: configuration: {error}");
            HashMap::new()
        }
    };
    state.loaded = loaded;
}

/// Keeps `state`'s configuration current: on every change to the subtree,
/// and every [`REVALIDATE`] regardless.
pub fn watch(state: Arc<Mutex<State>>) {
    let providers = providers();
    loop {
        match registry::Watch::new() {
            Ok(watch) => loop {
                if let Err(error) = watch.wait() {
                    eprintln!("pkid: watching the configuration: {error}");
                    break;
                }
                reload(&state, &providers);
            },
            Err(error) => {
                eprintln!(
                    "pkid: can't watch the configuration ({error}); re-reading it periodically"
                );
            }
        }
        std::thread::sleep(REVALIDATE);
        reload(&state, &providers);
    }
}

/// Tells peinit pkid is ready (PSPU §4.16). pkid is ready even with an
/// invalid configuration, so that it can say what is wrong.
pub fn notify_ready() {
    let Some(path) = std::env::var_os("NOTIFY_SOCKET") else {
        return;
    };
    let sent = UnixDatagram::unbound().and_then(|socket| socket.send_to(b"READY=1", path));
    if let Err(error) = sent {
        eprintln!("pkid: notify: {error}");
    }
}

/// Checks that pkid runs as its own service identity.
pub fn verify_identity() -> Result<(), String> {
    use peios::token::{Token, TokenAccess};
    let actor = Token::open_self(false, TokenAccess::QUERY)
        .and_then(|token| token.user())
        .map_err(|error| format!("can't read its own identity: {error}"))?;
    if actor.to_string() == SERVICE_SID {
        Ok(())
    } else {
        Err(format!(
            "runs as {actor}, not as its service identity {SERVICE_SID}"
        ))
    }
}
