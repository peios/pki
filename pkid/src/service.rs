//! Starting pkid, keeping its configuration current, and telling peinit
//! it is ready.

use std::collections::HashMap;
use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use peios::security::sddl;
use pki_keys::{KeyFileProvider, KeyProviders, ServiceKeyProvider};
use pki_pipeline::DEFAULT_CA_SDDL;
use pki_policy::SecurityBlob;
use pki_store::Store;
use pkid_core::SERVICE_SID;

use crate::config::{Defaults, DEFAULT_MANAGE_SDDL};
use crate::dispatch::{apply, Configurator, Services, State};
use crate::events::EventLog;
use crate::identity::LocalDirectory;
use crate::keystore::ServiceKeyFiles;
use crate::registry::{self, RegistryConfigurator};

pub use pki_management::{DATABASE, KEYS_DIR, STATE_DIR};

/// How often pkid re-reads its configuration while it can't watch it.
const REVALIDATE: Duration = Duration::from_secs(60);

fn binary_sd(text: &str) -> SecurityBlob {
    let sd = sddl::parse(text).expect("pkid's default descriptors parse");
    SecurityBlob::new(sd.as_bytes().to_vec())
}

/// The binary forms of pkid's default descriptors.
pub fn defaults() -> Defaults {
    Defaults {
        ca_security: binary_sd(DEFAULT_CA_SDDL),
        manage_security: binary_sd(DEFAULT_MANAGE_SDDL),
    }
}

/// The binary form of `DEFAULT_CA_SDDL`.
pub fn default_ca_security() -> SecurityBlob {
    defaults().ca_security
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

/// What every request and reload shares.
pub struct Runtime {
    pub providers: KeyProviders,
    pub defaults: Defaults,
}

impl Runtime {
    pub fn new() -> Self {
        Self {
            providers: providers(),
            defaults: defaults(),
        }
    }

    /// pkid's services on this machine.
    pub fn services(&self) -> Services<'_> {
        Services {
            directory: &LocalDirectory,
            audit: &EventLog,
            configurator: &RegistryConfigurator,
            providers: &self.providers,
            defaults: &self.defaults,
        }
    }
}

impl Default for Runtime {
    fn default() -> Self {
        Self::new()
    }
}

/// pkid's state as it starts, with its configuration loaded.
pub fn start(runtime: &Runtime) -> Arc<Mutex<State>> {
    let store = Store::open(Path::new(DATABASE)).map_err(|error| error.to_string());
    if let Err(error) = &store {
        eprintln!("pkid: the CA database: {error}");
    }
    let state = Arc::new(Mutex::new(State {
        store,
        loaded: Err("not loaded yet".into()),
        keys: HashMap::new(),
        source: None,
    }));
    refresh(&state, runtime);
    state
}

/// Re-reads the configuration and takes it up if it changed.
pub fn refresh(state: &Mutex<State>, runtime: &Runtime) {
    let source = RegistryConfigurator.read();
    if let Err(error) = &source {
        eprintln!("pkid: configuration: {error}");
    }
    let Ok(mut state) = state.lock() else {
        return;
    };
    // pkid may have started before `pki setup` created its state directory;
    // setup's Registry writes bring it here to try again.
    if state.store.is_err() {
        if let Ok(store) = Store::open(Path::new(DATABASE)) {
            state.store = Ok(store);
        }
    }
    apply(&mut state, source, &runtime.services());
    if let Err(error) = &state.loaded {
        eprintln!("pkid: configuration: {error}");
    }
}

/// Keeps `state`'s configuration current, on every change to the subtree.
/// While the subtree can't be watched, such as before it exists, pkid
/// re-reads it every [`REVALIDATE`] instead.
pub fn watch(state: Arc<Mutex<State>>, runtime: Arc<Runtime>) {
    loop {
        match registry::Watch::new() {
            Ok(watch) => loop {
                if let Err(error) = watch.wait() {
                    eprintln!("pkid: watching the configuration: {error}");
                    break;
                }
                refresh(&state, &runtime);
            },
            Err(error) => {
                eprintln!(
                    "pkid: can't watch the configuration ({error}); re-reading it periodically"
                );
            }
        }
        std::thread::sleep(REVALIDATE);
        refresh(&state, &runtime);
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
