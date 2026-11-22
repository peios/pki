//! What pki's commands reach outside themselves for: pkid, the Registry,
//! provisioning and the terminal. Tests stand in for all of it.

use std::io;

use peinit::client::{Command, ControlClient, Failure};
use pki_management::provision::{self, Boot, Seeded};
use pki_management::{registry, write, Snapshot};
use pki_policy::Values;
use pkid_client::{Client, ClientError};
use pkid_core::{Reply, Request};
use zeroize::Zeroizing;

use crate::secret;

pub trait Host {
    /// Sends one request to pkid.
    fn call(&self, request: &Request) -> Result<Reply, ClientError>;

    /// Provisions this machine for pkid.
    fn setup(&self) -> io::Result<Seeded>;

    /// Has `service` start at boot, unless it has Triggers already.
    fn start_at_boot(&self, service: &str) -> io::Result<Boot>;

    /// Has peinit start `service`, as the person. Says why it couldn't.
    fn start(&self, service: &str) -> Result<(), String>;

    /// Asks for a passphrase without echoing it.
    fn prompt(&self, question: &str) -> io::Result<Zeroizing<String>>;

    /// The configuration under `Machine\Software\Pki`, in one snapshot.
    fn snapshot(&self) -> io::Result<Snapshot>;

    /// Changes the existing key `path`.
    fn change(&self, path: &str, set: &Values, remove: &[&str]) -> io::Result<()>;

    /// Changes `path`, creating it if it is missing.
    fn put(&self, path: &str, set: &Values, remove: &[&str]) -> io::Result<()>;

    /// Creates `path`, which mustn't exist, with `set`.
    fn create(&self, path: &str, set: &Values) -> io::Result<()>;

    /// Deletes `path`, which must have no keys below it.
    fn delete(&self, path: &str) -> io::Result<()>;

    fn new_guid(&self) -> io::Result<String>;

    /// Tells the reader something worth knowing that doesn't stop the
    /// command.
    fn warn(&self, warning: &str);
}

/// The running system.
pub struct Live {
    client: Client,
}

impl Live {
    pub fn new() -> Self {
        Self {
            client: Client::new(),
        }
    }
}

impl Host for Live {
    fn call(&self, request: &Request) -> Result<Reply, ClientError> {
        self.client.call(request)
    }

    fn setup(&self) -> io::Result<Seeded> {
        provision::state_directories()?;
        provision::registry()
    }

    fn start_at_boot(&self, service: &str) -> io::Result<Boot> {
        provision::start_at_boot(service)
    }

    fn start(&self, service: &str) -> Result<(), String> {
        let mut client = ControlClient::connect_default().map_err(|error| error.to_string())?;
        match client.command(Command::Start, service) {
            Ok(_) => Ok(()),
            Err(Failure::Refused { code, .. }) if code == "ACCESS_DENIED" => {
                Err("you don't have permission to start it".into())
            }
            Err(Failure::Refused { message, .. }) => Err(message),
            Err(Failure::Unreachable(why)) => Err(why),
        }
    }

    fn prompt(&self, question: &str) -> io::Result<Zeroizing<String>> {
        secret::prompt(question)
    }

    fn snapshot(&self) -> io::Result<Snapshot> {
        registry::read()
    }

    fn change(&self, path: &str, set: &Values, remove: &[&str]) -> io::Result<()> {
        write::change(path, set, remove)
    }

    fn put(&self, path: &str, set: &Values, remove: &[&str]) -> io::Result<()> {
        write::put(path, set, remove)
    }

    fn create(&self, path: &str, set: &Values) -> io::Result<()> {
        write::create(path, set)
    }

    fn delete(&self, path: &str) -> io::Result<()> {
        write::delete(path)
    }

    fn new_guid(&self) -> io::Result<String> {
        pki_management::new_guid()
    }

    fn warn(&self, warning: &str) {
        eprintln!("pki: warning: {warning}");
    }
}
