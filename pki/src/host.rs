//! What pki's commands reach outside themselves for: pkid, the Registry,
//! provisioning and the terminal. Tests stand in for all of it.

use std::io;

use pki_management::provision::{self, Seeded};
use pki_management::registry;
use pkid_client::{Client, ClientError};
use pkid_core::{Reply, Request};
use zeroize::Zeroizing;

use crate::secret;

/// A template as the Registry names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemplateName {
    pub id: String,
    pub name: String,
}

pub trait Host {
    /// Sends one request to pkid.
    fn call(&self, request: &Request) -> Result<Reply, ClientError>;

    /// The templates configured, so that commands can take their names.
    fn templates(&self) -> io::Result<Vec<TemplateName>>;

    /// Provisions this machine for pkid.
    fn setup(&self) -> io::Result<Seeded>;

    /// Asks for a passphrase without echoing it.
    fn prompt(&self, question: &str) -> io::Result<Zeroizing<String>>;
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

    fn templates(&self) -> io::Result<Vec<TemplateName>> {
        Ok(registry::read()?
            .templates
            .into_iter()
            .map(|(id, values)| TemplateName {
                name: values.sz("Name").ok().flatten().unwrap_or("").to_owned(),
                id,
            })
            .collect())
    }

    fn setup(&self) -> io::Result<Seeded> {
        provision::state_directories()?;
        provision::registry()
    }

    fn prompt(&self, question: &str) -> io::Result<Zeroizing<String>> {
        secret::prompt(question)
    }
}
