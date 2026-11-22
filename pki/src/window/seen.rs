//! What the window shows, read away from its lock: pkid's authorities as
//! the person sees them, the configuration in the Registry, what the person
//! may change there, and the services.
//!
//! Nothing here guesses at authority. pkid says what the person holds at
//! each CA; each Registry key is opened with the access a change would
//! need; peinit says what the person may do with each service.

use std::collections::{BTreeMap, HashMap};
use std::io;

use auth_core::client::ident::Ident;
use auth_core::ident::{Fields, Key as IdentKey, Kind as IdentKind, Value};
use peios::registry::{Key, KeyAccess, OpenFlags};
use peios::security::SidRef;
use peios::token::{Token, TokenAccess};
use pki_management::names::NamePath;
use pki_management::{registry, Snapshot, ROOT};
use pki_policy::TreeKind;
use pkid_client::{Client, ClientError};
use pkid_core::{
    AuthorityInfo, CertificateInfo, CertificateQuery, ErrorCode, RequestInfo, RequestQuery,
    RequestStatus, MAX_LISTING,
};

use super::service::{self, Service};

/// pkid, as the person sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pkid {
    /// The CAs the person holds any right at. pkid leaves out the rest.
    pub authorities: Vec<AuthorityInfo>,
    /// Whether the person may create and import CAs.
    pub create: bool,
}

/// Why pkid can't be asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Trouble {
    /// Nothing answers on its socket: it isn't running.
    Down,
    /// It runs, but its configuration is invalid, so it serves nothing.
    Invalid(String),
    /// It runs, but its database can't be used.
    Database(String),
    /// Anything else, in pki's words.
    Failed(String),
}

/// Whether the person may change each part of the configuration, as the
/// Registry answered when asked for the access a change needs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct May {
    /// Create `Machine\Software\Pki`, or add what `pki setup` adds.
    pub setup: bool,
    /// Change `Settings`: the principal domains.
    pub settings: bool,
    /// Change `Http`: pki-httpd's port.
    pub http: bool,
    /// Add a template.
    pub add_template: bool,
    /// Change and delete each template, by GUID.
    pub templates: BTreeMap<String, Change>,
    /// Change, remove and add below each name's key, by key path.
    pub names: BTreeMap<String, Change>,
}

/// What may be done to one key.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Change {
    pub edit: bool,
    pub delete: bool,
    /// Create keys below it.
    pub add: bool,
}

/// Everything read in one look.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seen {
    pub pkid: Result<Pkid, Trouble>,
    /// The configuration, unless it can't be read.
    pub config: Result<Snapshot, String>,
    /// Whether `Machine\Software\Pki` exists.
    pub set_up: bool,
    pub may: May,
    pub pkid_service: Service,
    pub httpd_service: Service,
    /// Each issuing CA's requests waiting for an officer, newest first: all
    /// of them where the person may read everything, else their own.
    pub waiting: BTreeMap<String, Vec<RequestInfo>>,
    /// The port pki-httpd serves revocation lists on, unless it can't be
    /// read.
    pub http_port: Option<u16>,
    /// The requests the person made in the window that were held.
    pub held: Vec<super::held::Held>,
    /// Those of them issued since, with the first name each is for: their
    /// certificates are ready to save.
    pub ready: Vec<(super::held::Held, String)>,
}

impl Seen {
    pub fn authorities(&self) -> &[AuthorityInfo] {
        match &self.pkid {
            Ok(pkid) => &pkid.authorities,
            Err(_) => &[],
        }
    }

    pub fn authority(&self, id: &str) -> Option<&AuthorityInfo> {
        self.authorities().iter().find(|a| a.id == id)
    }
}

pub fn look() -> Seen {
    let client = Client::new();
    let pkid = match (client.authorities(), client.access()) {
        (Ok(authorities), Ok(access)) => Ok(Pkid {
            authorities,
            create: access.create,
        }),
        (Err(error), _) | (_, Err(error)) => Err(trouble(error)),
    };
    let set_up = match Key::open(None, ROOT, KeyAccess::QUERY_VALUE, OpenFlags::empty()) {
        Ok(_) => true,
        Err(error) => io::Error::from(error).kind() != io::ErrorKind::NotFound,
    };
    let config = registry::read().map_err(|error| pki_management::os_message(&error));
    let may = match &config {
        Ok(snapshot) => may(snapshot),
        Err(_) => May::default(),
    };
    let held = super::held::read();
    let mut waiting = BTreeMap::new();
    if let Ok(pkid) = &pkid {
        for authority in pkid.authorities.iter().filter(|a| a.certificate.is_some()) {
            if let Ok(requests) = requests(&authority.id, Some(RequestStatus::Pending)) {
                waiting.insert(authority.id.clone(), requests);
            }
        }
    }
    let may = May {
        setup: writable(ROOT, KeyAccess::SET_VALUE | KeyAccess::CREATE_SUB_KEY)
            || (!set_up && writable("Machine\\Software", KeyAccess::CREATE_SUB_KEY)),
        ..may
    };
    Seen {
        pkid,
        config,
        set_up,
        may,
        pkid_service: service::look(service::PKID),
        httpd_service: service::look(service::HTTPD),
        waiting,
        http_port: pki_management::provision::http_port().ok(),
        ready: ready(&held),
        held,
    }
}

/// The held requests that have been issued, each with its first name.
fn ready(held: &[super::held::Held]) -> Vec<(super::held::Held, String)> {
    let client = Client::new();
    held.iter()
        .rev()
        .take(32)
        .filter_map(|held| {
            let request = client.request(&held.ca, held.request).ok()?;
            (request.status == RequestStatus::Issued).then(|| {
                (
                    held.clone(),
                    request.names.first().cloned().unwrap_or_default(),
                )
            })
        })
        .collect()
}

/// Why pkid didn't answer, as the window tells it.
pub fn trouble(error: ClientError) -> Trouble {
    match error {
        ClientError::Unavailable(_) => Trouble::Down,
        ClientError::Refused(refusal) if refusal.code == ErrorCode::Unavailable => {
            let message = refusal.message;
            if let Some(reason) = message.strip_prefix("pkid's configuration is invalid: ") {
                Trouble::Invalid(reason.to_string())
            } else if let Some(reason) = message.strip_prefix("pkid's database is unavailable: ") {
                Trouble::Database(reason.to_string())
            } else {
                Trouble::Failed(message)
            }
        }
        other => Trouble::Failed(crate::failure::Failure::client(other).message),
    }
}

/// Whether the Registry gives the person `access` to `path`.
fn writable(path: &str, access: KeyAccess) -> bool {
    Key::open(None, path, access, OpenFlags::empty()).is_ok()
}

fn change(path: &str) -> Change {
    Change {
        edit: writable(path, KeyAccess::SET_VALUE),
        delete: writable(path, KeyAccess::DELETE),
        add: writable(path, KeyAccess::CREATE_SUB_KEY),
    }
}

fn may(snapshot: &Snapshot) -> May {
    let templates_key = format!("{ROOT}\\Templates");
    let mut names = BTreeMap::new();
    for (tree, nodes) in [
        (TreeKind::Dns, &snapshot.dns),
        (TreeKind::Principal, &snapshot.principals),
    ] {
        let root = NamePath::root(tree);
        names.insert(root.key(), change(&root.key()));
        for (path, _) in nodes {
            let name = NamePath {
                tree,
                path: path.clone(),
            };
            names.insert(name.key(), change(&name.key()));
        }
    }
    May {
        setup: false,
        settings: writable(&format!("{ROOT}\\Settings"), KeyAccess::SET_VALUE),
        http: writable(&format!("{ROOT}\\Http"), KeyAccess::SET_VALUE),
        add_template: writable(&templates_key, KeyAccess::CREATE_SUB_KEY),
        templates: snapshot
            .templates
            .iter()
            .map(|(id, _)| (id.clone(), change(&format!("{templates_key}\\{id}"))))
            .collect(),
        names,
    }
}

/// The person's own SID, to tell their own requests from others'.
pub fn me() -> Option<String> {
    let token = Token::open_self(true, TokenAccess::QUERY).ok()?;
    token.user().ok().map(|sid| sid.to_string())
}

/// Who a SID is, as authd has them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Person {
    /// Their account name, qualified.
    pub account: String,
    pub display: Option<String>,
}

/// How long the window waits for authd to name someone.
const AUTHD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// The people `sids` are, as far as authd knows them. A SID authd doesn't
/// know, or can't be asked about, is left out and shown as itself.
pub fn people(sids: &[String]) -> HashMap<String, Person> {
    let ident = Ident::new().with_timeout(AUTHD_TIMEOUT);
    let mut found = HashMap::new();
    for sid in sids {
        let Ok(native) = sid.parse::<peios::security::Sid>() else {
            continue;
        };
        let record = match ident.lookup(
            IdentKey::Sid(native.as_bytes().to_vec()),
            IdentKind::Any,
            Fields::DISPLAY_NAME,
        ) {
            Ok(Some(record)) => record,
            Ok(None) => continue,
            // authd isn't answering: don't wait on it for every SID.
            Err(_) => break,
        };
        if SidRef::from_bytes(&record.sid).is_none() {
            continue;
        }
        let display = match record.value(Fields::DISPLAY_NAME) {
            Some(Value::DisplayName(name)) if !name.trim().is_empty() => Some(name.clone()),
            _ => None,
        };
        found.insert(
            sid.clone(),
            Person {
                account: record.qualified_name,
                display,
            },
        );
    }
    found
}

/// The most the window lists of one CA's requests or certificates.
pub const MOST_LISTED: usize = 5_000;

/// A CA's requests with `status`, newest first.
pub fn requests(ca: &str, status: Option<RequestStatus>) -> Result<Vec<RequestInfo>, String> {
    let client = Client::new();
    let mut all = Vec::new();
    let mut after = None;
    loop {
        let page = client
            .requests(
                ca,
                RequestQuery {
                    status,
                    after,
                    limit: MAX_LISTING,
                },
            )
            .map_err(|error| crate::failure::Failure::client(error).message)?;
        let full = page.len() == MAX_LISTING as usize;
        after = page.last().map(|request| request.id);
        all.extend(page);
        if !full || all.len() >= MOST_LISTED {
            break;
        }
    }
    all.reverse();
    Ok(all)
}

/// A CA's certificates, newest first.
pub fn certificates(ca: &str) -> Result<Vec<CertificateInfo>, String> {
    let client = Client::new();
    let mut all = Vec::new();
    let mut after = None;
    loop {
        let page = client
            .certificates(
                ca,
                CertificateQuery {
                    unrevoked_only: false,
                    after,
                    limit: MAX_LISTING,
                },
            )
            .map_err(|error| crate::failure::Failure::client(error).message)?;
        let full = page.len() == MAX_LISTING as usize;
        after = page.last().map(|certificate| certificate.request);
        all.extend(page);
        if !full || all.len() >= MOST_LISTED {
            break;
        }
    }
    all.reverse();
    Ok(all)
}
