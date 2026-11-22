//! The Certificate Authority window, `pki --window`: pkid and pki's
//! configuration in GXWI.
//!
//! The window has no authority of its own. It reads pkid as the person,
//! which says what they hold at each CA, and opens each Registry key with
//! the access a change would need, so what it offers is what the system
//! would allow (see `seen`). What can't be changed is shown read-only, with
//! the reason. The changes it makes are the `pki` command's own, run
//! through a host that answers its prompts from the window, so the window
//! and the terminal can't disagree about what a change does.
//!
//! Its sections are an overview, requesting a certificate, the requests and
//! certificates of the CAs, each CA, and the templates and name trees.

pub(crate) mod act;
mod authority;
mod describe;
mod doing;
mod enrol;
mod held;
mod issued;
mod manage;
mod names;
mod overview;
mod permissions;
mod seen;
mod service;
mod templates;
mod words;

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::sync::{Arc, Weak};
use std::time::Duration;

use gxwi::settings::{self, Glyph, Tile};
use gxwi::{escape, App, Facts, Fields, Live, Surface, Value};
use pkid_core::{AuthorityInfo, CertificateInfo, RequestInfo, RequestStatus};

use self::doing::Asking;
use self::seen::{Person, Seen, Trouble};

// The window's icon, named for its declaration, dev.peios.pkid.toml (PGSS
// Icons §4.5). Only the window build carries it.
gxwi::icon!(b"dev.peios.pkid");

/// How often the window reads everything again. Nothing tells a client
/// when pkid or its configuration changes.
const LOOK_AGAIN: Duration = Duration::from_secs(5);

/// A change to make away from the window's lock: what to say once it is
/// made, or why it wasn't.
type Work = Box<dyn FnOnce() -> Result<String, String> + Send>;

/// A change whose page to open comes of it.
type WorkThen = Box<dyn FnOnce() -> Result<(String, Option<Page>), String> + Send>;

/// How many rows of a long list are shown before Show More.
const PAGE_ROWS: usize = 100;

/// What the window shows beside its sections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Page {
    Overview,
    Enrol,
    Requests,
    Request {
        ca: String,
        id: i64,
    },
    Certificates,
    Certificate {
        ca: String,
        serial: Vec<u8>,
    },
    Authority(String),
    Templates,
    Template(String),
    Names,
    /// A name, as people write it: `lab.home`, `jack@home`, `@home`, `.`.
    Name(String),
    NewAuthority,
    /// Signing a subordinate's request with this CA.
    Sign(String),
    /// Exporting this CA's key.
    ExportKey(String),
}

impl Page {
    /// The section of the side the page belongs to.
    fn section(&self) -> String {
        match self {
            Page::Overview => "overview".into(),
            Page::Enrol => "enrol".into(),
            Page::Requests | Page::Request { .. } => "requests".into(),
            Page::Certificates | Page::Certificate { .. } => "certificates".into(),
            Page::Authority(id) | Page::Sign(id) | Page::ExportKey(id) => format!("authority:{id}"),
            Page::NewAuthority => "new-authority".into(),
            Page::Templates | Page::Template(_) => "templates".into(),
            Page::Names | Page::Name(_) => "names".into(),
        }
    }

    fn parse(section: &str) -> Option<Page> {
        Some(match section {
            "overview" => Page::Overview,
            "enrol" => Page::Enrol,
            "requests" => Page::Requests,
            "certificates" => Page::Certificates,
            "templates" => Page::Templates,
            "names" => Page::Names,
            "new-authority" => Page::NewAuthority,
            _ => Page::Authority(section.strip_prefix("authority:")?.to_string()),
        })
    }

    /// The CA whose requests or certificates the page shows, if it shows a
    /// CA's.
    fn issued_by(&self) -> Option<&str> {
        match self {
            Page::Request { ca, .. } | Page::Certificate { ca, .. } => Some(ca),
            _ => None,
        }
    }
}

/// One CA's requests and certificates, as last read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Listing {
    pub ca: String,
    pub requests: Option<Result<Vec<RequestInfo>, String>>,
    pub certificates: Option<Result<Vec<CertificateInfo>, String>>,
}

pub struct Window {
    surface: Weak<Surface<Window>>,
    seen: Seen,
    /// The person's SID.
    me: Option<String>,
    /// Who the SIDs the window shows are, as far as authd has said.
    people: HashMap<String, Person>,
    page: Page,
    listing: Listing,
    /// How many rows of the list on show are shown.
    shown: usize,
    busy: bool,
    said: Option<Result<String, String>>,
    /// The question open under a row, if one is.
    asking: Option<Asking>,
    /// Whether the file dialog is open.
    choosing: bool,
    /// The permissions editors open from the window.
    editors: Vec<gxwi_sd_editor::Editor>,
}

impl Window {
    fn new(seen: Seen, me: Option<String>) -> Window {
        Window {
            surface: Weak::new(),
            seen,
            me,
            people: HashMap::new(),
            page: Page::Overview,
            listing: Listing::default(),
            shown: PAGE_ROWS,
            busy: false,
            said: None,
            asking: None,
            choosing: false,
            editors: Vec::new(),
        }
    }

    /// The CA the Requests and Certificates pages show: the one chosen, or
    /// else the first that issues from templates and whose every request
    /// the person may read, or the first that issues at all.
    fn listed_ca(&self, fields: &Fields) -> Option<&AuthorityInfo> {
        let authorities = self.seen.authorities();
        if let Some(ca) = self.page.issued_by() {
            return authorities.iter().find(|a| a.id == ca);
        }
        let chosen = fields.get("ca");
        let issues = |a: &&AuthorityInfo| a.certificate.is_some();
        let reads = |a: &&AuthorityInfo| a.granted & crate::show::READ != 0;
        authorities
            .iter()
            .filter(issues)
            .find(|a| a.id == chosen)
            .or_else(|| {
                authorities
                    .iter()
                    .filter(issues)
                    .filter(reads)
                    .find(|a| !a.templates.is_empty())
            })
            .or_else(|| {
                authorities
                    .iter()
                    .filter(issues)
                    .find(|a| !a.templates.is_empty())
            })
            .or_else(|| authorities.iter().find(issues))
    }

    /// Whether the page needs a CA's requests and certificates, and whose.
    fn wanted(&self, fields: &Fields) -> Option<String> {
        match self.page {
            Page::Requests
            | Page::Request { .. }
            | Page::Certificates
            | Page::Certificate { .. } => self.listed_ca(fields).map(|a| a.id.clone()),
            _ => None,
        }
    }

    fn open(&mut self, page: Page, fields: &mut Fields) {
        if matches!(page, Page::Requests | Page::Certificates) && page != self.page {
            fields.set("find", "");
            self.shown = PAGE_ROWS;
        }
        self.page = page;
        self.said = None;
        self.asking = None;
        doing::forget(fields);
        self.fill(fields);
        self.reload(fields);
    }

    /// Sets the fields of the form on the page from what it changes.
    fn fill(&self, fields: &mut Fields) {
        match &self.page {
            Page::Authority(id) => {
                if let Some(authority) = self.seen.authority(id) {
                    manage::fill_issuing(self, authority, fields);
                }
            }
            Page::NewAuthority => {
                for name in [
                    "new-name",
                    "new-crls",
                    "new-key-file",
                    "new-certificate",
                    "new-sealed",
                ] {
                    fields.set(name, "");
                }
                fields.set("new-kind", "root");
                fields.set("new-keep", "service");
                manage::fill_new(fields);
            }
            Page::Sign(_) => {
                for name in ["sign-request", "sign-name", "sign-out"] {
                    fields.set(name, "");
                }
                fields.set(
                    "sign-lifetime",
                    &crate::cli::SUBORDINATE_LIFETIME_DAYS.to_string(),
                );
                fields.set("sign-path", "0");
            }
            Page::ExportKey(_) => fields.set("key-out", ""),
            Page::Overview => {
                if let Some(port) = self.seen.http_port {
                    fields.set("http-port", &port.to_string());
                }
            }
            Page::Template(id) => {
                if let Some((_, values)) = self
                    .seen
                    .config
                    .as_ref()
                    .ok()
                    .and_then(|config| config.templates.iter().find(|(guid, _)| guid == id))
                {
                    templates::fill(values, fields);
                }
            }
            Page::Names => {
                if let Ok(config) = &self.seen.config {
                    fields.set("domains", &names::domains(config).join(", "));
                }
            }
            _ => {}
        }
    }

    /// Keeps the Authority field showing the CA the lists are of: the page
    /// shows a field's last value, not what the window chose by default.
    fn sync(&self, fields: &mut Fields) {
        if matches!(self.page, Page::Requests | Page::Certificates) {
            if let Some(ca) = self.listed_ca(fields) {
                // What the Requests page shows until the person chooses.
                if fields.get("show").is_empty() {
                    let officer = ca.granted & crate::show::OFFICER != 0;
                    fields.set("show", if officer { "waiting" } else { "all" });
                }
                let ca = ca.id.clone();
                if fields.get("ca") != ca {
                    fields.set("ca", &ca);
                }
            }
        }
    }

    /// Reads the listing the page needs, away from the lock, if it is not
    /// the one already read.
    fn reload(&mut self, fields: &mut Fields) {
        self.sync(fields);
        let Some(ca) = self.wanted(fields) else {
            return;
        };
        if self.listing.ca == ca && self.listing.requests.is_some() {
            return;
        }
        self.listing = Listing {
            ca: ca.clone(),
            requests: None,
            certificates: None,
        };
        let surface = self.surface.clone();
        let known: Vec<String> = self.people.keys().cloned().collect();
        std::thread::spawn(move || {
            let (listing, people) = read_listing(&ca, &known);
            if let Some(surface) = surface.upgrade() {
                surface.update(|w, _| w.listed(listing, people));
            }
        });
    }

    fn listed(&mut self, listing: Listing, people: HashMap<String, Person>) {
        self.people.extend(people);
        if listing.ca == self.listing.ca {
            self.listing = listing;
        }
    }

    /// Takes what was read in the background.
    fn heard(&mut self, seen: Seen, people: HashMap<String, Person>, fields: &mut Fields) {
        self.people.extend(people);
        self.seen = seen;
        self.sync(fields);
        // A page whose subject has gone falls back to its list.
        let gone = match &self.page {
            Page::Authority(id) => self.seen.pkid.is_ok() && self.seen.authority(id).is_none(),
            Page::Template(id) => self
                .seen
                .config
                .as_ref()
                .is_ok_and(|config| !config.templates.iter().any(|(guid, _)| guid == id)),
            _ => false,
        };
        if gone {
            self.page = match self.page {
                Page::Template(_) => Page::Templates,
                _ => Page::Overview,
            };
        }
    }

    /// Runs `work` away from the lock, then reads everything again and says
    /// what came of it. `then` is the page to open if it worked.
    fn launch(&mut self, work: Work, then: Option<Page>, fields: &Fields) {
        self.launch_then(Box::new(move || work().map(|said| (said, then))), fields);
    }

    /// Runs `work` as [`Window::launch`] does, where the page to open
    /// comes of the work itself.
    fn launch_then(&mut self, work: WorkThen, fields: &Fields) {
        if self.busy {
            return;
        }
        self.busy = true;
        self.said = None;
        let surface = self.surface.clone();
        let known: Vec<String> = self.people.keys().cloned().collect();
        let listed = self.wanted(fields);
        std::thread::spawn(move || {
            let result = work();
            let (seen, mut people) = look(&known);
            let listing = listed.map(|ca| {
                let (listing, more) = read_listing(&ca, &known);
                people.extend(more);
                listing
            });
            if let Some(surface) = surface.upgrade() {
                surface.update(|w, fields| {
                    w.busy = false;
                    w.heard(seen, people, fields);
                    if let Some(listing) = listing {
                        w.listing = listing;
                    }
                    let said = match result {
                        Ok((said, then)) => {
                            if let Some(page) = then {
                                w.open(page, fields);
                            }
                            Ok(said)
                        }
                        Err(why) => Err(why),
                    };
                    w.said = Some(said);
                });
            }
        });
    }

    /// Who a SID is, as a person reads it. Their own SID, when authd can't
    /// name it, is "You".
    pub fn who(&self, sid: &str) -> String {
        let named = describe::who(sid, &self.people);
        if named == sid && self.me.as_deref() == Some(sid) {
            return "You".to_string();
        }
        named
    }

    /// Who a SID is, with their account when they have a display name too.
    pub fn who_in_full(&self, sid: &str) -> String {
        let named = describe::who_in_full(sid, &self.people);
        if named == sid && self.me.as_deref() == Some(sid) {
            return "You".to_string();
        }
        named
    }

    fn nav(&self) -> String {
        let current = self.page.section();
        let mut side = nav(
            "overview",
            "Certificate Authority",
            &overview::summary(self),
            Glyph::Certificate,
            Tile::Red,
            &current,
        );
        if !self.seen.set_up {
            return side;
        }
        let authorities = self.seen.authorities();
        let reachable = self.seen.pkid.is_ok();
        if reachable {
            side.push_str("<h3>Certificates</h3>");
            if !enrol::authorities(self).is_empty() {
                side.push_str(&nav(
                    "enrol",
                    "Request a Certificate",
                    "Get a new certificate",
                    Glyph::Key,
                    Tile::Green,
                    &current,
                ));
            }
            side.push_str(&nav(
                "requests",
                "Requests",
                &issued::requests_summary(self),
                Glyph::Clock,
                Tile::Orange,
                &current,
            ));
            side.push_str(&nav(
                "certificates",
                "Certificates",
                &issued::certificates_summary(self),
                Glyph::Certificate,
                Tile::Blue,
                &current,
            ));
            let create = self.seen.pkid.as_ref().is_ok_and(|pkid| pkid.create);
            if !authorities.is_empty() || create {
                side.push_str("<h3>Authorities</h3>");
            }
            for authority in authorities {
                side.push_str(&nav(
                    &format!("authority:{}", authority.id),
                    &authority.name,
                    &authority::summary(authority),
                    Glyph::Shield,
                    authority::tile(authority),
                    &current,
                ));
            }
            if create {
                side.push_str(&nav(
                    "new-authority",
                    "Add an Authority",
                    "Create one, or import a backup",
                    Glyph::Shield,
                    Tile::Slate,
                    &current,
                ));
            }
        }
        side.push_str("<h3>Policy</h3>");
        side.push_str(&nav(
            "templates",
            "Templates",
            &templates::summary(self),
            Glyph::File,
            Tile::Violet,
            &current,
        ));
        side.push_str(&nav(
            "names",
            "Names",
            &names::summary(self),
            Glyph::Tag,
            Tile::Teal,
            &current,
        ));
        side
    }
}

/// A section of the side, drawn as the settings kit draws its own, for
/// sections that come and go with the CAs.
fn nav(id: &str, title: &str, now: &str, glyph: Glyph, tile: Tile, current: &str) -> String {
    format!(
        r#"<button id="st-nav-{id}" fx-click="section" fx-value-section="{id}" title="{title}"{current}>{icon}<span class="what"><b>{title}</b><small>{now}</small></span></button>"#,
        id = escape(id),
        title = escape(title),
        current = if id == current {
            r#" aria-current="page""#
        } else {
            ""
        },
        icon = settings::icon(glyph, tile),
        now = escape(now),
    )
}

/// One CA's requests and certificates, and who the people in them are.
fn read_listing(ca: &str, known: &[String]) -> (Listing, HashMap<String, Person>) {
    let requests = seen::requests(ca, None);
    let certificates = seen::certificates(ca);
    let mut sids: Vec<String> = Vec::new();
    if let Ok(requests) = &requests {
        for request in requests {
            sids.push(request.requester.clone());
            sids.extend(request.decider.clone());
        }
    }
    if let Ok(certificates) = &certificates {
        for certificate in certificates {
            sids.extend(certificate.owner.clone());
            sids.extend(certificate.revocation.as_ref().map(|r| r.revoker.clone()));
        }
    }
    sids.sort();
    sids.dedup();
    sids.retain(|sid| !known.contains(sid));
    (
        Listing {
            ca: ca.to_string(),
            requests: Some(requests),
            certificates: Some(certificates),
        },
        seen::people(&sids),
    )
}

/// Everything, read again, and who the SIDs in its descriptors are.
fn look(known: &[String]) -> (Seen, HashMap<String, Person>) {
    let seen = seen::look();
    let mut sids = describe::sids(&seen);
    sids.retain(|sid| !known.contains(sid));
    let people = seen::people(&sids);
    (seen, people)
}

impl Live for Window {
    fn render(&self, facts: &Facts) -> String {
        let fields = facts.fields;
        let page = match &self.page {
            Page::Overview => overview::page(self),
            Page::Enrol => enrol::page(self, fields),
            Page::Requests => issued::requests(self, fields),
            Page::Request { ca, id } => issued::request(self, ca, *id),
            Page::Certificates => issued::certificates(self, fields),
            Page::Certificate { ca, serial } => issued::certificate(self, ca, serial),
            Page::Authority(id) => match self.seen.authority(id) {
                Some(authority) => authority::page(self, authority),
                None => overview::page(self),
            },
            Page::Templates => templates::list(self),
            Page::Template(id) => templates::page(self, id),
            Page::Names => names::list(self, fields),
            Page::Name(name) => names::page(self, name),
            Page::NewAuthority => manage::new_page(self, fields),
            Page::Sign(id) => match self.seen.authority(id) {
                Some(authority) => manage::sign_page(self, authority),
                None => overview::page(self),
            },
            Page::ExportKey(id) => match self.seen.authority(id) {
                Some(authority) => manage::export_page(self, authority),
                None => overview::page(self),
            },
        };
        let aside = if self.busy { "Working…" } else { "" };
        format!(
            r#"<div class="st"><nav class="st-nav" aria-label="Sections">{}</nav><main class="st-page" id="st-page-{}"><div class="st-inner">{page}</div></main></div>{}"#,
            self.nav(),
            escape(&self.page.section()),
            settings::status(self.said.as_ref(), aside)
        )
    }

    fn input(&mut self, name: &str, fields: &mut Fields) {
        match name {
            "ca" => {
                self.shown = PAGE_ROWS;
                self.reload(fields);
            }
            "find" | "show" | "show-certificates" => self.shown = PAGE_ROWS,
            "new-kind" => manage::fill_new(fields),
            _ => {}
        }
    }

    fn event(&mut self, name: &str, value: &Value, fields: &mut Fields) {
        let text = |key: &str| {
            value
                .get(key)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned()
        };
        match name {
            "section" => {
                if let Some(page) = Page::parse(&text("section")) {
                    self.open(page, fields);
                }
            }
            "review" => {
                fields.set("ca", &text("ca"));
                fields.set("show", "waiting");
                self.open(Page::Requests, fields);
            }
            "request" => {
                if let Ok(id) = text("id").parse() {
                    self.open(Page::Request { ca: text("ca"), id }, fields);
                }
            }
            "certificate" => {
                if let Ok(serial) = crate::issue::serial(&text("serial")) {
                    self.open(
                        Page::Certificate {
                            ca: text("ca"),
                            serial,
                        },
                        fields,
                    );
                }
            }
            "template" => self.open(Page::Template(text("id")), fields),
            "name" => self.open(Page::Name(text("name")), fields),
            "back" => {
                let page = match &self.page {
                    Page::Sign(ca) | Page::ExportKey(ca) => Page::Authority(ca.clone()),
                    Page::Request { .. } => Page::Requests,
                    Page::Certificate { .. } => Page::Certificates,
                    Page::Template(_) => Page::Templates,
                    Page::Name(_) => Page::Names,
                    _ => Page::Overview,
                };
                self.open(page, fields);
            }
            "more" => self.shown += PAGE_ROWS,
            "service" => {
                let name = text("service");
                let (command, done) = match text("action").as_str() {
                    "start" => (peinit::client::Command::Start, "started"),
                    "stop" => (peinit::client::Command::Stop, "stopped"),
                    "restart" => (peinit::client::Command::Restart, "restarted"),
                    _ => return,
                };
                let title = match name.as_str() {
                    service::PKID => "Certificate Service",
                    service::HTTPD => "Revocation Publishing",
                    _ => return,
                };
                self.launch(
                    Box::new(move || {
                        service::command(&name, command).map(|()| format!("{title} {done}."))
                    }),
                    None,
                    fields,
                );
            }
            "refresh" => {
                self.listing = Listing::default();
                self.reload(fields);
            }
            "cancel" => self.cancel(fields),
            "choose" if !self.busy => self.choose_for(text("field"), &text("for"), fields),
            "issuing" if !self.busy => {
                if let Page::Authority(ca) = &self.page {
                    let ca = ca.clone();
                    self.issuing(ca, fields);
                }
            }
            "create" if !self.busy => self.create(fields),
            "sign" if !self.busy => match &self.page {
                Page::Sign(ca) => {
                    let ca = ca.clone();
                    self.sign(ca, fields);
                }
                _ => self.open(Page::Sign(text("ca")), fields),
            },
            "export-key" if !self.busy => match &self.page {
                Page::ExportKey(ca) => {
                    let ca = ca.clone();
                    self.export_key(ca, fields);
                }
                _ => self.open(Page::ExportKey(text("ca")), fields),
            },
            "install" if !self.busy => self.install(text("ca")),
            "ca-permissions" => self.edit_ca_permissions(&text("ca")),
            "template-permissions" => self.edit_template_permissions(&text("id")),
            "name-permissions" => self.edit_name_permissions(&text("name")),
            "template-save" if !self.busy => self.save_template(fields),
            "new-template" if !self.busy => {
                fields.set("new-template-name", "");
                self.ask(Asking::NewTemplate, fields);
            }
            "new-template-confirm" if !self.busy => self.new_template(fields),
            "delete-template" if !self.busy => {
                self.ask(Asking::DeleteTemplate { id: text("id") }, fields)
            }
            "delete-template-confirm" if !self.busy => self.delete_template(fields),
            "add-name" if !self.busy => {
                fields.set("add-name", "");
                self.ask(Asking::AddName, fields);
            }
            "add-name-confirm" if !self.busy => self.add_name(fields),
            "remove-name" if !self.busy => {
                self.ask(Asking::RemoveName { name: text("name") }, fields)
            }
            "remove-name-confirm" if !self.busy => self.remove_name(fields),
            "inherit" if !self.busy => self.ask(Asking::Inherit { name: text("name") }, fields),
            "inherit-confirm" if !self.busy => self.inherit(fields),
            "owner" if !self.busy => {
                fields.set("owner", "");
                self.ask(Asking::Owner { name: text("name") }, fields);
            }
            "owner-confirm" if !self.busy => self.set_owner(false, fields),
            "owner-none" if !self.busy => self.set_owner(true, fields),
            "domains-save" if !self.busy => self.save_domains(fields),
            "creators-permissions" => self.edit_creators_permissions(),
            "http-port-save" if !self.busy => self.save_http_port(fields),
            "approve" if !self.busy => {
                if let Ok(id) = text("id").parse() {
                    self.approve(text("ca"), id, fields);
                }
            }
            "deny" if !self.busy => {
                if let Ok(id) = text("id").parse() {
                    self.ask(Asking::Deny { ca: text("ca"), id }, fields);
                }
            }
            "deny-confirm" if !self.busy => self.deny(fields),
            "revoke" if !self.busy => self.ask(
                Asking::Revoke {
                    ca: text("ca"),
                    serial: text("serial"),
                },
                fields,
            ),
            "revoke-confirm" if !self.busy => self.revoke(fields),
            "publish" if !self.busy => self.publish(text("ca"), fields),
            "collect" if !self.busy => {
                if let Ok(id) = text("id").parse() {
                    self.ask(Asking::Collect { ca: text("ca"), id }, fields);
                }
            }
            "collect-confirm" if !self.busy => self.collect(fields),
            "forget-held" if !self.busy => {
                if let Ok(id) = text("id").parse() {
                    self.forget_held(text("ca"), id, fields);
                }
            }
            "setup" if !self.busy && self.seen.may.setup => self.setup(fields),
            "enrol" if !self.busy => self.enrol(fields),
            "choose-out" if !self.busy => self.choose_out(fields),
            "choose-csr" if !self.busy => self.choose_csr(),
            "export" => {
                let found = self.listing.certificates.as_ref().and_then(|list| {
                    list.as_ref()
                        .ok()?
                        .iter()
                        .find(|c| crate::show::hex(&c.serial) == text("serial"))
                        .cloned()
                });
                if let Some(certificate) = found {
                    let name = words::certificate_name(&certificate.der)
                        .unwrap_or_else(|| "certificate".into());
                    self.export(
                        "Export the Certificate",
                        &format!("{name}.pem"),
                        crate::files::CERTIFICATE,
                        certificate.der,
                    );
                }
            }
            "export-ca" => {
                if let Some(authority) = self.seen.authority(&text("ca")).cloned() {
                    if let Some(der) = authority.certificate {
                        self.export(
                            "Export the Authority's Certificate",
                            &format!("{}.pem", authority.name),
                            crate::files::CERTIFICATE,
                            der,
                        );
                    }
                }
            }
            "save-ca-request" => {
                if let Some(authority) = self.seen.authority(&text("ca")).cloned() {
                    if let Some(der) = authority.request {
                        self.export(
                            "Save the Authority's Request",
                            &format!("{}.csr", authority.name),
                            crate::files::REQUEST,
                            der,
                        );
                    }
                }
            }
            _ => {}
        }
    }
}

pub fn open() -> i32 {
    let mut app = match App::connect() {
        Ok(app) => app,
        Err(error) => {
            eprintln!("pki: can't open the window: {error}");
            return 1;
        }
    };
    settings::stylesheet(&mut app);
    app.stylesheet("/pki.css", include_str!("window.css"));
    let (seen, people) = look(&[]);
    let surface = app.live("Certificate Authority", Window::new(seen, seen::me()));
    let weak = Arc::downgrade(&surface);
    surface.update(|w, _| {
        w.surface = weak.clone();
        w.people.extend(people);
    });
    // Follow changes made elsewhere: by pki, another window, the Registry,
    // pkid itself.
    std::thread::spawn(move || loop {
        std::thread::sleep(LOOK_AGAIN);
        let Some(surface) = weak.upgrade() else {
            return;
        };
        let (known, listing) = surface.look(|w, fields, _| {
            (
                w.people.keys().cloned().collect::<Vec<_>>(),
                w.wanted(fields),
            )
        });
        drop(surface);
        let (seen, mut people) = look(&known);
        let listing = listing.map(|ca| {
            let (listing, more) = read_listing(&ca, &known);
            people.extend(more);
            listing
        });
        let Some(surface) = weak.upgrade() else {
            return;
        };
        let changed = surface.look(|w, _, _| {
            w.seen != seen
                || !people.is_empty()
                || listing
                    .as_ref()
                    .is_some_and(|listing| *listing != w.listing)
        });
        if changed {
            surface.update(|w, fields| {
                if w.busy {
                    return;
                }
                w.heard(seen, people, fields);
                if let Some(listing) = listing {
                    w.listed(listing, HashMap::new());
                }
            });
        }
    });
    match app.run() {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("pki: {error}");
            1
        }
    }
}

/// Whether pkid can be asked, and if not, the banner that says why, for
/// pages that need it.
fn unreachable(window: &Window) -> Option<String> {
    let trouble = window.seen.pkid.as_ref().err()?;
    Some(match trouble {
        Trouble::Down => settings::caution(
            "The Certificate Service isn't running, so authorities, requests and certificates can't be shown.",
        ),
        Trouble::Invalid(reason) => settings::caution(&format!(
            "Nothing is being issued: the configuration is invalid. {}",
            service::sentence(reason)
        )),
        Trouble::Database(reason) => settings::caution(&format!(
            "Nothing is being issued: the certificate database can't be used. {}",
            service::sentence(reason)
        )),
        Trouble::Failed(reason) => settings::caution(&service::sentence(reason)),
    })
}

/// A fact whose value is HTML: a value and a pill beside it, say.
fn fact_html(label: &str, html: &str) -> String {
    format!(
        r#"<div class="st-row fact"><span class="label"><b>{}</b></span><span class="control">{html}</span></div>"#,
        escape(label)
    )
}

/// Whether a request is still waiting.
fn waiting(request: &RequestInfo) -> bool {
    request.status == RequestStatus::Pending
}
