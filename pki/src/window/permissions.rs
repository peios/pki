//! Who may do what, in the permissions editor (gxwi-sd-editor): at an
//! authority, from a template, and for a name.
//!
//! The editor opens read-only, with the reason, for someone who can't
//! change what it shows. What it applies is saved the way `pki` saves it,
//! so the same checks and warnings come with it.

use gxwi_sd_editor::{splice, Can, Generic, Object, Part, Request, Right};
use peios::security::sddl;

use super::{act, Window};
use crate::host::Live;
use crate::show::{MANAGE, OFFICER, READ, REQUEST};

/// pkid's generic mapping: Generic All is every right it knows.
fn generic() -> Generic {
    Generic {
        read: 0,
        write: 0,
        execute: 0,
        all: 0xf,
    }
}

fn right(name: &str, mask: u32) -> Right {
    Right {
        name: name.into(),
        mask,
        general: true,
    }
}

impl Window {
    /// Opens the editor on who may do what at authority `ca`.
    pub(super) fn edit_ca_permissions(&mut self, ca: &str) {
        let Some(authority) = self.seen.authority(ca).cloned() else {
            return;
        };
        let manage = authority.granted & MANAGE != 0;
        let request = Request {
            object: Object {
                name: authority.name.clone(),
                kind: "Certificate authority".into(),
                ..Default::default()
            },
            sd: authority.security.clone(),
            read: None,
            rights: vec![
                right("Manage CA", MANAGE),
                right("Issue and Manage Certificates", OFFICER),
                right("Read", READ),
                right("Request Certificates", REQUEST),
            ],
            generic: generic(),
            can: Can {
                dacl: manage,
                why: (!manage).then(|| {
                    format!(
                        "Changing who may use {} needs Manage CA permission there.",
                        authority.name
                    )
                }),
                ..Can::default()
            },
        };
        let surface = self.surface.clone();
        let id = authority.id.clone();
        let base = authority.security.clone();
        let opened = gxwi_sd_editor::open(
            &request,
            move |edited, parts| {
                // Only the access list means anything to pkid.
                if !parts.contains(&Part::Dacl) {
                    return Ok(());
                }
                // Onto what pkid holds now, not what the editor began with.
                let now = pkid_client::Client::new()
                    .authorities()
                    .ok()
                    .and_then(|all| all.into_iter().find(|a| a.id == id))
                    .map_or(base.clone(), |a| a.security);
                let bytes = splice(&now, edited, &[Part::Dacl])?;
                let text = sddl::format(&bytes).map_err(|error| error.to_string())?;
                let said = act::set_security(&Live::new(), &id, &text)?;
                if let Some(surface) = surface.upgrade() {
                    surface.update(|w, _| w.said = Some(Ok(said)));
                }
                Ok(())
            },
            || {},
        );
        match opened {
            Ok(editor) => self.editors.push(editor),
            Err(error) => {
                self.said = Some(Err(format!(
                    "The permissions editor couldn't open: {error}."
                )))
            }
        }
    }
}

impl Window {
    /// Opens the editor on who may request from template `id`.
    pub(super) fn edit_template_permissions(&mut self, id: &str) {
        let Some(values) = self
            .seen
            .config
            .as_ref()
            .ok()
            .and_then(|config| config.templates.iter().find(|(guid, _)| guid == id))
            .map(|(_, values)| values.clone())
        else {
            return;
        };
        let Some(security) = values
            .binary("EnrollSecurity")
            .ok()
            .flatten()
            .map(<[u8]>::to_vec)
        else {
            return;
        };
        let name = super::templates::name(&values);
        let may = self.seen.may.templates.get(id).is_some_and(|may| may.edit);
        let request = Request {
            object: Object {
                name: name.clone(),
                kind: "Certificate template".into(),
                ..Default::default()
            },
            sd: security.clone(),
            read: None,
            rights: vec![
                right("Enroll", pki_policy::TEMPLATE_ENROLL),
                right("Autoenroll (Reserved)", pki_policy::TEMPLATE_AUTOENROLL),
            ],
            generic: generic(),
            can: Can {
                dacl: may,
                why: (!may)
                    .then(|| "You don't have permission to change this template.".to_string()),
                ..Can::default()
            },
        };
        let surface = self.surface.clone();
        let id = id.to_owned();
        let opened = gxwi_sd_editor::open(
            &request,
            move |edited, parts| {
                if !parts.contains(&Part::Dacl) {
                    return Ok(());
                }
                // Onto what the Registry holds now.
                let now = pki_management::registry::read()
                    .ok()
                    .and_then(|config| config.templates.into_iter().find(|(guid, _)| *guid == id))
                    .and_then(|(_, values)| {
                        values
                            .binary("EnrollSecurity")
                            .ok()
                            .flatten()
                            .map(<[u8]>::to_vec)
                    })
                    .unwrap_or_else(|| security.clone());
                let bytes = splice(&now, edited, &[Part::Dacl])?;
                let text = sddl::format(&bytes).map_err(|error| error.to_string())?;
                let said = act::template_security(&Live::new(), &id, &text)?;
                if let Some(surface) = surface.upgrade() {
                    surface.update(|w, _| w.said = Some(Ok(said)));
                }
                Ok(())
            },
            || {},
        );
        self.opened(opened);
    }

    /// Opens the editor on who may request `text`, a name, and the names
    /// below it: its own entries, and those it inherits from the name above.
    pub(super) fn edit_name_permissions(&mut self, text: &str) {
        let Ok(config) = self.seen.config.clone() else {
            return;
        };
        let Ok(name) = pki_management::names::NamePath::parse(text) else {
            return;
        };
        let nodes = match name.tree {
            pki_policy::TreeKind::Dns => &config.dns,
            pki_policy::TreeKind::Principal => &config.principals,
        };
        let Ok(effective) = pki_management::security::effective(nodes, &name.path) else {
            return;
        };
        let parent = name.parent().map(|above| gxwi_sd_editor::Parent {
            name: above.display(),
            sd: pki_management::security::effective(nodes, &above.path)
                .ok()
                .map(|e| e.security.as_bytes().to_vec()),
        });
        let may = self
            .seen
            .may
            .names
            .get(&name.key())
            .is_some_and(|may| may.edit)
            || (effective.inherited_levels > 0 && self.seen.may.names.values().any(|may| may.add));
        let request = Request {
            object: Object {
                name: name.display(),
                kind: "Name".into(),
                container: true,
                parent,
                ..Default::default()
            },
            sd: effective.security.as_bytes().to_vec(),
            read: None,
            rights: vec![
                right("Request", pki_policy::NAME_REQUEST),
                right(
                    "Request with Approval",
                    pki_policy::NAME_REQUEST_WITH_APPROVAL,
                ),
                right("Request Wildcard", pki_policy::NAME_REQUEST_WILDCARD),
            ],
            generic: generic(),
            can: Can {
                dacl: may,
                why: (!may).then(|| {
                    "You don't have permission to change who may request this name.".to_string()
                }),
                ..Can::default()
            },
        };
        let surface = self.surface.clone();
        let shown = name.display();
        let opened = gxwi_sd_editor::open(
            &request,
            move |edited, parts| {
                if !parts.contains(&Part::Dacl) {
                    return Ok(());
                }
                // pki folds in what the name inherits, as `name
                // set-security` does from a terminal.
                let text = sddl::format(edited).map_err(|error| error.to_string())?;
                let said = act::name_security(&Live::new(), &shown, Some(&text))?;
                if let Some(surface) = surface.upgrade() {
                    surface.update(|w, _| w.said = Some(Ok(said)));
                }
                Ok(())
            },
            || {},
        );
        self.opened(opened);
    }

    fn opened(&mut self, opened: std::io::Result<gxwi_sd_editor::Editor>) {
        match opened {
            Ok(editor) => self.editors.push(editor),
            Err(error) => {
                self.said = Some(Err(format!(
                    "The permissions editor couldn't open: {error}."
                )))
            }
        }
    }
}
