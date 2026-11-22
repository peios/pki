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
