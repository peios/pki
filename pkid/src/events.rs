//! pkid's events, emitted to eventd (see `pkid.evman`).
//!
//! An event that can't be emitted is reported on standard error and never
//! changes what pkid decides. Access denials aren't emitted here: the
//! kernel audits them through the descriptors' SACLs.

use peios::event::{EventPolicy, Tier};
use peios::msgpack::Writer;

use crate::dispatch::{Audit, Event};

/// Emits pkid's events to eventd.
pub struct EventLog;

fn emit(event_type: &str, build: impl FnOnce(&mut Writer)) {
    let result = EventPolicy::open().and_then(|policy| {
        policy.emit_with(event_type, Tier::Standard, || {
            let mut writer = Writer::new();
            build(&mut writer);
            writer.to_bytes().unwrap_or_default()
        })
    });
    if let Err(error) = result {
        eprintln!("pkid: event {event_type}: {error}");
    }
}

/// `subject.token.sid` and `object.pkid.ca`, then `extra` more entries
/// written by `rest`.
fn header(writer: &mut Writer, sid: &str, ca: &str, extra: u32, rest: impl FnOnce(&mut Writer)) {
    writer.write_map(2);
    writer
        .write_str("subject")
        .write_map(1)
        .write_str("token")
        .write_map(1)
        .write_str("sid")
        .write_str(sid);
    writer
        .write_str("object")
        .write_map(1)
        .write_str("pkid")
        .write_map(1 + extra)
        .write_str("ca")
        .write_str(ca);
    rest(writer);
}

impl Audit for EventLog {
    fn record(&self, event: Event) {
        match event {
            Event::ConfigurationLoaded { error } => configuration_loaded(error.as_deref()),
            Event::Managed {
                ca,
                action,
                operator,
            } => emit("pkid.authority.changed", |writer| {
                header(writer, operator.as_str(), &ca, 1, |writer| {
                    writer.write_str("action").write_str(action);
                })
            }),
            Event::Submitted {
                ca,
                request,
                requester,
                outcome,
            } => emit("pkid.request.submitted", |writer| {
                header(writer, requester.as_str(), &ca, 2, |writer| {
                    writer
                        .write_str("request")
                        .write_int(request)
                        .write_str("outcome")
                        .write_str(outcome);
                })
            }),
            Event::Approved {
                ca,
                request,
                officer,
            } => emit("pkid.request.approved", |writer| {
                header(writer, officer.as_str(), &ca, 1, |writer| {
                    writer.write_str("request").write_int(request);
                })
            }),
            Event::Denied {
                ca,
                request,
                officer,
            } => emit("pkid.request.denied", |writer| {
                header(writer, officer.as_str(), &ca, 1, |writer| {
                    writer.write_str("request").write_int(request);
                })
            }),
            Event::Revoked {
                ca,
                serial,
                reason,
                officer,
            } => emit("pkid.certificate.revoked", |writer| {
                header(writer, officer.as_str(), &ca, 2, |writer| {
                    writer
                        .write_str("serial")
                        .write_bin(&serial)
                        .write_str("reason")
                        .write_uint(u64::from(reason));
                })
            }),
        }
    }
}

/// `pkid.configuration.loaded`: pkid read its configuration, and whether
/// it can serve it (rule R3: changes to it are visible).
fn configuration_loaded(error: Option<&str>) {
    emit("pkid.configuration.loaded", |writer| {
        writer.write_map(1).write_str("outcome");
        match error {
            None => {
                writer.write_map(1).write_str("success").write_bool(true);
            }
            Some(reason) => {
                writer
                    .write_map(2)
                    .write_str("success")
                    .write_bool(false)
                    .write_str("reason")
                    .write_str(reason);
            }
        }
    });
}
