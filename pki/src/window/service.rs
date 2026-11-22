//! pkid and pki-httpd as peinit runs them: their state, what the person
//! may do with them, and starting and stopping them as the person.

use peinit::client::{Command, ControlClient, Failure, ServiceAccess, State};

/// The certificate service.
pub const PKID: &str = "pkid";
/// The web server that publishes revocation lists.
pub const HTTPD: &str = "pki-httpd";

/// A service as the person can see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Service {
    /// peinit answered: its state, and the rights peinit says the person
    /// holds over it.
    Known { state: Run, granted: Vec<String> },
    /// peinit has no such service: pki's packaging hasn't defined it.
    Undefined,
    /// peinit wouldn't say, and why.
    Unknown(String),
}

/// What a service is doing, in the terms the window uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Run {
    Running,
    Starting,
    Stopping,
    Stopped,
    Failed,
}

impl Service {
    /// Whether peinit would accept `command` from the person. Where peinit
    /// wouldn't say, the command is offered, and peinit decides.
    pub fn allows(&self, command: Command) -> bool {
        match self {
            Service::Known { granted, .. } => {
                let needed = ServiceAccess::for_command(command).bits();
                let held = ServiceAccess::WIRE_NAMES
                    .iter()
                    .filter(|(_, name)| granted.iter().any(|g| g == name))
                    .fold(0, |bits, (right, _)| bits | right.bits());
                held & needed == needed
            }
            Service::Undefined => false,
            Service::Unknown(_) => true,
        }
    }
}

fn run(state: State) -> Run {
    match state {
        State::Active | State::Reloading => Run::Running,
        State::Starting => Run::Starting,
        State::Stopping => Run::Stopping,
        State::Failed | State::Backoff | State::Abandoned => Run::Failed,
        State::Inactive | State::Completed | State::Skipped => Run::Stopped,
    }
}

/// `service` as peinit has it.
pub fn look(service: &str) -> Service {
    let mut client = match ControlClient::connect_default() {
        Ok(client) => client,
        Err(error) => return Service::Unknown(error.to_string()),
    };
    match client.status_of(service) {
        Ok(status) => Service::Known {
            state: run(status.summary.state),
            granted: status.granted,
        },
        Err(Failure::Refused { code, .. }) if code == "NOT_FOUND" || code == "UNKNOWN_SERVICE" => {
            Service::Undefined
        }
        Err(Failure::Refused { code, .. }) if code == "ACCESS_DENIED" => {
            Service::Unknown("You don't have permission to see whether it's running.".into())
        }
        Err(failure) => Service::Unknown(failure.to_string()),
    }
}

/// Starts, stops or restarts `service`, as the person.
pub fn command(service: &str, command: Command) -> Result<(), String> {
    let mut client = ControlClient::connect_default().map_err(|error| error.to_string())?;
    match client.command(command, service) {
        Ok(_) => Ok(()),
        Err(Failure::Refused { code, .. }) if code == "ACCESS_DENIED" => {
            Err("You don't have permission to control this service.".into())
        }
        Err(Failure::Refused { message, .. }) => Err(sentence(&message)),
        Err(Failure::Unreachable(why)) => Err(sentence(&why)),
    }
}

/// `text` as a sentence: capitalised, with a full stop. A sentence that
/// starts with a name, such as lab.home or a Registry path, keeps it as it
/// is.
pub fn sentence(text: &str) -> String {
    let text = text.trim();
    if text.is_empty() {
        return String::new();
    }
    // The system's own error numbers mean nothing to a person.
    let text = match text.find(" (os error ") {
        Some(at) if text.ends_with(')') || text.ends_with(").") => text[..at].trim_end(),
        _ => text,
    };
    let first_word = text.split_whitespace().next().unwrap_or_default();
    let named = first_word.contains(['.', '@', '\\', '/']) && first_word.len() > 1;
    let mut chars = text.chars();
    let mut out: String = if named {
        text.to_string()
    } else {
        match chars.next() {
            Some(first) => first.to_uppercase().chain(chars).collect(),
            None => return String::new(),
        }
    };
    if !out.ends_with(['.', '!', '?']) {
        out.push('.');
    }
    out
}
