//! Why a command failed, and the exit status that says so (see pki(8),
//! EXIT STATUS).

use std::fmt;
use std::io;

use pkid_client::ClientError;
use pkid_core::ErrorCode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Failed,
    Usage,
    Denied,
    NotFound,
    Exists,
}

impl Kind {
    pub fn status(self) -> u8 {
        match self {
            Self::Failed => 1,
            Self::Usage => 2,
            Self::Denied => 3,
            Self::NotFound => 4,
            Self::Exists => 5,
        }
    }

    /// The failure's name in JSON output.
    pub fn tag(self) -> &'static str {
        match self {
            Self::Failed => "failed",
            Self::Usage => "invalid-argument",
            Self::Denied => "permission-denied",
            Self::NotFound => "not-found",
            Self::Exists => "already-exists",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    pub kind: Kind,
    pub message: String,
    /// What the reader can do about it, as a sentence.
    pub hint: Option<String>,
}

impl Failure {
    pub fn new(kind: Kind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            hint: None,
        }
    }

    pub fn failed(message: impl Into<String>) -> Self {
        Self::new(Kind::Failed, message)
    }

    pub fn usage(message: impl Into<String>) -> Self {
        Self::new(Kind::Usage, message)
    }

    pub fn hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    /// Names what failed before the reason, as in `create Root: access
    /// denied`.
    pub fn context(mut self, what: impl fmt::Display) -> Self {
        self.message = format!("{what}: {}", self.message);
        self
    }

    pub fn io(error: &io::Error) -> Self {
        let kind = match error.kind() {
            io::ErrorKind::PermissionDenied => Kind::Denied,
            io::ErrorKind::NotFound => Kind::NotFound,
            io::ErrorKind::AlreadyExists => Kind::Exists,
            _ => Kind::Failed,
        };
        Self::new(kind, os_message(error))
    }

    pub fn client(error: ClientError) -> Self {
        match error {
            ClientError::Unavailable(error) => {
                Self::failed(format!("pkid is not available: {}", os_message(&error)))
                    .hint("Check that the pkid service is running.")
            }
            ClientError::NotPkid(who) => Self::failed(format!(
                "the server at {} is not pkid but {who}",
                pkid_core::SOCKET_PATH
            )),
            ClientError::Refused(refusal) => {
                let kind = match refusal.code {
                    ErrorCode::AccessDenied | ErrorCode::SelfApproval => Kind::Denied,
                    ErrorCode::NotFound => Kind::NotFound,
                    ErrorCode::Conflict => Kind::Exists,
                    _ => Kind::Failed,
                };
                Self::new(kind, refusal.message)
            }
            ClientError::Protocol(detail) => {
                Self::failed(format!("pkid sent an unexpected reply: {detail}"))
            }
            ClientError::Io(error) => Self::failed(format!(
                "the connection to pkid failed: {}",
                os_message(&error)
            )),
        }
    }
}

/// An I/O error in the system's own wording, without Rust's error number.
pub fn os_message(error: &io::Error) -> String {
    let mut text = error.to_string();
    if let Some(at) = text.find(" (os error ") {
        if text.ends_with(')') {
            text.truncate(at);
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use pkid_core::WireError;

    #[test]
    fn os_errors_lose_their_numbers() {
        let error = io::Error::from_raw_os_error(libc::ENOENT);
        assert_eq!(os_message(&error), "No such file or directory");
        assert_eq!(Failure::io(&error).kind, Kind::NotFound);
    }

    #[test]
    fn refusals_map_to_statuses() {
        for (code, status) in [
            (ErrorCode::AccessDenied, 3),
            (ErrorCode::SelfApproval, 3),
            (ErrorCode::NotFound, 4),
            (ErrorCode::Conflict, 5),
            (ErrorCode::BadRequest, 1),
            (ErrorCode::KeyUnavailable, 1),
        ] {
            let failure = Failure::client(ClientError::Refused(WireError::new(code, "no")));
            assert_eq!(failure.kind.status(), status, "{code:?}");
        }
    }

    #[test]
    fn context_comes_first() {
        let failure = Failure::failed("access denied").context("create Root");
        assert_eq!(failure.message, "create Root: access denied");
    }
}
