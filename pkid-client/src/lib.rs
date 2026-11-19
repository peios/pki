//! The client for pkid's control socket.
//!
//! Every call opens a connection, sends one request and reads one reply.
//! pkid authorizes it with the caller's own token, which the kernel conveys
//! when the client connects, so a call can do exactly what its caller may.
//! The client raises nothing: it refuses to talk to a server that isn't
//! pkid, so a caller's requests and keys' certificates never reach an
//! impostor listening at the socket's path.

use std::fmt;
use std::io::{self, Read, Write};
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use peios::security::Sid;
use peios::token::Token;
use pkid_core::{
    read_frame, write_frame, AuthorityInfo, CertificateInfo, CertificateQuery, FrameError,
    Passphrase, Reply, Request, RequestInfo, RequestQuery, SubmissionInfo, WireError,
    MAX_REPLY_BYTES, SERVICE_SID, SOCKET_PATH,
};
use zeroize::Zeroizing;

/// How long a call may wait on pkid before giving up.
const TIMEOUT: Duration = Duration::from_secs(30);

/// Why a call failed.
#[derive(Debug)]
pub enum ClientError {
    /// pkid isn't running, or its socket can't be reached.
    Unavailable(io::Error),
    /// The server at the socket isn't pkid.
    NotPkid(String),
    /// pkid refused or failed the request.
    Refused(WireError),
    /// pkid's reply couldn't be understood.
    Protocol(String),
    /// The connection failed part-way.
    Io(io::Error),
}

impl fmt::Display for ClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(error) => write!(formatter, "pkid is not available: {error}"),
            Self::NotPkid(who) => write!(formatter, "the server is not pkid but {who}"),
            Self::Refused(error) => error.fmt(formatter),
            Self::Protocol(detail) => write!(formatter, "unexpected reply from pkid: {detail}"),
            Self::Io(error) => write!(formatter, "connection to pkid failed: {error}"),
        }
    }
}

impl std::error::Error for ClientError {}

/// A connection point for pkid.
#[derive(Debug, Clone)]
pub struct Client {
    path: PathBuf,
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

impl Client {
    /// pkid at its usual socket.
    pub fn new() -> Self {
        Self {
            path: PathBuf::from(SOCKET_PATH),
        }
    }

    /// Sends `request` and returns pkid's reply.
    pub fn call(&self, request: &Request) -> Result<Reply, ClientError> {
        let mut stream = UnixStream::connect(&self.path).map_err(ClientError::Unavailable)?;
        verify_server(&stream)?;
        stream
            .set_read_timeout(Some(TIMEOUT))
            .and_then(|()| stream.set_write_timeout(Some(TIMEOUT)))
            .map_err(ClientError::Io)?;
        exchange(&mut stream, request)
    }

    pub fn authorities(&self) -> Result<Vec<AuthorityInfo>, ClientError> {
        match self.call(&Request::Authorities)? {
            Reply::Authorities(authorities) => Ok(authorities),
            other => Err(unexpected(&other)),
        }
    }

    /// Submits a DER certificate request.
    pub fn submit(
        &self,
        ca: &str,
        template: &str,
        csr: &[u8],
    ) -> Result<SubmissionInfo, ClientError> {
        self.submission(&Request::Submit {
            ca: ca.into(),
            template: template.into(),
            csr: csr.to_vec(),
        })
    }

    pub fn approve(&self, ca: &str, request: i64) -> Result<SubmissionInfo, ClientError> {
        self.submission(&Request::Approve {
            ca: ca.into(),
            request,
        })
    }

    pub fn deny(&self, ca: &str, request: i64, reason: Option<&str>) -> Result<(), ClientError> {
        self.done(&Request::Deny {
            ca: ca.into(),
            request,
            reason: reason.map(str::to_owned),
        })
    }

    /// Revokes a certificate, with an RFC 5280 reason code.
    pub fn revoke(&self, ca: &str, serial: &[u8], reason: u8) -> Result<(), ClientError> {
        self.done(&Request::Revoke {
            ca: ca.into(),
            serial: serial.to_vec(),
            reason,
        })
    }

    pub fn request(&self, ca: &str, request: i64) -> Result<RequestInfo, ClientError> {
        match self.call(&Request::Request {
            ca: ca.into(),
            request,
        })? {
            Reply::Request(request) => Ok(request),
            other => Err(unexpected(&other)),
        }
    }

    pub fn requests(&self, ca: &str, query: RequestQuery) -> Result<Vec<RequestInfo>, ClientError> {
        match self.call(&Request::Requests {
            ca: ca.into(),
            query,
        })? {
            Reply::Requests(requests) => Ok(requests),
            other => Err(unexpected(&other)),
        }
    }

    pub fn certificate(&self, ca: &str, serial: &[u8]) -> Result<CertificateInfo, ClientError> {
        self.one_certificate(&Request::Certificate {
            ca: ca.into(),
            serial: serial.to_vec(),
        })
    }

    /// The certificate issued for a request, such as one an officer has
    /// since approved.
    pub fn certificate_for(&self, ca: &str, request: i64) -> Result<CertificateInfo, ClientError> {
        self.one_certificate(&Request::CertificateFor {
            ca: ca.into(),
            request,
        })
    }

    pub fn certificates(
        &self,
        ca: &str,
        query: CertificateQuery,
    ) -> Result<Vec<CertificateInfo>, ClientError> {
        match self.call(&Request::Certificates {
            ca: ca.into(),
            query,
        })? {
            Reply::Certificates(certificates) => Ok(certificates),
            other => Err(unexpected(&other)),
        }
    }

    /// Creates, installs, imports or changes a CA: any request whose reply
    /// is the CA as it now stands.
    pub fn manage(&self, request: &Request) -> Result<AuthorityInfo, ClientError> {
        match self.call(request)? {
            Reply::Authority(authority) => Ok(authority),
            other => Err(unexpected(&other)),
        }
    }

    /// Signs a subordinate CA's request for a CA elsewhere, returning its
    /// DER certificate.
    pub fn sign_subordinate(&self, request: &Request) -> Result<Vec<u8>, ClientError> {
        match self.call(request)? {
            Reply::Signed(certificate) => Ok(certificate),
            other => Err(unexpected(&other)),
        }
    }

    /// Exports a CA's key as a sealed key file.
    pub fn export_key(
        &self,
        ca: &str,
        current: Option<Passphrase>,
        passphrase: Passphrase,
    ) -> Result<Vec<u8>, ClientError> {
        match self.call(&Request::ExportKey {
            ca: ca.into(),
            current,
            passphrase,
        })? {
            Reply::SealedKey(sealed) => Ok(sealed),
            other => Err(unexpected(&other)),
        }
    }

    fn submission(&self, request: &Request) -> Result<SubmissionInfo, ClientError> {
        match self.call(request)? {
            Reply::Submission(submission) => Ok(submission),
            other => Err(unexpected(&other)),
        }
    }

    fn done(&self, request: &Request) -> Result<(), ClientError> {
        match self.call(request)? {
            Reply::Done => Ok(()),
            other => Err(unexpected(&other)),
        }
    }

    fn one_certificate(&self, request: &Request) -> Result<CertificateInfo, ClientError> {
        match self.call(request)? {
            Reply::Certificate(certificate) => Ok(certificate),
            other => Err(unexpected(&other)),
        }
    }
}

/// Refuses a server whose identity, as the kernel captured it when it
/// listened, isn't pkid's service SID.
fn verify_server(stream: &UnixStream) -> Result<(), ClientError> {
    let expected: Sid = SERVICE_SID.parse().expect("SERVICE_SID is a valid SID");
    let server = Token::open_peer(stream.as_fd())
        .and_then(|token| token.user())
        .map_err(|error| ClientError::NotPkid(format!("an unidentifiable peer ({error})")))?;
    if server == expected {
        Ok(())
    } else {
        Err(ClientError::NotPkid(server.to_string()))
    }
}

/// One request and its reply over an established connection.
pub fn exchange(stream: &mut (impl Read + Write), request: &Request) -> Result<Reply, ClientError> {
    // The request may carry passphrases, so its encoding is wiped once sent.
    let payload = Zeroizing::new(
        request
            .encode()
            .map_err(|error| ClientError::Protocol(error.to_string()))?,
    );
    write_frame(stream, &payload).map_err(ClientError::Io)?;
    let reply = read_frame(stream, MAX_REPLY_BYTES).map_err(|error| match error {
        FrameError::TooLarge(length) => {
            ClientError::Protocol(format!("a {length}-byte reply is too large"))
        }
        FrameError::Io(error) => ClientError::Io(error),
    })?;
    Reply::decode(&reply)
        .map_err(|error| ClientError::Protocol(error.to_string()))?
        .map_err(ClientError::Refused)
}

fn unexpected(reply: &Reply) -> ClientError {
    ClientError::Protocol(format!("{reply:?}"))
}
