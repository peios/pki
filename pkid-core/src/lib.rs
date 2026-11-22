//! pkid's control wire.
//!
//! The socket is a PSPU observability query channel (§3.15): a
//! `SOCK_STREAM` socket carrying length-prefixed MessagePack maps, one
//! request and one reply per connection.
//!
//! ```text
//! +---------------------+------------------------+
//! | length u32 LE       | payload (MessagePack)  |
//! +---------------------+------------------------+
//! ```
//!
//! A request is a map whose `op` names the operation. A reply is a map whose
//! `status` is `ok`, with a `kind` naming the result, or `error`, with a
//! `code` and a `message`. Unknown keys are ignored and duplicate keys are
//! refused, as §3.15 requires.
//!
//! pkid authorizes every request against the caller's token, captured by
//! the kernel when it connected, so the wire carries no credentials. This
//! crate is inert: types and a codec, nothing that acts.

mod codec;
mod message;

pub use codec::{read_frame, write_frame, CodecError, FrameError};
pub use message::{
    AccessInfo, AuthorityInfo, CertificateInfo, CertificateQuery, CrlInfo, ErrorCode, Issuer,
    KeySpec, Outcome, Passphrase, Reply, Request, RequestInfo, RequestQuery, RequestStatus,
    RevocationInfo, SubmissionInfo, TemplateInfo, WireError,
};

/// pkid's runtime directory, which peinit creates (`RuntimeDirectories`).
pub const RUN_DIR: &str = "/run/pkid";
/// The control socket.
pub const SOCKET_PATH: &str = "/run/pkid/pki.sock";

/// pkid's service name.
pub const SERVICE_NAME: &str = "pkid";
/// pkid's service SID, derived from [`SERVICE_NAME`] by peinit's rule: the
/// SHA-1 of the name, uppercased and in UTF-16LE, as five little-endian
/// 32-bit sub-authorities under `S-1-5-80`. Clients check that the server
/// they reach has it.
pub const SERVICE_SID: &str = "S-1-5-80-927106304-3681130234-3843647545-210868499-909250352";

/// The service that serves pkid's published CRLs over HTTP.
pub const HTTPD_SERVICE_NAME: &str = "pki-httpd";
/// Its service SID, by the same rule as [`SERVICE_SID`].
pub const HTTPD_SERVICE_SID: &str =
    "S-1-5-80-4101192810-2505649581-2921298127-1686389970-3617382032";

/// The largest request payload pkid reads. A certificate request is a few
/// kilobytes at most.
pub const MAX_REQUEST_BYTES: usize = 1 << 20;
/// The largest reply payload a client reads. Listings are paged to stay
/// well within it.
pub const MAX_REPLY_BYTES: usize = 16 << 20;
/// The most records one listing returns, whatever limit is asked for.
pub const MAX_LISTING: u32 = 1000;
