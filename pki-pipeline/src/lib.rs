//! The request pipeline: how pkid takes a certificate request from
//! submission to an issued, held or refused certificate, and how officers
//! decide held requests and revoke certificates.
//!
//! The pipeline doesn't know how requests arrive. A front end, such as
//! pkid's local socket and later ACME, identifies the caller as a
//! [`Principal`] and calls the pipeline. Every right is checked here, against
//! the CA's `CaSecurity` and, through `pki-policy`, the template and the
//! name trees, and every outcome is recorded in `pki-store`.
//!
//! A held request is decided later, when the requester isn't present. The
//! pipeline therefore stores a snapshot of the requester's identity with
//! the request, and an officer's approval runs policy again for that
//! identity against the configuration as it then is. Nobody approves their
//! own request (R9).

mod authority;
mod error;
mod pipeline;

pub use authority::{
    Authority, Configuration, Directory, Principal, CA_ALL, CA_MANAGE, CA_OFFICER, CA_READ,
    CA_REQUEST, DEFAULT_CA_SDDL,
};
pub use error::PipelineError;
pub use pipeline::{Pipeline, Submission};
