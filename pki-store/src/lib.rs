//! The CA database: every request pkid receives, every certificate it
//! issues and every revocation.
//!
//! The store records decisions; it doesn't make them. The request pipeline
//! evaluates policy and checks rights, then records the outcome here. Two
//! rules are also enforced by the store itself, so that no caller can break
//! them: a request is decided at most once, and nobody approves their own
//! request (R9). The approver of every issued request is recorded.
//!
//! The database is SQLite, opened by one owner at a time.

mod error;
mod store;
mod types;

pub use error::StoreError;
pub use store::Store;
pub use types::{
    Certificate, CertificateFilter, NewCertificate, NewRequest, Request, RequestFilter, RequestId,
    RequestStatus, Revocation,
};
