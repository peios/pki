//! pkid, the Peios certificate authority service.
//!
//! pkid owns the CAs' online keys and the CA database, and answers requests
//! on its control socket. Every request is authorized against the caller's
//! token, which the kernel captures when the caller connects; pkid never
//! acts as its caller. The portable crates decide everything: `pki-policy`
//! what may be issued, `pki-pipeline` the request flow, `pki-store` what is
//! recorded. This crate connects them to the Registry, KACS, eventd and the
//! socket.

pub mod config;
pub mod dispatch;
pub mod events;
pub mod identity;
pub mod keystore;
pub mod provision;
pub mod registry;
pub mod server;
pub mod service;
