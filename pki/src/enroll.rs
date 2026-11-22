//! `pki enroll`: a key made here, certified by a CA, and saved with its
//! certificates as a PKCS #12 file for other software to import. The key
//! never leaves this machine except in that file: pkid sees only the
//! request.

use std::path::{Path, PathBuf};

use pki_core::{leaf_request, AltName, DnsName, Mailbox, UserPrincipalName};
use pki_keys::{open_sealed_key, seal_key, KeyAlgorithm, NewPassphrase, PrivateKey};
use pkid_core::{AuthorityInfo, Outcome, Reply, Request};
use serde_json::json;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::cli::Enroll;
use crate::failure::Failure;
use crate::files::{self, Reserved};
use crate::host::Host;
use crate::issue::offered;
use crate::run::{call, existing_passphrase, new_passphrase, resolve_ca, unexpected};
use crate::show::{self, Output};

/// The most CAs above a certificate that pki looks for.
const MAX_CHAIN: usize = 8;

fn algorithm(name: &str) -> KeyAlgorithm {
    match name {
        "ecdsa-p384" => KeyAlgorithm::EcdsaP384,
        "rsa-2048" => KeyAlgorithm::Rsa2048,
        "rsa-3072" => KeyAlgorithm::Rsa3072,
        "rsa-4096" => KeyAlgorithm::Rsa4096,
        _ => KeyAlgorithm::EcdsaP256,
    }
}

fn names(enroll: &Enroll) -> Result<Vec<AltName>, Failure> {
    let bad = |error: pki_core::Error| Failure::usage(error.to_string());
    let mut names = Vec::new();
    for name in &enroll.dns {
        names.push(AltName::Dns(DnsName::new(name).map_err(bad)?));
    }
    for address in &enroll.emails {
        names.push(AltName::Email(Mailbox::new(address).map_err(bad)?));
    }
    for name in &enroll.upns {
        names.push(AltName::Upn(UserPrincipalName::new(name).map_err(bad)?));
    }
    if names.is_empty() {
        return Err(Failure::usage(
            "give at least one of --dns, --email or --upn",
        ));
    }
    Ok(names)
}

/// Where a key is kept while its request awaits approval.
fn pending_path(out: &Path) -> PathBuf {
    let mut path = out.as_os_str().to_owned();
    path.push(".key");
    PathBuf::from(path)
}

/// The CA certificates above `certificate` that this pkid holds, nearest
/// first, matched by issuer and subject names.
fn chain(authorities: &[AuthorityInfo], certificate: &[u8]) -> Vec<Vec<u8>> {
    let mut chain: Vec<Vec<u8>> = Vec::new();
    let mut current = certificate.to_vec();
    while chain.len() < MAX_CHAIN {
        let Ok((_, child)) = X509Certificate::from_der(&current) else {
            break;
        };
        if child.subject().as_raw() == child.issuer().as_raw() && !chain.is_empty() {
            break;
        }
        let issuer = authorities
            .iter()
            .filter_map(|a| a.certificate.as_ref())
            .find(|der| {
                X509Certificate::from_der(der).is_ok_and(|(_, ca)| {
                    ca.subject().as_raw() == child.issuer().as_raw() && **der != current
                })
            });
        let Some(issuer) = issuer else {
            break;
        };
        if chain.contains(issuer) {
            break;
        }
        chain.push(issuer.clone());
        current = issuer.clone();
    }
    chain
}

/// The PKCS #12 file for `key` and `certificate`.
fn package(
    authorities: &[AuthorityInfo],
    key: &PrivateKey,
    certificate: &[u8],
    friendly_name: Option<&str>,
    passphrase: &str,
) -> Result<Vec<u8>, Failure> {
    let chain = chain(authorities, certificate);
    let chain: Vec<&[u8]> = chain.iter().map(Vec::as_slice).collect();
    peios_crypto::pkcs12::write(key, certificate, &chain, friendly_name, passphrase)
        .map_err(|error| Failure::failed(format!("writing the PKCS #12 file: {error}")))
}

fn text(passphrase: &pkid_core::Passphrase) -> Result<&str, Failure> {
    std::str::from_utf8(passphrase.expose())
        .map_err(|_| Failure::failed("the passphrase is not UTF-8 text"))
}

fn issued_output(out: &Path, certificate: &[u8], request: i64) -> Output {
    let summary = show::summary(certificate);
    Output {
        json: json!({
            "request": request,
            "status": "issued",
            "written": out.display().to_string(),
            "subject": summary.as_ref().map(|s| s.subject.clone()),
            "not_after": summary.as_ref().map(|s| s.not_after.clone()),
        }),
        text: format!("Wrote the key and certificate to {}.\n", out.display()),
    }
}

pub fn enroll(host: &dyn Host, enroll: Enroll) -> Result<Output, Failure> {
    match enroll.request {
        Some(request) => collect(host, &enroll, request),
        None => request(host, &enroll),
    }
}

fn request(host: &dyn Host, enroll: &Enroll) -> Result<Output, Failure> {
    let names = names(enroll)?;
    let template = enroll
        .template
        .as_deref()
        .expect("clap requires a template");
    let what = format!("enroll {}", names[0]);
    let authority = resolve_ca(host, &enroll.ca)?;
    let template = offered(&authority, template)?;
    let reserve = |path: &Path| {
        if enroll.replace {
            Reserved::replacing(path, true)
        } else {
            Reserved::new(path, true)
        }
    };
    let out = reserve(&enroll.out)?;
    let pending = reserve(&pending_path(&enroll.out))?;
    let passphrase = new_passphrase(
        host,
        enroll.passphrase_file.as_deref(),
        &format!("Passphrase for {}: ", enroll.out.display()),
    )?;
    let key = PrivateKey::generate(algorithm(&enroll.algorithm))
        .map_err(|error| Failure::failed(format!("making a key: {error}")).context(&what))?;
    let csr = leaf_request(&key, &names)
        .map_err(|error| Failure::failed(error.to_string()).context(&what))?;
    let reply = call(
        host,
        &Request::Submit {
            ca: authority.id.clone(),
            template,
            csr,
        },
        &what,
    )?;
    let Reply::Submission(submission) = reply else {
        return Err(unexpected(&reply, &what));
    };
    let friendly = enroll
        .friendly_name
        .clone()
        .unwrap_or_else(|| names[0].to_string());
    match submission.outcome {
        Outcome::Issued(certificate) => {
            let authorities = all_authorities(host)?;
            let file = package(
                &authorities,
                &key,
                &certificate,
                Some(&friendly),
                text(&passphrase)?,
            )?;
            out.write(&file)?;
            drop(pending);
            Ok(issued_output(&enroll.out, &certificate, submission.request))
        }
        Outcome::Pending => {
            // The key exists only here, so it is kept, sealed under the
            // same passphrase, until the certificate can be collected.
            let seal = NewPassphrase::new(text(&passphrase)?)
                .map_err(|error| Failure::failed(error.to_string()))?;
            let sealed = seal_key(&key, &seal)
                .map_err(|error| Failure::failed(error.to_string()).context(&what))?;
            let key_path = pending_path(&enroll.out);
            pending.write(&sealed)?;
            drop(out);
            let id = submission.request;
            let mut text = format!("Request {id} awaits approval");
            if !submission.reasons.is_empty() {
                text.push_str(&format!(": {}", submission.reasons.join("; ")));
            }
            text.push_str(&format!(
                ".\nIts key is sealed in {}. Once the request is approved, run:\n  pki enroll {} --request {id} --key {} --out {}\n",
                key_path.display(),
                authority.id,
                key_path.display(),
                enroll.out.display(),
            ));
            Ok(Output {
                json: json!({
                    "request": id,
                    "status": "pending",
                    "reasons": submission.reasons,
                    "key_file": key_path.display().to_string(),
                }),
                text,
            })
        }
        Outcome::Denied => {
            let mut message = format!("request {} was denied", submission.request);
            if !submission.reasons.is_empty() {
                message.push_str(&format!(": {}", submission.reasons.join("; ")));
            }
            Err(Failure::failed(message).context(&what))
        }
    }
}

fn collect(host: &dyn Host, enroll: &Enroll, request: i64) -> Result<Output, Failure> {
    let what = format!("enroll --request {request}");
    let key_path = enroll.key.as_deref().expect("clap requires a key");
    let authority = resolve_ca(host, &enroll.ca)?;
    let sealed = files::read(key_path)?;
    let out = if enroll.replace {
        Reserved::replacing(&enroll.out, true)?
    } else {
        Reserved::new(&enroll.out, true)?
    };
    // The certificate first: while the request is still held there is
    // nothing to ask the passphrase for.
    let reply = call(
        host,
        &Request::CertificateFor {
            ca: authority.id,
            request,
        },
        &what,
    )?;
    let Reply::Certificate(certificate) = reply else {
        return Err(unexpected(&reply, &what));
    };
    let passphrase = existing_passphrase(
        host,
        enroll.passphrase_file.as_deref(),
        &format!("Passphrase for {}: ", key_path.display()),
    )?;
    let text = text(&passphrase)?;
    let key = open_sealed_key(&sealed, &pki_keys::Passphrase::new(text))
        .map_err(|error| Failure::failed(error.to_string()).context(key_path.display()))?;
    let friendly = match &enroll.friendly_name {
        Some(name) => Some(name.clone()),
        None => show::summary(&certificate.der).map(|s| s.subject),
    };
    let authorities = all_authorities(host)?;
    let file = package(
        &authorities,
        &key,
        &certificate.der,
        friendly.as_deref().filter(|name| !name.is_empty()),
        text,
    )
    .map_err(|failure| {
        failure.hint(format!(
            "Check that {} holds the key request {request} was made with.",
            key_path.display()
        ))
    })?;
    out.write(&file)?;
    let mut output = issued_output(&enroll.out, &certificate.der, request);
    output.text.push_str(&format!(
        "{} is no longer needed; delete it once the file has been imported.\n",
        key_path.display()
    ));
    Ok(output)
}

fn all_authorities(host: &dyn Host) -> Result<Vec<AuthorityInfo>, Failure> {
    match call(host, &Request::Authorities, "list CAs")? {
        Reply::Authorities(authorities) => Ok(authorities),
        other => Err(unexpected(&other, "list CAs")),
    }
}

#[cfg(test)]
pub fn tests_pending_path(out: &Path) -> PathBuf {
    pending_path(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_held_key_is_kept_beside_its_file() {
        assert_eq!(
            pending_path(Path::new("/tmp/www.p12")),
            PathBuf::from("/tmp/www.p12.key")
        );
    }

    #[test]
    fn algorithms_default_to_p256() {
        assert_eq!(algorithm("ecdsa-p256"), KeyAlgorithm::EcdsaP256);
        assert_eq!(algorithm("rsa-3072"), KeyAlgorithm::Rsa3072);
    }
}
