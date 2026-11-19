//! The request and certificate commands: what a CA has been asked for,
//! what it issued, and revoking it.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use pkid_core::{
    AuthorityInfo, CertificateInfo, CertificateQuery, Outcome, Reply, Request, RequestInfo,
    RequestQuery, RequestStatus, SubmissionInfo, MAX_LISTING,
};
use serde_json::{json, Value};

use crate::cli::{Cert, RequestCommand, REASONS};
use crate::failure::{Failure, Kind};
use crate::files::{self, Reserved};
use crate::host::Host;
use crate::run::{call, resolve_ca, unexpected};
use crate::show::{self, Output};

/// The template `text` names among those `authority` offers.
fn offered(authority: &AuthorityInfo, text: &str) -> Result<String, Failure> {
    authority
        .templates
        .iter()
        .find(|t| t.id.eq_ignore_ascii_case(text) || t.name.to_lowercase() == text.to_lowercase())
        .map(|t| t.id.clone())
        .ok_or_else(|| {
            Failure::new(
                Kind::NotFound,
                format!("CA {} offers no template '{text}'", authority.name),
            )
        })
}

/// A template's name, where the CA still offers it.
fn template_name(authority: &AuthorityInfo, id: &str) -> String {
    authority
        .templates
        .iter()
        .find(|t| t.id.eq_ignore_ascii_case(id))
        .map(|t| t.name.clone())
        .unwrap_or_else(|| id.to_owned())
}

/// A serial number as the reader typed it: hex, with or without colons.
pub fn serial(text: &str) -> Result<Vec<u8>, Failure> {
    let digits: String = text.chars().filter(|c| *c != ':').collect();
    let bad = || Failure::usage(format!("'{text}' is not a serial number in hex"));
    if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(bad());
    }
    let digits = if digits.len() % 2 == 1 {
        format!("0{digits}")
    } else {
        digits
    };
    (0..digits.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&digits[at..at + 2], 16).map_err(|_| bad()))
        .collect()
}

fn reason_name(code: u8) -> String {
    REASONS
        .iter()
        .find(|(_, value)| *value == code)
        .map(|(name, _)| name.to_string())
        .unwrap_or_else(|| match code {
            6 => "certificate-hold".to_string(),
            other => other.to_string(),
        })
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

fn certificate_status(certificate: &CertificateInfo, now: i64) -> &'static str {
    if certificate.revocation.is_some() {
        "revoked"
    } else if certificate.not_after < now {
        "expired"
    } else {
        "valid"
    }
}

fn request_json(authority: &AuthorityInfo, request: &RequestInfo) -> Value {
    json!({
        "id": request.id,
        "status": request.status.as_str(),
        "template": request.template,
        "template_name": template_name(authority, &request.template),
        "names": request.names,
        "requester": request.requester,
        "submitted": show::time(request.submitted),
        "reasons": request.reasons,
        "decided": request.decided.map(show::time),
        "decider": request.decider,
    })
}

fn request_text(authority: &AuthorityInfo, request: &RequestInfo) -> String {
    let mut rows = vec![
        ("Request", request.id.to_string()),
        ("Status", request.status.as_str().to_string()),
        ("Template", template_name(authority, &request.template)),
        ("Names", request.names.join(", ")),
        ("Requester", request.requester.clone()),
        ("Submitted", show::time(request.submitted)),
    ];
    if let Some(decided) = request.decided {
        rows.push(("Decided", show::time(decided)));
    }
    if let Some(decider) = &request.decider {
        rows.push(("Decided by", decider.clone()));
    }
    if !request.reasons.is_empty() {
        rows.push(("Reasons", request.reasons.join("; ")));
    }
    show::fields(&rows)
}

fn certificate_json(certificate: &CertificateInfo, now: i64) -> Value {
    let summary = show::summary(&certificate.der);
    json!({
        "serial": show::hex(&certificate.serial),
        "request": certificate.request,
        "status": certificate_status(certificate, now),
        "subject": summary.as_ref().map(|s| s.subject.clone()),
        "not_before": show::time(certificate.not_before),
        "not_after": show::time(certificate.not_after),
        "owner": certificate.owner,
        "sha256": show::fingerprint(&certificate.der),
        "revocation": certificate.revocation.as_ref().map(|r| json!({
            "revoked": show::time(r.revoked),
            "reason": reason_name(r.reason),
            "revoker": r.revoker,
        })),
    })
}

fn certificate_text(certificate: &CertificateInfo, now: i64) -> String {
    let summary = show::summary(&certificate.der);
    let mut rows = vec![
        ("Serial", show::hex(&certificate.serial)),
        ("Request", certificate.request.to_string()),
        ("Status", certificate_status(certificate, now).to_string()),
    ];
    if let Some(summary) = &summary {
        rows.push(("Subject", summary.subject.clone()));
        rows.push(("Issuer", summary.issuer.clone()));
    }
    rows.push(("Valid from", show::time(certificate.not_before)));
    rows.push(("Valid until", show::time(certificate.not_after)));
    if let Some(owner) = &certificate.owner {
        rows.push(("Owner", owner.clone()));
    }
    rows.push(("SHA-256", show::fingerprint(&certificate.der)));
    if let Some(revocation) = &certificate.revocation {
        rows.push(("Revoked", show::time(revocation.revoked)));
        rows.push(("Reason", reason_name(revocation.reason)));
        rows.push(("Revoked by", revocation.revoker.clone()));
    }
    show::fields(&rows)
}

/// A certificate as a command's output: written to `out`, or printed in
/// PEM.
fn deliver(der: &[u8], out: Option<Reserved>, mut json: Value) -> Result<Output, Failure> {
    let pem = files::pem(files::CERTIFICATE, der);
    json["certificate"] = json!(pem);
    let text = match out {
        Some(file) => {
            let path = file.path().to_owned();
            file.write(pem.as_bytes())?;
            json["written"] = json!(path.display().to_string());
            format!("Wrote the certificate to {}.\n", path.display())
        }
        None => pem,
    };
    Ok(Output { json, text })
}

/// What became of a submitted or approved request.
fn outcome(
    authority: &AuthorityInfo,
    submission: SubmissionInfo,
    out: Option<Reserved>,
    approving: bool,
) -> Result<Output, Failure> {
    let id = submission.request;
    match submission.outcome {
        Outcome::Issued(der) => {
            let json = json!({"request": id, "status": "issued"});
            let mut output = deliver(&der, out, json)?;
            if approving && output.json.get("written").is_none() {
                output.text = format!("Approved request {id}.\n{}", output.text);
            }
            Ok(output)
        }
        Outcome::Pending => {
            let mut text = format!("Request {id} awaits approval");
            if !submission.reasons.is_empty() {
                text.push_str(&format!(": {}", submission.reasons.join("; ")));
            }
            text.push_str(&format!(
                ".\nOnce it is approved, fetch the certificate with:\n  pki cert get {} {id}\n",
                authority.id
            ));
            Ok(Output {
                json: json!({"request": id, "status": "pending", "reasons": submission.reasons}),
                text,
            })
        }
        Outcome::Denied => {
            let mut message = format!("request {id} was denied");
            if !submission.reasons.is_empty() {
                message.push_str(&format!(": {}", submission.reasons.join("; ")));
            }
            Err(Failure::failed(message))
        }
    }
}

fn reserve(out: Option<PathBuf>) -> Result<Option<Reserved>, Failure> {
    out.map(|path| Reserved::new(&path, false)).transpose()
}

/// Every page of a listing, each starting after the last record of the
/// one before.
fn all_pages<T>(
    mut page: impl FnMut(Option<i64>) -> Result<Vec<T>, Failure>,
    key: impl Fn(&T) -> i64,
) -> Result<Vec<T>, Failure> {
    let mut all = Vec::new();
    let mut after = None;
    loop {
        let records = page(after)?;
        let full = records.len() >= MAX_LISTING as usize;
        let last = records.last().map(&key);
        all.extend(records);
        match last {
            Some(last) if full && Some(last) != after => after = Some(last),
            _ => return Ok(all),
        }
    }
}

pub fn request(host: &dyn Host, command: RequestCommand) -> Result<Output, Failure> {
    match command {
        RequestCommand::Submit {
            ca,
            template,
            request,
            out,
        } => {
            let what = format!("submit {}", request.display());
            let authority = resolve_ca(host, &ca)?;
            let template = offered(&authority, &template)?;
            let csr = files::read_der(&request, files::REQUEST)?;
            let out = reserve(out)?;
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
            outcome(&authority, submission, out, false).map_err(|failure| failure.context(&what))
        }

        RequestCommand::List { ca, status } => {
            let authority = resolve_ca(host, &ca)?;
            let status = status.as_deref().and_then(RequestStatus::parse);
            let requests = all_pages(
                |after| {
                    let request = Request::Requests {
                        ca: authority.id.clone(),
                        query: RequestQuery {
                            status,
                            after,
                            limit: MAX_LISTING,
                        },
                    };
                    match call(host, &request, "list requests")? {
                        Reply::Requests(page) => Ok(page),
                        other => Err(unexpected(&other, "list requests")),
                    }
                },
                |request| request.id,
            )?;
            let text = if requests.is_empty() {
                "No requests.\n".to_string()
            } else {
                let rows: Vec<Vec<String>> = requests
                    .iter()
                    .map(|r| {
                        vec![
                            r.id.to_string(),
                            r.status.as_str().to_string(),
                            template_name(&authority, &r.template),
                            show::time(r.submitted),
                            r.names.join(", "),
                        ]
                    })
                    .collect();
                show::table(&["ID", "STATUS", "TEMPLATE", "SUBMITTED", "NAMES"], &rows)
            };
            Ok(Output {
                json: json!({
                    "requests": requests.iter().map(|r| request_json(&authority, r)).collect::<Vec<_>>(),
                }),
                text,
            })
        }

        RequestCommand::Show { ca, request } => {
            let authority = resolve_ca(host, &ca)?;
            let what = format!("show request {request}");
            let reply = call(
                host,
                &Request::Request {
                    ca: authority.id.clone(),
                    request,
                },
                &what,
            )?;
            let Reply::Request(info) = reply else {
                return Err(unexpected(&reply, &what));
            };
            Ok(Output {
                json: request_json(&authority, &info),
                text: request_text(&authority, &info),
            })
        }

        RequestCommand::Approve { ca, request, out } => {
            let what = format!("approve {request}");
            let authority = resolve_ca(host, &ca)?;
            let out = reserve(out)?;
            let reply = call(
                host,
                &Request::Approve {
                    ca: authority.id.clone(),
                    request,
                },
                &what,
            )?;
            let Reply::Submission(submission) = reply else {
                return Err(unexpected(&reply, &what));
            };
            outcome(&authority, submission, out, true).map_err(|failure| failure.context(&what))
        }

        RequestCommand::Deny {
            ca,
            request,
            reason,
        } => {
            let what = format!("deny {request}");
            let authority = resolve_ca(host, &ca)?;
            match call(
                host,
                &Request::Deny {
                    ca: authority.id.clone(),
                    request,
                    reason,
                },
                &what,
            )? {
                Reply::Done => Ok(Output {
                    json: json!({"request": request, "status": "denied"}),
                    text: format!("Denied request {request}.\n"),
                }),
                other => Err(unexpected(&other, &what)),
            }
        }
    }
}

pub fn cert(host: &dyn Host, command: Cert) -> Result<Output, Failure> {
    let now = now();
    match command {
        Cert::List { ca, unrevoked } => {
            let authority = resolve_ca(host, &ca)?;
            let certificates = all_pages(
                |after| {
                    let request = Request::Certificates {
                        ca: authority.id.clone(),
                        query: CertificateQuery {
                            unrevoked_only: unrevoked,
                            after,
                            limit: MAX_LISTING,
                        },
                    };
                    match call(host, &request, "list certificates")? {
                        Reply::Certificates(page) => Ok(page),
                        other => Err(unexpected(&other, "list certificates")),
                    }
                },
                |certificate| certificate.request,
            )?;
            let text = if certificates.is_empty() {
                "No certificates.\n".to_string()
            } else {
                let rows: Vec<Vec<String>> = certificates
                    .iter()
                    .map(|c| {
                        vec![
                            show::hex(&c.serial),
                            c.request.to_string(),
                            certificate_status(c, now).to_string(),
                            show::time(c.not_after),
                            show::summary(&c.der).map(|s| s.subject).unwrap_or_default(),
                        ]
                    })
                    .collect();
                show::table(
                    &["SERIAL", "REQUEST", "STATUS", "EXPIRES", "SUBJECT"],
                    &rows,
                )
            };
            Ok(Output {
                json: json!({
                    "certificates": certificates.iter().map(|c| certificate_json(c, now)).collect::<Vec<_>>(),
                }),
                text,
            })
        }

        Cert::Show {
            ca,
            serial: text,
            out,
        } => {
            let what = format!("show {text}");
            let number = serial(&text)?;
            let authority = resolve_ca(host, &ca)?;
            let out = reserve(out)?;
            let reply = call(
                host,
                &Request::Certificate {
                    ca: authority.id,
                    serial: number,
                },
                &what,
            )?;
            let Reply::Certificate(certificate) = reply else {
                return Err(unexpected(&reply, &what));
            };
            let mut output = Output {
                json: certificate_json(&certificate, now),
                text: certificate_text(&certificate, now),
            };
            if let Some(file) = out {
                let path = file.path().to_owned();
                file.write(files::pem(files::CERTIFICATE, &certificate.der).as_bytes())?;
                output
                    .text
                    .push_str(&format!("\nWrote it to {}.\n", path.display()));
                output.json["written"] = json!(path.display().to_string());
            }
            Ok(output)
        }

        Cert::Get { ca, request, out } => {
            let what = format!("get {request}");
            let authority = resolve_ca(host, &ca)?;
            let out = reserve(out)?;
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
            let json = certificate_json(&certificate, now);
            deliver(&certificate.der, out, json)
        }

        Cert::Revoke {
            ca,
            serial: text,
            reason,
        } => {
            let what = format!("revoke {text}");
            let number = serial(&text)?;
            let code = REASONS
                .iter()
                .find(|(name, _)| *name == reason)
                .map(|(_, code)| *code)
                .expect("clap allows only the reasons offered");
            let authority = resolve_ca(host, &ca)?;
            match call(
                host,
                &Request::Revoke {
                    ca: authority.id,
                    serial: number.clone(),
                    reason: code,
                },
                &what,
            )? {
                Reply::Done => Ok(Output {
                    json: json!({"revoked": show::hex(&number), "reason": reason}),
                    text: format!("Revoked certificate {}.\n", show::hex(&number)),
                }),
                other => Err(unexpected(&other, &what)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serials_take_colons_and_odd_lengths() {
        assert_eq!(serial("0a:FF").unwrap(), [0x0a, 0xff]);
        assert_eq!(serial("abc").unwrap(), [0x0a, 0xbc]);
        assert!(serial("").is_err());
        assert!(serial("xyz").is_err());
        assert!(serial("0x12").is_err());
    }

    #[test]
    fn every_offered_reason_has_its_rfc_5280_code() {
        assert_eq!(reason_name(1), "key-compromise");
        assert_eq!(reason_name(9), "privilege-withdrawn");
        assert_eq!(reason_name(6), "certificate-hold");
    }

    #[test]
    fn listings_follow_pages_to_the_end() {
        let full = MAX_LISTING as i64;
        let mut asked = Vec::new();
        let all = all_pages(
            |after| {
                asked.push(after);
                let start = after.unwrap_or(0);
                let end = (start + full).min(full + 5);
                Ok((start + 1..=end).collect::<Vec<i64>>())
            },
            |id| *id,
        )
        .unwrap();
        assert_eq!(all.len() as i64, full + 5);
        assert_eq!(asked, [None, Some(full)]);
    }
}
