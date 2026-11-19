//! The control wire's codec.

use pkid_core::{
    read_frame, write_frame, AuthorityInfo, CertificateInfo, CertificateQuery, ErrorCode,
    FrameError, Issuer, KeySpec, Outcome, Passphrase, Reply, Request, RequestInfo, RequestQuery,
    RequestStatus, RevocationInfo, SubmissionInfo, TemplateInfo, WireError, MAX_LISTING,
    SERVICE_NAME, SERVICE_SID,
};
use sha1::{Digest, Sha1};

#[test]
fn the_service_sid_follows_peinits_rule() {
    let name: Vec<u8> = SERVICE_NAME
        .to_uppercase()
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let digest = Sha1::digest(&name);
    let parts: Vec<String> = digest
        .chunks(4)
        .map(|chunk| u32::from_le_bytes(chunk.try_into().unwrap()).to_string())
        .collect();
    assert_eq!(SERVICE_SID, format!("S-1-5-80-{}", parts.join("-")));
}

#[test]
fn requests_round_trip() {
    let requests = [
        Request::Authorities,
        Request::Submit {
            ca: "issuing".into(),
            template: "server".into(),
            csr: vec![0x30, 0x82, 0x01],
        },
        Request::Approve {
            ca: "issuing".into(),
            request: 7,
        },
        Request::Deny {
            ca: "issuing".into(),
            request: 7,
            reason: Some("not a lab host".into()),
        },
        Request::Deny {
            ca: "issuing".into(),
            request: 8,
            reason: None,
        },
        Request::Revoke {
            ca: "issuing".into(),
            serial: vec![0x12, 0x34],
            reason: 1,
        },
        Request::Request {
            ca: "issuing".into(),
            request: 3,
        },
        Request::Requests {
            ca: "issuing".into(),
            query: RequestQuery {
                status: Some(RequestStatus::Pending),
                after: Some(10),
                limit: 50,
            },
        },
        Request::Requests {
            ca: "issuing".into(),
            query: RequestQuery::default(),
        },
        Request::Certificate {
            ca: "issuing".into(),
            serial: vec![0x01],
        },
        Request::CertificateFor {
            ca: "issuing".into(),
            request: 3,
        },
        Request::Certificates {
            ca: "issuing".into(),
            query: CertificateQuery {
                unrevoked_only: true,
                after: None,
                limit: 20,
            },
        },
    ];
    for request in requests {
        let decoded = Request::decode(&request.encode().unwrap()).unwrap();
        assert_eq!(decoded, request);
    }
}

#[test]
fn management_requests_round_trip() {
    let service_key = KeySpec {
        provider: "service".into(),
        locator: None,
        algorithm: Some("ecdsa-p384".into()),
        exportable: true,
        passphrase: None,
    };
    let file_key = KeySpec {
        provider: "file".into(),
        locator: Some("/media/usb/root.key".into()),
        algorithm: Some("rsa-4096".into()),
        exportable: true,
        passphrase: Some(Passphrase::new(b"correct horse battery staple".to_vec())),
    };
    let requests = [
        Request::CreateAuthority {
            name: "Home Root CA".into(),
            key: file_key.clone(),
            issuer: Issuer::SelfSigned,
            lifetime_days: 7300,
            path_length: Some(1),
            templates: Vec::new(),
            crl_distribution_points: Vec::new(),
        },
        Request::CreateAuthority {
            name: "Home Issuing CA".into(),
            key: service_key.clone(),
            issuer: Issuer::Authority {
                ca: "root".into(),
                passphrase: Some(Passphrase::new(b"root passphrase".to_vec())),
            },
            lifetime_days: 1825,
            path_length: Some(0),
            templates: vec!["server".into()],
            crl_distribution_points: vec!["http://pki.home/issuing.crl".into()],
        },
        Request::CreateAuthority {
            name: "Lab CA".into(),
            key: service_key.clone(),
            issuer: Issuer::Offline,
            lifetime_days: 1825,
            path_length: None,
            templates: Vec::new(),
            crl_distribution_points: Vec::new(),
        },
        Request::SignSubordinate {
            ca: "root".into(),
            csr: vec![0x30, 0x01],
            name: "Lab CA".into(),
            lifetime_days: 1825,
            path_length: Some(0),
            passphrase: None,
        },
        Request::InstallAuthority {
            ca: "lab".into(),
            certificate: vec![0x30, 0x02],
        },
        Request::ImportAuthority {
            name: "Old Root".into(),
            certificate: vec![0x30, 0x03],
            sealed_key: b"PEIOSKEY".to_vec(),
            passphrase: Passphrase::new(b"backup passphrase".to_vec()),
            key: service_key,
            templates: Vec::new(),
            crl_distribution_points: Vec::new(),
        },
        Request::ExportKey {
            ca: "issuing".into(),
            current: None,
            passphrase: Passphrase::new(b"a long backup passphrase".to_vec()),
        },
        Request::ConfigureAuthority {
            ca: "issuing".into(),
            templates: Some(vec!["server".into(), "device".into()]),
            crl_distribution_points: None,
        },
    ];
    for request in requests {
        let decoded = Request::decode(&request.encode().unwrap()).unwrap();
        assert_eq!(decoded, request);
    }
}

#[test]
fn passphrases_are_never_printed() {
    let request = Request::ExportKey {
        ca: "issuing".into(),
        current: Some(Passphrase::new(b"the current secret".to_vec())),
        passphrase: Passphrase::new(b"the new secret".to_vec()),
    };
    let printed = format!("{request:?}");
    assert!(!printed.contains("secret"), "{printed}");
}

#[test]
fn listings_are_capped() {
    let request = Request::Requests {
        ca: "issuing".into(),
        query: RequestQuery {
            limit: u32::MAX,
            ..RequestQuery::default()
        },
    };
    let Request::Requests { query, .. } = Request::decode(&request.encode().unwrap()).unwrap()
    else {
        unreachable!()
    };
    assert_eq!(query.limit, MAX_LISTING);
}

fn certificate(revoked: bool) -> CertificateInfo {
    CertificateInfo {
        serial: vec![0x12, 0x34],
        request: 3,
        der: vec![0x30, 0x03],
        not_before: 1_800_000_000,
        not_after: 1_830_000_000,
        owner: Some("S-1-5-80-1-2-3".into()),
        revocation: revoked.then(|| RevocationInfo {
            revoked: 1_810_000_000,
            reason: 1,
            revoker: "S-1-5-21-1-2-3-1002".into(),
        }),
    }
}

fn request_info(status: RequestStatus) -> RequestInfo {
    RequestInfo {
        id: 3,
        template: "server".into(),
        names: vec!["radius.home".into()],
        requester: "S-1-5-80-1-2-3".into(),
        submitted: 1_800_000_000,
        status,
        reasons: vec!["Server requires approval".into()],
        decided: (status != RequestStatus::Pending).then_some(1_800_000_100),
        decider: (status == RequestStatus::Issued).then(|| "S-1-5-21-1-2-3-1002".into()),
    }
}

#[test]
fn replies_round_trip() {
    let replies: Vec<Result<Reply, WireError>> = vec![
        Ok(Reply::Done),
        Ok(Reply::Authorities(vec![
            AuthorityInfo {
                id: "issuing".into(),
                name: "Home Issuing CA".into(),
                certificate: Some(vec![0x30, 0x01]),
                request: None,
                key: "service:issuing".into(),
                templates: vec![TemplateInfo {
                    id: "server".into(),
                    name: "Server".into(),
                }],
                key_available: true,
            },
            AuthorityInfo {
                id: "lab".into(),
                name: "Lab CA".into(),
                certificate: None,
                request: Some(vec![0x30, 0x02]),
                key: "service:lab".into(),
                templates: Vec::new(),
                key_available: true,
            },
        ])),
        Ok(Reply::Signed(vec![0x30, 0x03])),
        Ok(Reply::SealedKey(b"PEIOSKEY".to_vec())),
        Ok(Reply::Submission(SubmissionInfo {
            request: 4,
            outcome: Outcome::Issued(vec![0x30, 0x02]),
            reasons: Vec::new(),
        })),
        Ok(Reply::Submission(SubmissionInfo {
            request: 5,
            outcome: Outcome::Pending,
            reasons: vec!["Server requires approval".into()],
        })),
        Ok(Reply::Submission(SubmissionInfo {
            request: 6,
            outcome: Outcome::Denied,
            reasons: vec!["radius.home: not permitted".into()],
        })),
        Ok(Reply::Request(request_info(RequestStatus::Pending))),
        Ok(Reply::Requests(vec![
            request_info(RequestStatus::Issued),
            request_info(RequestStatus::Denied),
        ])),
        Ok(Reply::Certificate(certificate(true))),
        Ok(Reply::Certificates(vec![
            certificate(false),
            certificate(true),
        ])),
        Ok(Reply::Requests(Vec::new())),
        Err(WireError::new(ErrorCode::SelfApproval, "no")),
    ];
    for reply in replies {
        let decoded = Reply::decode(&Reply::encode(&reply).unwrap()).unwrap();
        assert_eq!(decoded, reply);
    }
}

#[test]
fn every_error_code_round_trips() {
    for code in [
        ErrorCode::AccessDenied,
        ErrorCode::NotFound,
        ErrorCode::BadRequest,
        ErrorCode::Conflict,
        ErrorCode::SelfApproval,
        ErrorCode::NowRefused,
        ErrorCode::KeyUnavailable,
        ErrorCode::Unavailable,
        ErrorCode::Internal,
    ] {
        assert_eq!(ErrorCode::parse(code.as_str()), code);
    }
    assert_eq!(ErrorCode::parse("something-new"), ErrorCode::Internal);
}

/// A map written by hand, as another client might.
fn map(entries: &[(&str, &str)]) -> Vec<u8> {
    let mut writer = peios::msgpack::Writer::new();
    writer.write_map(entries.len() as u32);
    for (key, value) in entries {
        writer.write_str(key).write_str(value);
    }
    writer.to_bytes().unwrap()
}

#[test]
fn unknown_keys_are_ignored_and_duplicates_refused() {
    let request = map(&[("op", "authorities"), ("from-the-future", "yes")]);
    assert_eq!(Request::decode(&request).unwrap(), Request::Authorities);
    let duplicated = map(&[("op", "authorities"), ("op", "submit")]);
    assert!(Request::decode(&duplicated).is_err());
    assert!(Request::decode(&map(&[("op", "explode")])).is_err());
    assert!(Request::decode(b"\x90").is_err());
    let mut trailing = map(&[("op", "authorities")]);
    trailing.push(0xc0);
    assert!(Request::decode(&trailing).is_err());
}

#[test]
fn frames_carry_their_length() {
    let mut wire = Vec::new();
    write_frame(&mut wire, b"payload").unwrap();
    assert_eq!(&wire[..4], &7u32.to_le_bytes());
    let payload = read_frame(&mut wire.as_slice(), 64).unwrap();
    assert_eq!(payload, b"payload");
}

#[test]
fn oversized_frames_are_refused_unread() {
    let mut wire = Vec::new();
    write_frame(&mut wire, &[0; 100]).unwrap();
    let mut reader = wire.as_slice();
    assert!(matches!(
        read_frame(&mut reader, 64),
        Err(FrameError::TooLarge(100))
    ));
    // Only the length was consumed.
    assert_eq!(reader.len(), 100);
}
