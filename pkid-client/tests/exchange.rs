//! One request and reply against a stand-in server. Checking that the server
//! is pkid needs a Peios kernel and is qualified in a guest.

use std::os::unix::net::UnixStream;
use std::thread;

use pkid_client::{exchange, ClientError};
use pkid_core::{
    read_frame, write_frame, ErrorCode, Outcome, Reply, Request, SubmissionInfo, WireError,
    MAX_REQUEST_BYTES,
};

/// Serves one connection: reads a request and answers with `answer`'s
/// reply to it.
fn serve(answer: impl FnOnce(Request) -> Vec<u8> + Send + 'static) -> UnixStream {
    let (client, mut server) = UnixStream::pair().unwrap();
    thread::spawn(move || {
        let payload = read_frame(&mut server, MAX_REQUEST_BYTES).unwrap();
        let request = Request::decode(&payload).unwrap();
        write_frame(&mut server, &answer(request)).unwrap();
    });
    client
}

#[test]
fn replies_come_back_typed() {
    let mut stream = serve(|request| {
        let Request::Submit { csr, .. } = request else {
            panic!("expected a submission")
        };
        assert_eq!(csr, b"csr");
        Reply::encode(&Ok(Reply::Submission(SubmissionInfo {
            request: 9,
            outcome: Outcome::Issued(b"certificate".to_vec()),
            reasons: Vec::new(),
        })))
        .unwrap()
    });
    let request = Request::Submit {
        ca: "issuing".into(),
        template: "server".into(),
        csr: b"csr".to_vec(),
    };
    let reply = exchange(&mut stream, &request).unwrap();
    assert!(matches!(
        reply,
        Reply::Submission(SubmissionInfo { request: 9, .. })
    ));
}

#[test]
fn refusals_carry_pkids_reason() {
    let mut stream = serve(|_| {
        Reply::encode(&Err(WireError::new(
            ErrorCode::AccessDenied,
            "access denied",
        )))
        .unwrap()
    });
    let result = exchange(&mut stream, &Request::Authorities);
    match result {
        Err(ClientError::Refused(error)) => assert_eq!(error.code, ErrorCode::AccessDenied),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn garbage_replies_are_protocol_errors() {
    let mut stream = serve(|_| b"\xc1".to_vec());
    assert!(matches!(
        exchange(&mut stream, &Request::Authorities),
        Err(ClientError::Protocol(_))
    ));
}

#[test]
fn a_closed_connection_is_an_io_error() {
    let (mut client, server) = UnixStream::pair().unwrap();
    drop(server);
    assert!(matches!(
        exchange(&mut client, &Request::Authorities),
        Err(ClientError::Io(_))
    ));
}
