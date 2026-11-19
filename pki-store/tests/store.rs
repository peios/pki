//! Behaviour of the CA database.

use std::path::PathBuf;

use pki_core::{RevocationReason, SerialNumber, Sid};
use pki_store::{
    CertificateFilter, NewCertificate, NewRequest, RequestFilter, RequestStatus, Revocation, Store,
    StoreError,
};
use time::macros::datetime;
use time::OffsetDateTime;

const CA: &str = "6f1c6c52-8f3a-4d55-9b1e-0a1b2c3d4e5f";
const SERVER: &str = "0e5b5a3c-2f4d-4c1a-8e9b-111111111111";

fn sid(text: &str) -> Sid {
    Sid::new(text).unwrap()
}

fn requester() -> Sid {
    sid("S-1-5-21-1-2-3-1001")
}

fn officer() -> Sid {
    sid("S-1-5-21-1-2-3-1002")
}

fn new_request(requester: &Sid) -> NewRequest {
    NewRequest {
        ca: CA.into(),
        template: SERVER.into(),
        csr: vec![0x30, 0x00],
        names: vec!["radius.home".into(), "radius.lab.home".into()],
        requester: requester.clone(),
        subject: vec![1, 2, 3],
        submitted: datetime!(2027-01-01 0:00 UTC),
    }
}

fn certificate(not_after: OffsetDateTime) -> NewCertificate {
    NewCertificate {
        serial: SerialNumber::random().unwrap(),
        der: vec![0x30, 0x01, 0x00],
        not_before: datetime!(2027-01-01 0:00 UTC),
        not_after,
        owner: Some(requester()),
    }
}

fn year_long() -> NewCertificate {
    certificate(datetime!(2028-01-01 0:00 UTC))
}

fn reasons(lines: &[&str]) -> Vec<String> {
    lines.iter().map(|line| line.to_string()).collect()
}

#[test]
fn approved_requests_are_issued_with_their_approver() {
    let mut store = Store::memory().unwrap();
    let request = new_request(&requester());
    let id = store
        .record_pending(&request, &reasons(&["the template requires approval"]))
        .unwrap();

    let held = store.request(id).unwrap().unwrap();
    assert_eq!(held.status, RequestStatus::Pending);
    assert_eq!(held.reasons, reasons(&["the template requires approval"]));
    assert_eq!(held.names, request.names);
    assert_eq!(held.subject, request.subject);
    assert_eq!(held.decided, None);
    assert!(store.certificate_for(id).unwrap().is_none());

    let issued = year_long();
    let at = datetime!(2027-01-02 9:30 UTC);
    store.approve(id, &officer(), at, &issued).unwrap();
    let decided = store.request(id).unwrap().unwrap();
    assert_eq!(decided.status, RequestStatus::Issued);
    assert_eq!(decided.decider, Some(officer()));
    assert_eq!(decided.decided, Some(at));

    let stored = store.certificate_for(id).unwrap().unwrap();
    assert_eq!(stored.serial, issued.serial);
    assert_eq!(stored.der, issued.der);
    assert_eq!(stored.owner, issued.owner);
    assert_eq!(stored.request, id);
    assert_eq!(store.certificate(CA, &issued.serial).unwrap(), Some(stored));
}

#[test]
fn nobody_approves_their_own_request() {
    let mut store = Store::memory().unwrap();
    let id = store
        .record_pending(&new_request(&requester()), &[])
        .unwrap();
    let result = store.approve(
        id,
        &requester(),
        datetime!(2027-01-02 0:00 UTC),
        &year_long(),
    );
    assert_eq!(result, Err(StoreError::SelfApproval));
    let request = store.request(id).unwrap().unwrap();
    assert_eq!(request.status, RequestStatus::Pending);
    assert!(store.certificate_for(id).unwrap().is_none());
}

#[test]
fn requests_are_decided_once() {
    let mut store = Store::memory().unwrap();
    let id = store
        .record_pending(&new_request(&requester()), &[])
        .unwrap();
    let at = datetime!(2027-01-02 0:00 UTC);
    store
        .deny(id, &officer(), at, &reasons(&["not a lab host"]))
        .unwrap();
    assert_eq!(
        store.approve(id, &officer(), at, &year_long()),
        Err(StoreError::NotPending(id, RequestStatus::Denied))
    );
    assert_eq!(
        store.deny(id, &officer(), at, &[]),
        Err(StoreError::NotPending(id, RequestStatus::Denied))
    );
    let denied = store.request(id).unwrap().unwrap();
    assert_eq!(denied.decider, Some(officer()));
    assert_eq!(denied.reasons, reasons(&["not a lab host"]));
}

#[test]
fn unknown_requests_are_reported() {
    let mut store = Store::memory().unwrap();
    let id = pki_store::RequestId::new(42);
    assert_eq!(
        store.approve(id, &officer(), datetime!(2027-01-02 0:00 UTC), &year_long()),
        Err(StoreError::NoSuchRequest(id))
    );
    assert_eq!(store.request(id).unwrap(), None);
}

#[test]
fn policy_decisions_have_no_officer() {
    let mut store = Store::memory().unwrap();
    let issued = store
        .record_issued(&new_request(&requester()), &year_long())
        .unwrap();
    let denied = store
        .record_denied(
            &new_request(&requester()),
            &reasons(&["radius.home: not permitted", "multi\nline"]),
            datetime!(2027-01-01 0:00 UTC),
        )
        .unwrap();
    let issued = store.request(issued).unwrap().unwrap();
    assert_eq!(issued.status, RequestStatus::Issued);
    assert_eq!(issued.decider, None);
    assert!(issued.decided.is_some());
    let denied = store.request(denied).unwrap().unwrap();
    assert_eq!(denied.status, RequestStatus::Denied);
    assert_eq!(denied.decider, None);
    assert_eq!(
        denied.reasons,
        reasons(&["radius.home: not permitted", "multi line"])
    );
}

#[test]
fn a_reused_serial_records_nothing() {
    let mut store = Store::memory().unwrap();
    let first = year_long();
    store
        .record_issued(&new_request(&requester()), &first)
        .unwrap();
    let mut second = year_long();
    second.serial = first.serial.clone();
    assert_eq!(
        store.record_issued(&new_request(&requester()), &second),
        Err(StoreError::DuplicateSerial)
    );
    let all = store.requests(&RequestFilter::default()).unwrap();
    assert_eq!(all.len(), 1);

    // The same serial under another CA is a different certificate.
    let mut elsewhere = new_request(&requester());
    elsewhere.ca = "another-ca".into();
    store.record_issued(&elsewhere, &second).unwrap();
}

#[test]
fn approval_with_a_reused_serial_leaves_the_request_pending() {
    let mut store = Store::memory().unwrap();
    let first = year_long();
    store
        .record_issued(&new_request(&requester()), &first)
        .unwrap();
    let id = store
        .record_pending(&new_request(&requester()), &[])
        .unwrap();
    let mut clash = year_long();
    clash.serial = first.serial.clone();
    assert_eq!(
        store.approve(id, &officer(), datetime!(2027-01-02 0:00 UTC), &clash),
        Err(StoreError::DuplicateSerial)
    );
    assert_eq!(
        store.request(id).unwrap().unwrap().status,
        RequestStatus::Pending
    );
}

#[test]
fn revocations_are_recorded_once() {
    let mut store = Store::memory().unwrap();
    let issued = year_long();
    let id = store
        .record_issued(&new_request(&requester()), &issued)
        .unwrap();
    let revocation = Revocation {
        revoked: datetime!(2027-03-01 0:00 UTC),
        reason: RevocationReason::KeyCompromise,
        revoker: officer(),
    };
    store.revoke(CA, &issued.serial, &revocation).unwrap();
    assert_eq!(
        store.revoke(CA, &issued.serial, &revocation),
        Err(StoreError::AlreadyRevoked)
    );
    assert_eq!(
        store.revoke("another-ca", &issued.serial, &revocation),
        Err(StoreError::NoSuchCertificate)
    );
    let stored = store.certificate_for(id).unwrap().unwrap();
    assert_eq!(stored.revocation, Some(revocation));
}

#[test]
fn every_revocation_reason_round_trips() {
    let mut store = Store::memory().unwrap();
    for reason in [
        RevocationReason::Unspecified,
        RevocationReason::KeyCompromise,
        RevocationReason::CaCompromise,
        RevocationReason::AffiliationChanged,
        RevocationReason::Superseded,
        RevocationReason::CessationOfOperation,
        RevocationReason::CertificateHold,
        RevocationReason::PrivilegeWithdrawn,
    ] {
        let issued = year_long();
        store
            .record_issued(&new_request(&requester()), &issued)
            .unwrap();
        let revocation = Revocation {
            revoked: datetime!(2027-03-01 0:00 UTC),
            reason,
            revoker: officer(),
        };
        store.revoke(CA, &issued.serial, &revocation).unwrap();
        let stored = store.certificate(CA, &issued.serial).unwrap().unwrap();
        assert_eq!(stored.revocation.unwrap().reason, reason);
    }
}

#[test]
fn crls_list_only_unexpired_revocations() {
    let mut store = Store::memory().unwrap();
    let expiring = certificate(datetime!(2027-02-01 0:00 UTC));
    let lasting = year_long();
    let untouched = year_long();
    for issued in [&expiring, &lasting, &untouched] {
        store
            .record_issued(&new_request(&requester()), issued)
            .unwrap();
    }
    for issued in [&expiring, &lasting] {
        let revocation = Revocation {
            revoked: datetime!(2027-01-15 0:00 UTC),
            reason: RevocationReason::Superseded,
            revoker: officer(),
        };
        store.revoke(CA, &issued.serial, &revocation).unwrap();
    }
    let early = store.revoked(CA, datetime!(2027-01-20 0:00 UTC)).unwrap();
    assert_eq!(early.len(), 2);
    let later = store.revoked(CA, datetime!(2027-06-01 0:00 UTC)).unwrap();
    let serials: Vec<_> = later.iter().map(|(serial, _)| serial.clone()).collect();
    assert_eq!(serials, vec![lasting.serial.clone()]);
    assert!(store
        .revoked("another-ca", datetime!(2027-01-20 0:00 UTC))
        .unwrap()
        .is_empty());
}

#[test]
fn listings_filter_and_continue() {
    let mut store = Store::memory().unwrap();
    let other = sid("S-1-5-21-1-2-3-1003");
    let mut ids = Vec::new();
    for index in 0..5 {
        let who = if index % 2 == 0 {
            requester()
        } else {
            other.clone()
        };
        ids.push(store.record_pending(&new_request(&who), &[]).unwrap());
    }
    store
        .approve(
            ids[0],
            &officer(),
            datetime!(2027-01-02 0:00 UTC),
            &year_long(),
        )
        .unwrap();

    let pending = RequestFilter {
        status: Some(RequestStatus::Pending),
        ..RequestFilter::default()
    };
    let listed: Vec<_> = store
        .requests(&pending)
        .unwrap()
        .iter()
        .map(|request| request.id)
        .collect();
    assert_eq!(listed, ids[1..].to_vec());

    let page = RequestFilter {
        status: Some(RequestStatus::Pending),
        after: Some(ids[1]),
        limit: 2,
        ..RequestFilter::default()
    };
    let listed: Vec<_> = store
        .requests(&page)
        .unwrap()
        .iter()
        .map(|request| request.id)
        .collect();
    assert_eq!(listed, vec![ids[2], ids[3]]);

    let mine = RequestFilter {
        requester: Some(other.clone()),
        ..RequestFilter::default()
    };
    assert_eq!(store.requests(&mine).unwrap().len(), 2);
}

#[test]
fn certificate_listings_can_leave_out_revoked_ones() {
    let mut store = Store::memory().unwrap();
    let kept = year_long();
    let revoked = year_long();
    let mut unowned = year_long();
    unowned.owner = None;
    for issued in [&kept, &revoked, &unowned] {
        store
            .record_issued(&new_request(&requester()), issued)
            .unwrap();
    }
    let revocation = Revocation {
        revoked: datetime!(2027-03-01 0:00 UTC),
        reason: RevocationReason::Unspecified,
        revoker: officer(),
    };
    store.revoke(CA, &revoked.serial, &revocation).unwrap();

    let all = store.certificates(&CertificateFilter::default()).unwrap();
    assert_eq!(all.len(), 3);
    let current = CertificateFilter {
        unrevoked_only: true,
        ..CertificateFilter::default()
    };
    let serials: Vec<_> = store
        .certificates(&current)
        .unwrap()
        .into_iter()
        .map(|certificate| certificate.serial)
        .collect();
    assert_eq!(serials, vec![kept.serial.clone(), unowned.serial.clone()]);
    let owned = CertificateFilter {
        owner: Some(requester()),
        ..CertificateFilter::default()
    };
    assert_eq!(store.certificates(&owned).unwrap().len(), 2);

    let someone_else = sid("S-1-5-21-1-2-3-1003");
    let theirs = year_long();
    store
        .record_issued(&new_request(&someone_else), &theirs)
        .unwrap();
    let requested = CertificateFilter {
        requester: Some(someone_else),
        ..CertificateFilter::default()
    };
    let serials: Vec<_> = store
        .certificates(&requested)
        .unwrap()
        .into_iter()
        .map(|certificate| certificate.serial)
        .collect();
    assert_eq!(serials, vec![theirs.serial]);
}

/// A fresh, empty directory for one test's database.
fn directory(test: &str) -> PathBuf {
    let directory = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(test);
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

#[test]
fn the_database_persists_and_has_one_owner() {
    let path = directory("persist").join("pkid.db");
    let id = {
        let mut store = Store::open(&path).unwrap();
        assert!(matches!(Store::open(&path), Err(StoreError::InUse)));
        store
            .record_pending(&new_request(&requester()), &[])
            .unwrap()
    };
    let store = Store::open(&path).unwrap();
    assert_eq!(
        store.request(id).unwrap().unwrap().status,
        RequestStatus::Pending
    );
}

#[test]
fn other_databases_are_not_adopted() {
    let path = directory("foreign").join("pkid.db");
    {
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection
            .execute_batch("CREATE TABLE something (x INTEGER);")
            .unwrap();
    }
    assert!(matches!(Store::open(&path), Err(StoreError::Unusable(_))));

    let path = directory("newer").join("pkid.db");
    {
        Store::open(&path).unwrap();
    }
    {
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection
            .execute_batch("PRAGMA user_version = 99;")
            .unwrap();
    }
    assert!(matches!(Store::open(&path), Err(StoreError::Unusable(_))));
}

#[cfg(unix)]
#[test]
fn linked_databases_are_refused() {
    let directory = directory("linked");
    let target = directory.join("elsewhere.db");
    std::fs::write(&target, b"").unwrap();
    let path = directory.join("pkid.db");
    std::os::unix::fs::symlink(&target, &path).unwrap();
    assert!(matches!(Store::open(&path), Err(StoreError::Unusable(_))));
}
