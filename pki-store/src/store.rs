use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::time::Duration;

use pki_core::{RevocationReason, SerialNumber, Sid};
use rusqlite::{params, Connection, OptionalExtension, Row, TransactionBehavior};
use time::OffsetDateTime;

use crate::{
    Certificate, CertificateFilter, NewCertificate, NewRequest, Request, RequestFilter, RequestId,
    RequestStatus, Revocation, StoreError,
};

/// ASCII `PKID`, marking the database as pkid's.
const APPLICATION: i64 = 0x504b_4944;
const SCHEMA: i64 = 1;

const SCHEMA_V1: &str = "
CREATE TABLE requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ca TEXT NOT NULL CHECK (ca <> ''),
    template TEXT NOT NULL CHECK (template <> ''),
    csr BLOB NOT NULL,
    names TEXT NOT NULL,
    requester TEXT NOT NULL,
    subject BLOB NOT NULL,
    submitted INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'issued', 'denied')),
    reasons TEXT NOT NULL,
    decided INTEGER,
    decider TEXT,
    CHECK ((status = 'pending') = (decided IS NULL)),
    CHECK (status <> 'pending' OR decider IS NULL),
    CHECK (decider IS NULL OR status <> 'issued' OR decider <> requester)
);
CREATE INDEX requests_by_status ON requests (status, id);
CREATE INDEX requests_by_requester ON requests (requester, id);

CREATE TABLE certificates (
    ca TEXT NOT NULL,
    serial BLOB NOT NULL,
    request INTEGER NOT NULL UNIQUE REFERENCES requests (id),
    der BLOB NOT NULL,
    not_before INTEGER NOT NULL,
    not_after INTEGER NOT NULL,
    owner TEXT,
    PRIMARY KEY (ca, serial)
);
CREATE INDEX certificates_by_owner ON certificates (owner, request);

CREATE TABLE revocations (
    ca TEXT NOT NULL,
    serial BLOB NOT NULL,
    revoked INTEGER NOT NULL,
    reason INTEGER NOT NULL,
    revoker TEXT NOT NULL,
    PRIMARY KEY (ca, serial),
    FOREIGN KEY (ca, serial) REFERENCES certificates (ca, serial)
);
";

/// The CA database.
pub struct Store {
    connection: Connection,
    _owner: Option<File>,
}

impl Store {
    /// Opens or creates the database at `path`, taking sole ownership of it.
    ///
    /// The directory must already exist and be protected: pkid's native
    /// layer provisions and checks it. As a further defence, links are
    /// refused here.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let directory = path
            .parent()
            .ok_or_else(|| StoreError::Unusable("the database needs a directory".into()))?;
        let metadata = fs::symlink_metadata(directory)
            .map_err(|error| StoreError::Unusable(format!("{}: {error}", directory.display())))?;
        if !metadata.is_dir() {
            return Err(StoreError::Unusable(
                "the database directory is not a real directory".into(),
            ));
        }
        for file in [
            path.to_path_buf(),
            sidecar(path, "-wal"),
            sidecar(path, "-shm"),
            sidecar(path, ".owner"),
        ] {
            if let Ok(metadata) = fs::symlink_metadata(&file) {
                if !metadata.is_file() {
                    return Err(StoreError::Unusable(format!(
                        "{} is not a regular file",
                        file.display()
                    )));
                }
            }
        }
        let owner = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(sidecar(path, ".owner"))
            .map_err(|error| StoreError::Unusable(error.to_string()))?;
        owner.try_lock().map_err(|_| StoreError::InUse)?;
        let mut store = Self {
            connection: Connection::open(path)?,
            _owner: Some(owner),
        };
        store.initialise()?;
        Ok(store)
    }

    /// A database in memory, for tests.
    pub fn memory() -> Result<Self, StoreError> {
        let mut store = Self {
            connection: Connection::open_in_memory()?,
            _owner: None,
        };
        store.initialise()?;
        Ok(store)
    }

    fn initialise(&mut self) -> Result<(), StoreError> {
        self.connection.busy_timeout(Duration::from_millis(250))?;
        let application: i64 = self
            .connection
            .query_row("PRAGMA application_id", [], |row| row.get(0))?;
        let version: i64 = self
            .connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if application != 0 && application != APPLICATION {
            return Err(StoreError::Unusable("the database is not pkid's".into()));
        }
        if version > SCHEMA {
            return Err(StoreError::Unusable(format!(
                "schema version {version} is newer than this pkid reads"
            )));
        }
        if application == 0 {
            let tables: i64 = self.connection.query_row(
                "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
                [],
                |row| row.get(0),
            )?;
            if tables != 0 {
                return Err(StoreError::Unusable(
                    "refusing to adopt another program's database".into(),
                ));
            }
        }
        self.connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA trusted_schema = OFF;
             PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;",
        )?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        // Each schema version adds a step here; steps only ever go forward.
        if version < 1 {
            transaction.execute_batch(SCHEMA_V1)?;
        }
        transaction.execute_batch(&format!(
            "PRAGMA application_id = {APPLICATION}; PRAGMA user_version = {SCHEMA};"
        ))?;
        transaction.commit()?;
        let check: String = self
            .connection
            .query_row("PRAGMA quick_check", [], |row| row.get(0))?;
        if check != "ok" {
            return Err(StoreError::Unusable(format!("integrity check: {check}")));
        }
        Ok(())
    }

    /// Records a request held for an officer, with why it was held.
    pub fn record_pending(
        &mut self,
        request: &NewRequest,
        reasons: &[String],
    ) -> Result<RequestId, StoreError> {
        let transaction = self.connection.transaction()?;
        let id = insert_request(&transaction, request, RequestStatus::Pending, reasons, None)?;
        transaction.commit()?;
        Ok(id)
    }

    /// Records a request that policy refused, with why.
    pub fn record_denied(
        &mut self,
        request: &NewRequest,
        reasons: &[String],
        at: OffsetDateTime,
    ) -> Result<RequestId, StoreError> {
        let transaction = self.connection.transaction()?;
        let id = insert_request(
            &transaction,
            request,
            RequestStatus::Denied,
            reasons,
            Some(at),
        )?;
        transaction.commit()?;
        Ok(id)
    }

    /// Records a request issued without an officer, with its certificate.
    /// It was decided when it was submitted.
    pub fn record_issued(
        &mut self,
        request: &NewRequest,
        certificate: &NewCertificate,
    ) -> Result<RequestId, StoreError> {
        let transaction = self.connection.transaction()?;
        let id = insert_request(
            &transaction,
            request,
            RequestStatus::Issued,
            &[],
            Some(request.submitted),
        )?;
        insert_certificate(&transaction, &request.ca, id, certificate)?;
        transaction.commit()?;
        Ok(id)
    }

    /// Issues a pending request on an officer's approval.
    pub fn approve(
        &mut self,
        id: RequestId,
        approver: &Sid,
        at: OffsetDateTime,
        certificate: &NewCertificate,
    ) -> Result<(), StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let request = pending(&transaction, id)?;
        if &request.requester == approver {
            return Err(StoreError::SelfApproval);
        }
        transaction.execute(
            "UPDATE requests SET status = 'issued', decided = ?2, decider = ?3
             WHERE id = ?1 AND status = 'pending'",
            params![id.0, at.unix_timestamp(), approver.as_str()],
        )?;
        insert_certificate(&transaction, &request.ca, id, certificate)?;
        transaction.commit()?;
        Ok(())
    }

    /// Refuses a pending request on an officer's decision.
    pub fn deny(
        &mut self,
        id: RequestId,
        officer: &Sid,
        at: OffsetDateTime,
        reasons: &[String],
    ) -> Result<(), StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        pending(&transaction, id)?;
        transaction.execute(
            "UPDATE requests SET status = 'denied', decided = ?2, decider = ?3, reasons = ?4
             WHERE id = ?1 AND status = 'pending'",
            params![
                id.0,
                at.unix_timestamp(),
                officer.as_str(),
                join_lines(reasons)
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Revokes a certificate.
    pub fn revoke(
        &mut self,
        ca: &str,
        serial: &SerialNumber,
        revocation: &Revocation,
    ) -> Result<(), StoreError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let exists = transaction
            .query_row(
                "SELECT 1 FROM certificates WHERE ca = ?1 AND serial = ?2",
                params![ca, serial.as_bytes()],
                |_| Ok(()),
            )
            .optional()?;
        if exists.is_none() {
            return Err(StoreError::NoSuchCertificate);
        }
        let inserted = transaction.execute(
            "INSERT INTO revocations (ca, serial, revoked, reason, revoker)
             VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT DO NOTHING",
            params![
                ca,
                serial.as_bytes(),
                revocation.revoked.unix_timestamp(),
                reason_code(revocation.reason),
                revocation.revoker.as_str()
            ],
        )?;
        if inserted == 0 {
            return Err(StoreError::AlreadyRevoked);
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn request(&self, id: RequestId) -> Result<Option<Request>, StoreError> {
        let mut statement = self
            .connection
            .prepare(&format!("{REQUEST_COLUMNS} WHERE id = ?1"))?;
        let mut rows = statement.query(params![id.0])?;
        rows.next()?.map(read_request).transpose()
    }

    /// Requests matching `filter`, oldest first.
    pub fn requests(&self, filter: &RequestFilter) -> Result<Vec<Request>, StoreError> {
        let mut statement = self.connection.prepare(&format!(
            "{REQUEST_COLUMNS}
             WHERE (?1 IS NULL OR ca = ?1) AND (?2 IS NULL OR status = ?2)
               AND (?3 IS NULL OR requester = ?3) AND id > ?4
             ORDER BY id LIMIT ?5"
        ))?;
        let mut rows = statement.query(params![
            filter.ca,
            filter.status.map(RequestStatus::as_str),
            filter.requester.as_ref().map(Sid::as_str),
            filter.after.map_or(0, |id| id.0),
            limit(filter.limit),
        ])?;
        let mut requests = Vec::new();
        while let Some(row) = rows.next()? {
            requests.push(read_request(row)?);
        }
        Ok(requests)
    }

    pub fn certificate(
        &self,
        ca: &str,
        serial: &SerialNumber,
    ) -> Result<Option<Certificate>, StoreError> {
        let mut statement = self.connection.prepare(&format!(
            "{CERTIFICATE_COLUMNS} WHERE c.ca = ?1 AND c.serial = ?2"
        ))?;
        let mut rows = statement.query(params![ca, serial.as_bytes()])?;
        rows.next()?.map(read_certificate).transpose()
    }

    /// The certificate issued for a request, if it was issued.
    pub fn certificate_for(&self, id: RequestId) -> Result<Option<Certificate>, StoreError> {
        let mut statement = self
            .connection
            .prepare(&format!("{CERTIFICATE_COLUMNS} WHERE c.request = ?1"))?;
        let mut rows = statement.query(params![id.0])?;
        rows.next()?.map(read_certificate).transpose()
    }

    /// Certificates matching `filter`, in order of their requests.
    pub fn certificates(&self, filter: &CertificateFilter) -> Result<Vec<Certificate>, StoreError> {
        let mut statement = self.connection.prepare(&format!(
            "{CERTIFICATE_COLUMNS}
             JOIN requests q ON q.id = c.request
             WHERE (?1 IS NULL OR c.ca = ?1) AND (?2 IS NULL OR c.owner = ?2)
               AND (?3 IS NULL OR q.requester = ?3)
               AND (NOT ?4 OR r.serial IS NULL) AND c.request > ?5
             ORDER BY c.request LIMIT ?6"
        ))?;
        let mut rows = statement.query(params![
            filter.ca,
            filter.owner.as_ref().map(Sid::as_str),
            filter.requester.as_ref().map(Sid::as_str),
            filter.unrevoked_only,
            filter.after.map_or(0, |id| id.0),
            limit(filter.limit),
        ])?;
        let mut certificates = Vec::new();
        while let Some(row) = rows.next()? {
            certificates.push(read_certificate(row)?);
        }
        Ok(certificates)
    }

    /// The certificates a CA has revoked that are still within their
    /// validity at `at`: what its next CRL must list.
    pub fn revoked(
        &self,
        ca: &str,
        at: OffsetDateTime,
    ) -> Result<Vec<(SerialNumber, Revocation)>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT r.serial, r.revoked, r.reason, r.revoker
             FROM revocations r JOIN certificates c ON c.ca = r.ca AND c.serial = r.serial
             WHERE r.ca = ?1 AND c.not_after > ?2
             ORDER BY r.revoked, r.serial",
        )?;
        let mut rows = statement.query(params![ca, at.unix_timestamp()])?;
        let mut revoked = Vec::new();
        while let Some(row) = rows.next()? {
            let serial = serial(row.get(0)?)?;
            revoked.push((serial, read_revocation(row, 1)?));
        }
        Ok(revoked)
    }
}

const REQUEST_COLUMNS: &str = "SELECT id, ca, template, csr, names, requester, subject, submitted,
    status, reasons, decided, decider FROM requests";

const CERTIFICATE_COLUMNS: &str = "SELECT c.ca, c.serial, c.request, c.der, c.not_before,
    c.not_after, c.owner, r.revoked, r.reason, r.revoker
    FROM certificates c LEFT JOIN revocations r ON r.ca = c.ca AND r.serial = c.serial";

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

fn limit(limit: usize) -> i64 {
    if limit == 0 {
        -1
    } else {
        i64::try_from(limit).unwrap_or(i64::MAX)
    }
}

/// Lines are joined with newlines, so a line can't contain one.
fn join_lines(lines: &[String]) -> String {
    lines
        .iter()
        .map(|line| line.replace(['\n', '\r'], " "))
        .collect::<Vec<_>>()
        .join("\n")
}

fn split_lines(text: String) -> Vec<String> {
    if text.is_empty() {
        Vec::new()
    } else {
        text.split('\n').map(str::to_owned).collect()
    }
}

fn insert_request(
    transaction: &rusqlite::Transaction<'_>,
    request: &NewRequest,
    status: RequestStatus,
    reasons: &[String],
    decided: Option<OffsetDateTime>,
) -> Result<RequestId, StoreError> {
    if request.ca.is_empty() || request.template.is_empty() {
        return Err(StoreError::Invalid(
            "a request needs a CA and a template".into(),
        ));
    }
    transaction.execute(
        "INSERT INTO requests (ca, template, csr, names, requester, subject, submitted,
                               status, reasons, decided)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            request.ca,
            request.template,
            request.csr,
            join_lines(&request.names),
            request.requester.as_str(),
            request.subject,
            request.submitted.unix_timestamp(),
            status.as_str(),
            join_lines(reasons),
            decided.map(OffsetDateTime::unix_timestamp),
        ],
    )?;
    Ok(RequestId(transaction.last_insert_rowid()))
}

fn insert_certificate(
    transaction: &rusqlite::Transaction<'_>,
    ca: &str,
    request: RequestId,
    certificate: &NewCertificate,
) -> Result<(), StoreError> {
    let inserted = transaction.execute(
        "INSERT INTO certificates (ca, serial, request, der, not_before, not_after, owner)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) ON CONFLICT (ca, serial) DO NOTHING",
        params![
            ca,
            certificate.serial.as_bytes(),
            request.0,
            certificate.der,
            certificate.not_before.unix_timestamp(),
            certificate.not_after.unix_timestamp(),
            certificate.owner.as_ref().map(Sid::as_str),
        ],
    )?;
    if inserted == 0 {
        return Err(StoreError::DuplicateSerial);
    }
    Ok(())
}

/// The pending request `id`, or why it can't be decided.
fn pending(transaction: &rusqlite::Transaction<'_>, id: RequestId) -> Result<Request, StoreError> {
    let mut statement = transaction.prepare(&format!("{REQUEST_COLUMNS} WHERE id = ?1"))?;
    let mut rows = statement.query(params![id.0])?;
    let request = rows
        .next()?
        .map(read_request)
        .transpose()?
        .ok_or(StoreError::NoSuchRequest(id))?;
    if request.status != RequestStatus::Pending {
        return Err(StoreError::NotPending(id, request.status));
    }
    Ok(request)
}

fn read_request(row: &Row<'_>) -> Result<Request, StoreError> {
    let status: String = row.get(8)?;
    Ok(Request {
        id: RequestId(row.get(0)?),
        ca: row.get(1)?,
        template: row.get(2)?,
        csr: row.get(3)?,
        names: split_lines(row.get(4)?),
        requester: sid(row.get(5)?)?,
        subject: row.get(6)?,
        submitted: timestamp(row.get(7)?)?,
        status: RequestStatus::parse(&status)
            .ok_or_else(|| StoreError::Corrupt(format!("request status {status:?}")))?,
        reasons: split_lines(row.get(9)?),
        decided: row.get::<_, Option<i64>>(10)?.map(timestamp).transpose()?,
        decider: row.get::<_, Option<String>>(11)?.map(sid).transpose()?,
    })
}

fn read_certificate(row: &Row<'_>) -> Result<Certificate, StoreError> {
    let revoked: Option<i64> = row.get(7)?;
    Ok(Certificate {
        ca: row.get(0)?,
        serial: serial(row.get(1)?)?,
        request: RequestId(row.get(2)?),
        der: row.get(3)?,
        not_before: timestamp(row.get(4)?)?,
        not_after: timestamp(row.get(5)?)?,
        owner: row.get::<_, Option<String>>(6)?.map(sid).transpose()?,
        revocation: match revoked {
            Some(_) => Some(read_revocation(row, 7)?),
            None => None,
        },
    })
}

fn read_revocation(row: &Row<'_>, first: usize) -> Result<Revocation, StoreError> {
    Ok(Revocation {
        revoked: timestamp(row.get(first)?)?,
        reason: reason_from_code(row.get(first + 1)?)?,
        revoker: sid(row.get(first + 2)?)?,
    })
}

fn sid(text: String) -> Result<Sid, StoreError> {
    Sid::new(&text).map_err(|_| StoreError::Corrupt(format!("SID {text:?}")))
}

fn serial(bytes: Vec<u8>) -> Result<SerialNumber, StoreError> {
    SerialNumber::from_bytes(&bytes).map_err(|_| StoreError::Corrupt("serial number".into()))
}

fn timestamp(seconds: i64) -> Result<OffsetDateTime, StoreError> {
    OffsetDateTime::from_unix_timestamp(seconds)
        .map_err(|_| StoreError::Corrupt(format!("time {seconds}")))
}

/// The CRL reason codes of RFC 5280 §5.3.1, so stored values never depend
/// on this program's enum order.
fn reason_code(reason: RevocationReason) -> i64 {
    match reason {
        RevocationReason::Unspecified => 0,
        RevocationReason::KeyCompromise => 1,
        RevocationReason::CaCompromise => 2,
        RevocationReason::AffiliationChanged => 3,
        RevocationReason::Superseded => 4,
        RevocationReason::CessationOfOperation => 5,
        RevocationReason::CertificateHold => 6,
        RevocationReason::PrivilegeWithdrawn => 9,
    }
}

fn reason_from_code(code: i64) -> Result<RevocationReason, StoreError> {
    Ok(match code {
        0 => RevocationReason::Unspecified,
        1 => RevocationReason::KeyCompromise,
        2 => RevocationReason::CaCompromise,
        3 => RevocationReason::AffiliationChanged,
        4 => RevocationReason::Superseded,
        5 => RevocationReason::CessationOfOperation,
        6 => RevocationReason::CertificateHold,
        9 => RevocationReason::PrivilegeWithdrawn,
        _ => return Err(StoreError::Corrupt(format!("revocation reason {code}"))),
    })
}
