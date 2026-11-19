//! pki-httpd serves, read-only, the folder pkid publishes CRLs to, so that
//! software checking revocation can fetch them at their distribution
//! points. It holds no keys and can't reach pkid: a fault here exposes no
//! more than the CRLs, which are public.
//!
//! It speaks the least of HTTP/1.1 that a CRL fetch needs: one GET or HEAD
//! per connection, no request body, and a response that closes the
//! connection. Everything else is refused.

use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::Path;

use pki_management::http::relative_path;

/// The longest request head read: the request line and headers together.
pub const MAX_HEAD: usize = 8 * 1024;
/// The largest file served. A CRL listing every certificate a large CA
/// ever revoked fits easily.
pub const MAX_FILE: u64 = 64 * 1024 * 1024;

/// What a request asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub head_only: bool,
    pub path: String,
}

/// Why a request was refused, as an HTTP status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    BadRequest,
    NotFound,
    MethodNotAllowed,
    HeadTooLarge,
    VersionNotSupported,
}

impl Refusal {
    fn status(self) -> (u16, &'static str) {
        match self {
            Self::BadRequest => (400, "Bad Request"),
            Self::NotFound => (404, "Not Found"),
            Self::MethodNotAllowed => (405, "Method Not Allowed"),
            Self::HeadTooLarge => (431, "Request Header Fields Too Large"),
            Self::VersionNotSupported => (505, "HTTP Version Not Supported"),
        }
    }
}

/// Reads a request's head, up to the blank line that ends it, and parses
/// its request line. Headers are read past and ignored.
pub fn read_request(reader: &mut impl BufRead) -> Result<Target, Refusal> {
    let mut head = Vec::new();
    loop {
        let mut line = Vec::new();
        let read = (&mut *reader)
            .take((MAX_HEAD - head.len() + 1) as u64)
            .read_until(b'\n', &mut line)
            .map_err(|_| Refusal::BadRequest)?;
        if read == 0 {
            return Err(Refusal::BadRequest);
        }
        if head.len() + line.len() > MAX_HEAD {
            return Err(Refusal::HeadTooLarge);
        }
        let blank = line == b"\r\n" || line == b"\n";
        head.extend_from_slice(&line);
        if blank {
            break;
        }
        if !line.ends_with(b"\n") {
            return Err(Refusal::BadRequest);
        }
    }
    let request_line = head.split(|byte| *byte == b'\n').next().unwrap_or_default();
    let request_line = std::str::from_utf8(request_line)
        .map_err(|_| Refusal::BadRequest)?
        .trim_end_matches('\r');
    let mut parts = request_line.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Refusal::BadRequest);
    };
    if !matches!(version, "HTTP/1.1" | "HTTP/1.0") {
        return Err(if version.starts_with("HTTP/") {
            Refusal::VersionNotSupported
        } else {
            Refusal::BadRequest
        });
    }
    let head_only = match method {
        "GET" => false,
        "HEAD" => true,
        _ => return Err(Refusal::MethodNotAllowed),
    };
    if !target.starts_with('/') {
        return Err(Refusal::BadRequest);
    }
    // A query is accepted and ignored, as a static server does.
    let path = target.split('?').next().unwrap_or_default();
    Ok(Target {
        head_only,
        path: path.to_owned(),
    })
}

/// The media type a file is served as.
fn content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some(extension) if extension.eq_ignore_ascii_case("crl") => "application/pkix-crl",
        Some(extension)
            if extension.eq_ignore_ascii_case("crt") || extension.eq_ignore_ascii_case("cer") =>
        {
            "application/pkix-cert"
        }
        _ => "application/octet-stream",
    }
}

/// The file `target` names under `root`, opened, if it is a regular file
/// that may be served.
fn open(root: &Path, target: &Target) -> Result<(File, u64, &'static str), Refusal> {
    let relative = relative_path(&target.path).ok_or(Refusal::NotFound)?;
    let path = root.join(&relative);
    let file = File::open(&path).map_err(|_| Refusal::NotFound)?;
    let metadata = file.metadata().map_err(|_| Refusal::NotFound)?;
    if !metadata.is_file() || metadata.len() > MAX_FILE {
        return Err(Refusal::NotFound);
    }
    Ok((file, metadata.len(), content_type(&relative)))
}

fn write_refusal(writer: &mut impl Write, refusal: Refusal) -> io::Result<()> {
    let (code, reason) = refusal.status();
    let body = format!("{code} {reason}\n");
    let allow = if refusal == Refusal::MethodNotAllowed {
        "Allow: GET, HEAD\r\n"
    } else {
        ""
    };
    write!(
        writer,
        "HTTP/1.1 {code} {reason}\r\n{allow}Content-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    writer.flush()
}

/// Answers one request read from `stream` with a file under `root`, and
/// says what was asked and how it was answered, for the log.
pub fn serve(stream: &mut (impl Read + Write), root: &Path) -> io::Result<(Option<Target>, u16)> {
    let mut reader = BufReader::new(&mut *stream);
    let target = match read_request(&mut reader) {
        Ok(target) => target,
        Err(refusal) => {
            drop(reader);
            write_refusal(stream, refusal)?;
            return Ok((None, refusal.status().0));
        }
    };
    drop(reader);
    match open(root, &target) {
        Ok((mut file, length, media_type)) => {
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: {media_type}\r\nContent-Length: {length}\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n"
            )?;
            if !target.head_only {
                io::copy(&mut (&mut file).take(length), stream)?;
            }
            stream.flush()?;
            Ok((Some(target), 200))
        }
        Err(refusal) => {
            write_refusal(stream, refusal)?;
            Ok((Some(target), refusal.status().0))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A connection: the request to read, and what was written back.
    struct Connection {
        input: io::Cursor<Vec<u8>>,
        output: Vec<u8>,
    }

    impl Connection {
        fn new(request: &[u8]) -> Self {
            Self {
                input: io::Cursor::new(request.to_vec()),
                output: Vec::new(),
            }
        }
    }

    impl Read for Connection {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.input.read(buffer)
        }
    }

    impl Write for Connection {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.output.write(buffer)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn root() -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!("pki-httpd-{}", std::process::id()));
        std::fs::create_dir_all(root.join("crl")).unwrap();
        std::fs::write(root.join("crl/issuing.crl"), [0x30, 0x03, 0x02, 0x01, 0x01]).unwrap();
        std::fs::create_dir_all(root.join("crl/folder.crl")).unwrap();
        root
    }

    fn answer(request: &str) -> String {
        let mut connection = Connection::new(request.as_bytes());
        serve(&mut connection, &root()).unwrap();
        String::from_utf8_lossy(&connection.output).into_owned()
    }

    #[test]
    fn a_published_crl_is_served() {
        let response = answer("GET /crl/issuing.crl HTTP/1.1\r\nHost: pki.home\r\n\r\n");
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
        assert!(
            response.contains("Content-Type: application/pkix-crl\r\n"),
            "{response}"
        );
        assert!(response.contains("Content-Length: 5\r\n"), "{response}");
        assert!(
            response.ends_with("\r\n\r\n\u{30}\u{3}\u{2}\u{1}\u{1}"),
            "{response:?}"
        );
        let head = answer("HEAD /crl/issuing.crl?x HTTP/1.0\r\n\r\n");
        assert!(
            head.starts_with("HTTP/1.1 200 OK\r\n") && head.ends_with("\r\n\r\n"),
            "{head}"
        );
    }

    #[test]
    fn nothing_outside_the_folder_or_unpublished_is_served() {
        for path in [
            "/crl/missing.crl",
            "/../etc/passwd",
            "/crl/../crl/issuing.crl",
            "/crl/folder.crl",
            "/.hidden",
            "/",
            "/crl%2Fissuing.crl",
        ] {
            let response = answer(&format!("GET {path} HTTP/1.1\r\n\r\n"));
            assert!(response.starts_with("HTTP/1.1 404 "), "{path}: {response}");
        }
    }

    #[test]
    fn other_requests_are_refused() {
        let cases = [
            (
                "POST /crl/issuing.crl HTTP/1.1\r\n\r\n",
                "405 ",
                "Allow: GET, HEAD",
            ),
            ("GET /crl/issuing.crl HTTP/2.0\r\n\r\n", "505 ", ""),
            ("GET crl/issuing.crl HTTP/1.1\r\n\r\n", "400 ", ""),
            ("GET /crl/issuing.crl\r\n\r\n", "400 ", ""),
            ("GET  /crl/issuing.crl HTTP/1.1\r\n\r\n", "400 ", ""),
            ("GET /crl/issuing.crl HTTP/1.1\r\n", "400 ", ""),
        ];
        for (request, status, header) in cases {
            let response = answer(request);
            assert!(
                response.starts_with(&format!("HTTP/1.1 {status}")),
                "{request:?}: {response}"
            );
            assert!(response.contains(header), "{request:?}: {response}");
        }
        let long = format!(
            "GET /crl/issuing.crl HTTP/1.1\r\nX: {}\r\n\r\n",
            "a".repeat(MAX_HEAD)
        );
        assert!(answer(&long).starts_with("HTTP/1.1 431 "));
    }
}
