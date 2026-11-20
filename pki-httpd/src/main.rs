//! pki-httpd: serve the CRLs pkid publishes over HTTP. peinit starts it as
//! the pki-httpd service; it takes its port from the Registry and no
//! arguments.

use std::io;
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::process::ExitCode;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use pki_management::HTTP_DIR;
use pkid_core::HTTPD_SERVICE_SID;

const HELP: &str = "\
Serve the CRLs the Peios certificate authority publishes

Usage: pki-httpd

pki-httpd is started by peinit as the pki-httpd service. It serves
/var/state/pki/http over HTTP, on the port Machine\\Software\\Pki\\Http
sets.

Options:
  -h, --help     Print help
  -V, --version  Print version

See pki-httpd(8).
";

/// Connections served at once; more are closed straight away.
const MAX_CLIENTS: usize = 64;
/// How long a client has to send its request, and to take the answer.
const CLIENT_TIMEOUT: Duration = Duration::from_secs(10);

/// Checks that pki-httpd runs as its own service identity, so that it
/// reaches only what that identity is granted.
fn verify_identity() -> Result<(), String> {
    use peios::token::{Token, TokenAccess};
    let actor = Token::open_self(false, TokenAccess::QUERY)
        .and_then(|token| token.user())
        .map_err(|error| format!("can't read its own identity: {error}"))?;
    if actor.to_string() == HTTPD_SERVICE_SID {
        Ok(())
    } else {
        Err(format!(
            "runs as {actor}, not as its service identity {HTTPD_SERVICE_SID}"
        ))
    }
}

/// Listens on every address: IPv6 and, through it, IPv4, or IPv4 alone
/// where IPv6 is unavailable.
fn listen(port: u16) -> io::Result<TcpListener> {
    TcpListener::bind(("::", port))
        .or_else(|error| TcpListener::bind(("0.0.0.0", port)).map_err(|_| error))
}

/// Tells peinit pki-httpd is ready (PSPU §4.16).
fn notify_ready() {
    let Some(path) = std::env::var_os("NOTIFY_SOCKET") else {
        return;
    };
    let sent = UnixDatagram::unbound().and_then(|socket| socket.send_to(b"READY=1", path));
    if let Err(error) = sent {
        eprintln!("pki-httpd: notify: {error}");
    }
}

fn connection(mut stream: TcpStream) {
    let set = stream
        .set_read_timeout(Some(CLIENT_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(CLIENT_TIMEOUT)));
    if set.is_err() {
        return;
    }
    // A client that goes away part-way is no concern of the server's.
    let _ = pki_httpd::serve(&mut stream, Path::new(HTTP_DIR));
}

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match arguments
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        [] => {}
        ["-h" | "--help"] => {
            print!("{HELP}");
            return ExitCode::SUCCESS;
        }
        ["-V" | "--version"] => {
            println!("pki-httpd {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        [other, ..] => {
            eprintln!("pki-httpd: {other}: unexpected argument");
            eprintln!("Try 'pki-httpd --help' for more information.");
            return ExitCode::from(2);
        }
    }
    if let Err(error) = verify_identity() {
        eprintln!("pki-httpd: {error}");
        return ExitCode::FAILURE;
    }
    let port = match pki_management::provision::http_port() {
        Ok(port) => port,
        Err(error) => {
            eprintln!("pki-httpd: {error}");
            return ExitCode::FAILURE;
        }
    };
    let listener = match listen(port) {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("pki-httpd: port {port}: {error}");
            return ExitCode::FAILURE;
        }
    };
    notify_ready();
    let active = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming() {
        let Ok(stream) = stream else {
            continue;
        };
        if active.fetch_add(1, Ordering::SeqCst) >= MAX_CLIENTS {
            active.fetch_sub(1, Ordering::SeqCst);
            continue;
        }
        let finished = Arc::clone(&active);
        let spawned = std::thread::Builder::new().spawn(move || {
            connection(stream);
            finished.fetch_sub(1, Ordering::SeqCst);
        });
        if spawned.is_err() {
            // The thread, and its decrement, never ran.
            active.fetch_sub(1, Ordering::SeqCst);
            eprintln!("pki-httpd: can't start a thread for a connection");
        }
    }
    ExitCode::SUCCESS
}
