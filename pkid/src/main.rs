//! pkid: the Peios certificate authority service. peinit starts it; it
//! takes its configuration from the Registry and no arguments.

use std::process::ExitCode;
use std::sync::Arc;

use pkid::{server, service};

const HELP: &str = "\
Run the Peios certificate authority service.

Usage: pkid

pkid is started by peinit as the pkid service. It reads its configuration
from Machine\\Software\\Pki and serves requests on /run/pkid/pki.sock.

Options:
  -h, --help     Print help
  -V, --version  Print version

See pkid(8).
";

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
            println!("pkid {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        [other, ..] => {
            eprintln!("pkid: {other}: unexpected argument");
            eprintln!("Try 'pkid --help' for more information.");
            return ExitCode::from(2);
        }
    }

    if let Err(error) = service::verify_identity() {
        eprintln!("pkid: {error}");
        return ExitCode::FAILURE;
    }
    let providers = service::providers();
    let state = service::start(&providers);
    let listener = match server::listen() {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("pkid: {}: {error}", pkid_core::SOCKET_PATH);
            return ExitCode::FAILURE;
        }
    };
    {
        let state = Arc::clone(&state);
        std::thread::spawn(move || service::watch(state));
    }
    service::notify_ready();
    match server::serve(listener, state) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("pkid: {}: {error}", pkid_core::SOCKET_PATH);
            ExitCode::FAILURE
        }
    }
}
