//! The control socket.

use std::io;
use std::os::fd::AsFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use peios::file::SecInfo;
use peios::security::{AccessMask, AceFlags, AclBuilder, SdBuilder, Sid, WellKnown};
use peios::token::{Token, TokenAccess};
use peios_crypto::Secret;
use pkid_core::{
    read_frame, write_frame, ErrorCode, FrameError, Reply, Request, WireError, MAX_REQUEST_BYTES,
    RUN_DIR, SOCKET_PATH,
};
use time::OffsetDateTime;

use crate::dispatch::{handle, State};
use crate::identity::Caller;
use crate::service::Runtime;

/// How long a client has to deliver its request, and to take its reply.
const CLIENT_TIMEOUT: Duration = Duration::from_secs(5);
/// Connections served at once, so a local flood exhausts a counter rather
/// than threads.
const MAX_CLIENTS: usize = 64;

/// Binds the control socket, replacing one a previous run left behind.
pub fn listen() -> io::Result<UnixListener> {
    let directory = Path::new(RUN_DIR);
    std::fs::create_dir_all(directory)?;
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o755))?;
    protect(directory, false);
    let path = Path::new(SOCKET_PATH);
    match std::fs::remove_file(path) {
        Ok(()) => eprintln!("pkid: removed a stale {SOCKET_PATH}"),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;
    protect(path, true);
    Ok(listener)
}

/// Lets everyone reach the socket; each request's own check decides what
/// they may do. Sets the DACL only, since a service can't make someone else
/// the owner and `set_sd` would then fail whole. pkid keeps full access for
/// itself, so a restart can delete the socket it left behind (PEI-1373).
fn protect(path: &Path, socket: bool) {
    let system = Sid::well_known(WellKnown::System);
    let everyone = Sid::well_known(WellKnown::Everyone);
    let me = Token::open_self(true, TokenAccess::QUERY).and_then(|token| token.user());
    let mut acl = AclBuilder::new();
    acl.allow(
        system.as_ref(),
        AccessMask::GENERIC_ALL.bits(),
        AceFlags::empty(),
    );
    match &me {
        Ok(me) => {
            acl.allow(
                me.as_ref(),
                AccessMask::GENERIC_ALL.bits(),
                AceFlags::empty(),
            );
        }
        Err(error) => eprintln!(
            "pkid: can't read its own identity ({error}); a restart may not replace {}",
            path.display()
        ),
    }
    // Everyone may connect to the socket, and only pass through and list
    // the directory: never add to it.
    let everyone_rights = if socket {
        AccessMask::GENERIC_READ.bits()
            | AccessMask::GENERIC_WRITE.bits()
            | AccessMask::GENERIC_EXECUTE.bits()
    } else {
        AccessMask::GENERIC_READ.bits() | AccessMask::GENERIC_EXECUTE.bits()
    };
    acl.allow(everyone.as_ref(), everyone_rights, AceFlags::empty());
    let descriptor = acl
        .build()
        .and_then(|dacl| SdBuilder::new().dacl(&dacl).build());
    let result = descriptor.and_then(|sd| peios::file::set_sd(None, path, SecInfo::DACL, &sd, 0));
    if let Err(error) = result {
        eprintln!(
            "pkid: can't set the descriptor on {} ({error}); only SYSTEM and administrators \
             may reach pkid",
            path.display()
        );
    }
}

/// Serves connections until the listener fails, each on its own thread.
pub fn serve(
    listener: UnixListener,
    state: Arc<Mutex<State>>,
    runtime: Arc<Runtime>,
) -> io::Result<()> {
    let active = Arc::new(AtomicUsize::new(0));
    loop {
        let (stream, _) = match listener.accept() {
            Ok(connection) => connection,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        if active.fetch_add(1, Ordering::SeqCst) >= MAX_CLIENTS {
            active.fetch_sub(1, Ordering::SeqCst);
            continue;
        }
        let state = Arc::clone(&state);
        let runtime = Arc::clone(&runtime);
        let active = Arc::clone(&active);
        std::thread::spawn(move || {
            connection(stream, &state, &runtime);
            active.fetch_sub(1, Ordering::SeqCst);
        });
    }
}

/// One request and its reply. A caller whose identity can't be read is
/// closed on without a reply (PSPU §4.6).
fn connection(mut stream: UnixStream, state: &Mutex<State>, runtime: &Runtime) {
    let token = match Token::open_peer(stream.as_fd()) {
        Ok(token) => token,
        Err(error) => {
            eprintln!("pkid: a caller with no identity: {error}");
            return;
        }
    };
    let configured = stream
        .set_read_timeout(Some(CLIENT_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(CLIENT_TIMEOUT)));
    if configured.is_err() {
        return;
    }
    let reply = match read_frame(&mut stream, MAX_REQUEST_BYTES) {
        // The request may carry passphrases, so its bytes are wiped once
        // decoded.
        Ok(payload) => answer(Secret::new(payload).expose(), token, state, runtime),
        Err(FrameError::TooLarge(length)) => Err(WireError::new(
            ErrorCode::BadRequest,
            format!("a {length}-byte request is too large"),
        )),
        Err(FrameError::Io(_)) => return,
    };
    match Reply::encode(&reply) {
        Ok(payload) => {
            let _ = write_frame(&mut stream, &payload);
        }
        Err(error) => eprintln!("pkid: can't encode a reply: {error}"),
    }
}

fn answer(
    payload: &[u8],
    token: Token,
    state: &Mutex<State>,
    runtime: &Runtime,
) -> Result<Reply, WireError> {
    let request = Request::decode(payload)
        .map_err(|error| WireError::new(ErrorCode::BadRequest, error.to_string()))?;
    let caller = Caller::new(token)
        .map_err(|error| WireError::new(ErrorCode::Internal, error.to_string()))?;
    let mut state = state
        .lock()
        .map_err(|_| WireError::new(ErrorCode::Internal, "pkid's state is poisoned"))?;
    handle(
        &mut state,
        request,
        &caller,
        &runtime.services(),
        OffsetDateTime::now_utc(),
    )
}
