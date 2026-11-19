//! Reading passphrases: from the terminal without echoing them, or from a
//! file a script names. pki never takes one from its arguments or the
//! environment, where other processes can read it.

use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::fd::AsRawFd;
use std::path::Path;

use zeroize::Zeroizing;

/// The longest passphrase read, from a terminal or a file.
const MAX_BYTES: usize = 4096;

/// Restores a terminal's settings when dropped, so a failed read never
/// leaves echo off.
struct EchoOff {
    fd: libc::c_int,
    original: libc::termios,
}

impl EchoOff {
    fn new(fd: libc::c_int) -> io::Result<Self> {
        // SAFETY: termios is plain data, and tcgetattr fills it in.
        let mut original: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: fd is an open terminal and `original` is a valid termios.
        if unsafe { libc::tcgetattr(fd, &mut original) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut quiet = original;
        quiet.c_lflag &= !libc::ECHO;
        quiet.c_lflag |= libc::ECHONL;
        // SAFETY: as above, with settings derived from the terminal's own.
        if unsafe { libc::tcsetattr(fd, libc::TCSAFLUSH, &quiet) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd, original })
    }
}

impl Drop for EchoOff {
    fn drop(&mut self) {
        // SAFETY: restores the settings read from the same terminal.
        unsafe { libc::tcsetattr(self.fd, libc::TCSAFLUSH, &self.original) };
    }
}

/// One line of at most [`MAX_BYTES`], without its line ending. A longer
/// line is refused rather than cut short, since a cut passphrase would
/// seal or fail to open with no sign why.
fn line(reader: &mut impl BufRead) -> io::Result<Zeroizing<String>> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(128));
    reader
        .take(MAX_BYTES as u64 + 2)
        .read_until(b'\n', &mut bytes)?;
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    if bytes.len() > MAX_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("a passphrase is at most {MAX_BYTES} bytes"),
        ));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "a passphrase must be UTF-8"))?;
    Ok(Zeroizing::new(text.to_owned()))
}

/// Asks for a passphrase on the controlling terminal, without echo.
pub fn prompt(question: &str) -> io::Result<Zeroizing<String>> {
    let terminal = File::options()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "there is no terminal to ask for a passphrase on",
            )
        })?;
    (&terminal).write_all(question.as_bytes())?;
    (&terminal).flush()?;
    let _echo = EchoOff::new(terminal.as_raw_fd())?;
    line(&mut BufReader::new(&terminal))
}

/// The first line of `path`.
pub fn from_file(path: &Path) -> io::Result<Zeroizing<String>> {
    line(&mut BufReader::new(File::open(path)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line_loses_its_ending_only() {
        assert_eq!(
            *line(&mut &b"correct horse\n"[..]).unwrap(),
            "correct horse"
        );
        assert_eq!(*line(&mut &b"windows\r\nnext"[..]).unwrap(), "windows");
        assert_eq!(*line(&mut &b" spaced \n"[..]).unwrap(), " spaced ");
        assert_eq!(*line(&mut &b"no ending"[..]).unwrap(), "no ending");
    }

    #[test]
    fn an_overlong_line_is_refused_not_cut() {
        let long = vec![b'a'; MAX_BYTES + 1];
        assert!(line(&mut &long[..]).is_err());
        let mut exact = vec![b'a'; MAX_BYTES];
        exact.push(b'\n');
        assert_eq!(line(&mut &exact[..]).unwrap().len(), MAX_BYTES);
    }

    #[test]
    fn a_passphrase_must_be_text() {
        assert!(line(&mut &b"\xff\xfe\n"[..]).is_err());
    }
}
