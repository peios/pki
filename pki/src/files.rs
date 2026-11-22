//! Reading certificates and requests, in PEM or DER, and writing pki's
//! output files.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use pem::{EncodeConfig, LineEnding, Pem};

use crate::failure::Failure;

pub const CERTIFICATE: &str = "CERTIFICATE";
pub const REQUEST: &str = "CERTIFICATE REQUEST";

/// `der` in PEM, with Unix line endings.
pub fn pem(label: &str, der: &[u8]) -> String {
    pem::encode_config(
        &Pem::new(label, der),
        EncodeConfig::new().set_line_ending(LineEnding::LF),
    )
}

pub fn read(path: &Path) -> Result<Vec<u8>, Failure> {
    std::fs::read(path).map_err(|error| Failure::io(&error).context(path.display()))
}

/// The DER in `path`, which holds either DER or one PEM block labelled
/// `label`. A request may also carry the older `NEW CERTIFICATE REQUEST`
/// label.
pub fn read_der(path: &Path, label: &str) -> Result<Vec<u8>, Failure> {
    let bytes = read(path)?;
    let text = bytes.trim_ascii_start();
    if !text.starts_with(b"-----BEGIN ") {
        return Ok(bytes);
    }
    let block = pem::parse(text)
        .map_err(|error| Failure::failed(format!("{}: {error}", path.display())))?;
    let accepted =
        block.tag() == label || (label == REQUEST && block.tag() == "NEW CERTIFICATE REQUEST");
    if !accepted {
        return Err(Failure::failed(format!(
            "{}: holds a {} where a {label} was expected",
            path.display(),
            block.tag()
        )));
    }
    Ok(block.into_contents())
}

/// An output file, created before pki asks pkid for its contents so that
/// a path it can't write fails first. It is removed again unless written.
pub struct Reserved {
    path: PathBuf,
    file: Option<File>,
    /// Where the contents go once written, for a file that replaces
    /// another: `path` is then a temporary file beside it.
    replaces: Option<PathBuf>,
}

impl Reserved {
    /// Creates `path`, which mustn't exist. `private` files are readable
    /// by their owner alone.
    pub fn new(path: &Path, private: bool) -> Result<Self, Failure> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(if private { 0o600 } else { 0o644 })
            .open(path)
            .map_err(|error| Failure::io(&error).context(path.display()))?;
        Ok(Self {
            path: path.to_owned(),
            file: Some(file),
            replaces: None,
        })
    }

    /// Like [`Reserved::new`], but `path` may exist: whatever is there is
    /// replaced whole once the new contents are written, and left alone if
    /// they aren't. For the window, whose file dialog has already asked
    /// the person whether to replace it.
    pub fn replacing(path: &Path, private: bool) -> Result<Self, Failure> {
        let name = path
            .file_name()
            .ok_or_else(|| Failure::usage(format!("{} is not a file", path.display())))?;
        let mut temporary = name.to_owned();
        temporary.push(format!(".pki-{}", std::process::id()));
        let temporary = path.with_file_name(temporary);
        let _ = std::fs::remove_file(&temporary);
        let mut reserved = Self::new(&temporary, private)?;
        reserved.replaces = Some(path.to_owned());
        Ok(reserved)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn write(mut self, contents: &[u8]) -> Result<(), Failure> {
        let mut file = self.file.take().expect("written once");
        file.write_all(contents)
            .and_then(|()| file.sync_all())
            .and_then(|()| match &self.replaces {
                Some(target) => std::fs::rename(&self.path, target),
                None => Ok(()),
            })
            .map_err(|error| {
                let _ = std::fs::remove_file(&self.path);
                let shown = self.replaces.as_ref().unwrap_or(&self.path);
                Failure::io(&error).context(shown.display())
            })
    }
}

impl Drop for Reserved {
    fn drop(&mut self) {
        if self.file.take().is_some() {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// `path` as pkid must be given it: absolute, since pkid doesn't share
/// pki's working directory.
pub fn absolute(path: &Path) -> Result<String, Failure> {
    let absolute =
        std::path::absolute(path).map_err(|error| Failure::io(&error).context(path.display()))?;
    absolute
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| Failure::usage(format!("{}: the path is not UTF-8", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("pki-files-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    #[test]
    fn a_replacing_file_replaces_only_once_written() {
        let path = scratch("replaced.p12");
        std::fs::write(&path, b"old").unwrap();
        assert!(
            Reserved::new(&path, true).is_err(),
            "pki itself never replaces"
        );
        drop(Reserved::replacing(&path, true).unwrap());
        assert_eq!(std::fs::read(&path).unwrap(), b"old");
        Reserved::replacing(&path, true)
            .unwrap()
            .write(b"new")
            .unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        let leftovers = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .filter(|entry| {
                entry
                    .as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with("replaced.p12.pki-")
            })
            .count();
        assert_eq!(leftovers, 0);
    }

    #[test]
    fn reads_pem_or_der() {
        let der = vec![0x30, 0x03, 0x02, 0x01, 0x05];
        let path = scratch("both.pem");
        std::fs::write(&path, pem(CERTIFICATE, &der)).unwrap();
        assert_eq!(read_der(&path, CERTIFICATE).unwrap(), der);
        std::fs::write(&path, &der).unwrap();
        assert_eq!(read_der(&path, CERTIFICATE).unwrap(), der);
        std::fs::write(&path, pem(REQUEST, &der)).unwrap();
        let failure = read_der(&path, CERTIFICATE).unwrap_err();
        assert!(
            failure.message.contains("CERTIFICATE REQUEST"),
            "{failure:?}"
        );
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn reserved_files_vanish_unless_written() {
        let path = scratch("reserved");
        let _ = std::fs::remove_file(&path);
        drop(Reserved::new(&path, true).unwrap());
        assert!(!path.exists());

        Reserved::new(&path, true).unwrap().write(b"kept").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"kept");
        // An existing file is never overwritten.
        let failure = Reserved::new(&path, true).err().unwrap();
        assert_eq!(failure.kind, crate::failure::Kind::Exists);
        assert_eq!(std::fs::read(&path).unwrap(), b"kept");
        std::fs::remove_file(&path).unwrap();
    }
}
