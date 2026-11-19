//! The store for online CA keys: files only pkid's service identity can
//! read.

use std::io::{self, Write};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use peios::file::{Disposition, FileAccess, OpenOptions};
use peios::security::sddl;
use peios_crypto::Secret;
use pki_keys::KeyStore;

/// Keeps each key in its own file in a directory.
///
/// Each file is created with a descriptor granting pkid's service identity
/// alone; not even Administrators can read it. An administrator who needs a
/// key without pkid takes ownership of the file, which is audited, or
/// exports the key through pkid while it runs.
pub struct ServiceKeyFiles {
    directory: PathBuf,
    service_sid: String,
}

impl ServiceKeyFiles {
    pub fn new(directory: &Path, service_sid: &str) -> Self {
        Self {
            directory: directory.to_path_buf(),
            service_sid: service_sid.to_owned(),
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.directory.join(format!("{name}.key"))
    }

    /// The descriptor each key file is created with.
    pub fn file_descriptor(&self) -> String {
        format!("D:P(A;;FA;;;{})", self.service_sid)
    }
}

impl KeyStore for ServiceKeyFiles {
    fn create(&self, name: &str, contents: &[u8]) -> io::Result<()> {
        let descriptor = sddl::parse(&self.file_descriptor())?;
        let path = self.path(name);
        let (file, _) = OpenOptions::new()
            .desired_access(FileAccess::WRITE_DATA)
            .disposition(Disposition::Create)
            .creator_sd(&descriptor)
            .create(None, &path)?;
        let mut file = std::fs::File::from(OwnedFd::from(file));
        let written = file.write_all(contents).and_then(|()| file.sync_all());
        if let Err(error) = written {
            drop(file);
            let _ = std::fs::remove_file(&path);
            return Err(error);
        }
        if let Some(directory) = path.parent() {
            std::fs::File::open(directory)?.sync_all()?;
        }
        Ok(())
    }

    fn read(&self, name: &str) -> io::Result<Secret> {
        std::fs::read(self.path(name)).map(Secret::new)
    }
}
