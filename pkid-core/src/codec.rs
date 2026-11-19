//! Framing, and reading MessagePack maps field by field.

use std::fmt;
use std::io::{self, Read, Write};

use peios::msgpack::{Reader, Type, Writer};

/// A payload that isn't a valid message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodecError(pub String);

impl fmt::Display for CodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "malformed message: {}", self.0)
    }
}

impl std::error::Error for CodecError {}

pub(crate) fn malformed(detail: impl Into<String>) -> CodecError {
    CodecError(detail.into())
}

impl From<peios::Error> for CodecError {
    fn from(error: peios::Error) -> Self {
        CodecError(error.to_string())
    }
}

/// A failure to read a frame.
#[derive(Debug)]
pub enum FrameError {
    /// The frame announces more than the reader accepts. Its payload has not
    /// been read.
    TooLarge(usize),
    Io(io::Error),
}

impl fmt::Display for FrameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge(length) => write!(formatter, "a {length}-byte message is too large"),
            Self::Io(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for FrameError {}

impl From<io::Error> for FrameError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Writes one frame: the payload's length, then the payload.
pub fn write_frame(stream: &mut impl Write, payload: &[u8]) -> io::Result<()> {
    let length = u32::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "message too large"))?;
    stream.write_all(&length.to_le_bytes())?;
    stream.write_all(payload)?;
    stream.flush()
}

/// Reads one frame of at most `max` payload bytes. An oversized frame is
/// refused before its payload is read, so the caller can reply first.
pub fn read_frame(stream: &mut impl Read, max: usize) -> Result<Vec<u8>, FrameError> {
    let mut length = [0; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_le_bytes(length) as usize;
    if length > max {
        return Err(FrameError::TooLarge(length));
    }
    let mut payload = vec![0; length];
    stream.read_exact(&mut payload)?;
    Ok(payload)
}

/// The raw encoding of the value at the reader's position, which it skips.
fn value<'a>(buffer: &'a [u8], reader: &mut Reader<'a>) -> Result<&'a [u8], CodecError> {
    let start = buffer.len() - reader.remaining();
    reader.skip()?;
    let end = buffer.len() - reader.remaining();
    Ok(&buffer[start..end])
}

/// A map's entries, each value still encoded.
pub(crate) struct Fields<'a> {
    entries: Vec<(&'a str, &'a [u8])>,
}

impl<'a> Fields<'a> {
    /// Reads a map that is the whole of `buffer`, refusing duplicate keys
    /// and trailing bytes.
    pub(crate) fn read(buffer: &'a [u8]) -> Result<Self, CodecError> {
        let mut reader = Reader::new(buffer);
        if reader.peek() != Some(Type::Map) {
            return Err(malformed("expected a map"));
        }
        let count = reader.read_map()?;
        let mut entries: Vec<(&'a str, &'a [u8])> = Vec::with_capacity(count.min(64));
        for _ in 0..count {
            let key = reader.read_str()?;
            if entries.iter().any(|(existing, _)| *existing == key) {
                return Err(malformed(format!("duplicate key {key}")));
            }
            entries.push((key, value(buffer, &mut reader)?));
        }
        if reader.remaining() != 0 {
            return Err(malformed("trailing bytes"));
        }
        Ok(Self { entries })
    }

    fn raw(&self, key: &str) -> Option<&'a [u8]> {
        self.entries
            .iter()
            .find(|(existing, _)| *existing == key)
            .map(|(_, value)| *value)
    }

    fn required(&self, key: &str) -> Result<&'a [u8], CodecError> {
        self.raw(key)
            .ok_or_else(|| malformed(format!("missing {key}")))
    }

    /// The value at `key`, absent if it is missing or nil.
    fn optional(&self, key: &str) -> Option<&'a [u8]> {
        self.raw(key)
            .filter(|value| Reader::new(value).peek() != Some(Type::Nil))
    }

    pub(crate) fn str(&self, key: &str) -> Result<&'a str, CodecError> {
        Ok(Reader::new(self.required(key)?).read_str()?)
    }

    pub(crate) fn opt_str(&self, key: &str) -> Result<Option<&'a str>, CodecError> {
        self.optional(key)
            .map(|value| Reader::new(value).read_str().map_err(CodecError::from))
            .transpose()
    }

    pub(crate) fn bin(&self, key: &str) -> Result<&'a [u8], CodecError> {
        Ok(Reader::new(self.required(key)?).read_bin()?)
    }

    pub(crate) fn opt_bin(&self, key: &str) -> Result<Option<&'a [u8]>, CodecError> {
        self.optional(key)
            .map(|value| Reader::new(value).read_bin().map_err(CodecError::from))
            .transpose()
    }

    pub(crate) fn opt_uint(&self, key: &str) -> Result<Option<u64>, CodecError> {
        self.optional(key)
            .map(|value| Reader::new(value).read_uint().map_err(CodecError::from))
            .transpose()
    }

    /// The strings at `key`, or none if it is missing or nil.
    pub(crate) fn opt_strings(&self, key: &str) -> Result<Option<Vec<String>>, CodecError> {
        if self.optional(key).is_none() {
            return Ok(None);
        }
        self.strings(key).map(Some)
    }

    pub(crate) fn int(&self, key: &str) -> Result<i64, CodecError> {
        Ok(Reader::new(self.required(key)?).read_int()?)
    }

    pub(crate) fn opt_int(&self, key: &str) -> Result<Option<i64>, CodecError> {
        self.optional(key)
            .map(|value| Reader::new(value).read_int().map_err(CodecError::from))
            .transpose()
    }

    pub(crate) fn uint(&self, key: &str) -> Result<u64, CodecError> {
        Ok(Reader::new(self.required(key)?).read_uint()?)
    }

    pub(crate) fn bool(&self, key: &str) -> Result<bool, CodecError> {
        match self.optional(key) {
            Some(value) => Ok(Reader::new(value).read_bool()?),
            None => Ok(false),
        }
    }

    /// The map at `key`.
    pub(crate) fn map(&self, key: &str) -> Result<Fields<'a>, CodecError> {
        Fields::read(self.required(key)?)
    }

    pub(crate) fn opt_map(&self, key: &str) -> Result<Option<Fields<'a>>, CodecError> {
        self.optional(key).map(Fields::read).transpose()
    }

    /// The array at `key`, each element decoded by `decode`.
    pub(crate) fn array<T>(
        &self,
        key: &str,
        decode: impl Fn(&'a [u8]) -> Result<T, CodecError>,
    ) -> Result<Vec<T>, CodecError> {
        let buffer = self.required(key)?;
        let mut reader = Reader::new(buffer);
        let count = reader.read_array()?;
        let mut items = Vec::with_capacity(count.min(1024));
        for _ in 0..count {
            items.push(decode(value(buffer, &mut reader)?)?);
        }
        Ok(items)
    }

    pub(crate) fn strings(&self, key: &str) -> Result<Vec<String>, CodecError> {
        self.array(key, |value| Ok(Reader::new(value).read_str()?.to_owned()))
    }
}

/// A map under construction. Each value is encoded on its own, since a
/// [`Writer`] only finishes a single value, and the map is assembled at the
/// end. The first encoding error is kept and reported by
/// [`MapWriter::finish`].
pub(crate) struct MapWriter {
    entries: Vec<(String, Vec<u8>)>,
    error: Option<CodecError>,
}

impl MapWriter {
    pub(crate) fn new() -> Self {
        Self {
            entries: Vec::new(),
            error: None,
        }
    }

    fn put(&mut self, key: &str, write: impl FnOnce(&mut Writer)) -> &mut Self {
        let mut writer = Writer::new();
        write(&mut writer);
        match writer.to_bytes() {
            Ok(value) => self.entries.push((key.to_owned(), value)),
            Err(error) => {
                self.error.get_or_insert(error.into());
            }
        }
        self
    }

    pub(crate) fn str(&mut self, key: &str, value: &str) -> &mut Self {
        self.put(key, |writer| {
            writer.write_str(value);
        })
    }

    pub(crate) fn opt_str(&mut self, key: &str, value: Option<&str>) -> &mut Self {
        if let Some(value) = value {
            self.str(key, value);
        }
        self
    }

    pub(crate) fn bin(&mut self, key: &str, value: &[u8]) -> &mut Self {
        self.put(key, |writer| {
            writer.write_bin(value);
        })
    }

    pub(crate) fn opt_bin(&mut self, key: &str, value: Option<&[u8]>) -> &mut Self {
        if let Some(value) = value {
            self.bin(key, value);
        }
        self
    }

    pub(crate) fn int(&mut self, key: &str, value: i64) -> &mut Self {
        self.put(key, |writer| {
            writer.write_int(value);
        })
    }

    pub(crate) fn opt_uint(&mut self, key: &str, value: Option<u64>) -> &mut Self {
        if let Some(value) = value {
            self.uint(key, value);
        }
        self
    }

    pub(crate) fn opt_strings(&mut self, key: &str, values: Option<&[String]>) -> &mut Self {
        if let Some(values) = values {
            self.strings(key, values);
        }
        self
    }

    pub(crate) fn opt_int(&mut self, key: &str, value: Option<i64>) -> &mut Self {
        if let Some(value) = value {
            self.int(key, value);
        }
        self
    }

    pub(crate) fn uint(&mut self, key: &str, value: u64) -> &mut Self {
        self.put(key, |writer| {
            writer.write_uint(value);
        })
    }

    pub(crate) fn bool(&mut self, key: &str, value: bool) -> &mut Self {
        self.put(key, |writer| {
            writer.write_bool(value);
        })
    }

    /// An already encoded value.
    pub(crate) fn raw(&mut self, key: &str, encoded: &[u8]) -> &mut Self {
        self.put(key, |writer| {
            writer.write_raw(encoded);
        })
    }

    pub(crate) fn strings(&mut self, key: &str, values: &[String]) -> &mut Self {
        self.put(key, |writer| {
            writer.write_array(values.len() as u32);
            for value in values {
                writer.write_str(value);
            }
        })
    }

    /// An array of already encoded values.
    pub(crate) fn array(&mut self, key: &str, encoded: &[Vec<u8>]) -> &mut Self {
        self.put(key, |writer| {
            writer.write_array(encoded.len() as u32);
            for value in encoded {
                writer.write_raw(value);
            }
        })
    }

    pub(crate) fn finish(&self) -> Result<Vec<u8>, CodecError> {
        if let Some(error) = &self.error {
            return Err(error.clone());
        }
        let mut writer = Writer::new();
        writer.write_map(self.entries.len() as u32);
        for (key, value) in &self.entries {
            writer.write_str(key).write_raw(value);
        }
        Ok(writer.to_bytes()?)
    }
}
