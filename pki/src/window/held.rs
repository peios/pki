//! Certificates the person requested in the window that are waiting for an
//! officer, remembered so that the window can save each once it is issued.
//!
//! They are the person's own, kept at `CurrentUser\Software\pki`, value
//! `Held`, a REG_MULTI_SZ of lines, as other GXWI programs keep what is a
//! person's. Each line is the CA, the request's number, the file to save
//! and the sealed key kept for it, separated by tabs. A line that can't be
//! read is left out.

use std::path::PathBuf;

use peios::registry::{CreateFlags, Data, Key, KeyAccess, OpenFlags, ValueType};

const PARENT: &str = "CurrentUser\\Software";
const CHILD: &str = "pki";
const OWN: &str = "CurrentUser\\Software\\pki";
const NAME: &str = "Held";

/// The most held requests that are remembered.
const MOST: usize = 256;

/// A request the window made, held for an officer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Held {
    pub ca: String,
    pub request: i64,
    /// Where its key and certificate are to be saved.
    pub out: PathBuf,
    /// Its key, sealed under the file's password, until then.
    pub key: PathBuf,
}

fn line(held: &Held) -> Option<String> {
    let out = held.out.to_str()?;
    let key = held.key.to_str()?;
    if [held.ca.as_str(), out, key]
        .iter()
        .any(|part| part.contains(['\t', '\n']))
    {
        return None;
    }
    Some(format!("{}\t{}\t{out}\t{key}", held.ca, held.request))
}

fn parse(line: &str) -> Option<Held> {
    let mut parts = line.split('\t');
    let held = Held {
        ca: parts.next()?.to_owned(),
        request: parts.next()?.parse().ok()?,
        out: PathBuf::from(parts.next()?),
        key: PathBuf::from(parts.next()?),
    };
    parts.next().is_none().then_some(held)
}

/// What is remembered. Nothing, if nothing can be read.
pub fn read() -> Vec<Held> {
    let Ok(key) = Key::open(None, OWN, KeyAccess::QUERY_VALUE, OpenFlags::empty()) else {
        return Vec::new();
    };
    let Ok(value) = key.query_value(NAME.as_bytes(), None) else {
        return Vec::new();
    };
    match Data::decode(value.ty, &value.data) {
        Data::MultiSz(lines) => lines.iter().filter_map(|l| parse(l)).take(MOST).collect(),
        _ => Vec::new(),
    }
}

fn write(all: &[Held]) -> Result<(), String> {
    let (parent, _) = Key::create(
        None,
        PARENT,
        KeyAccess::CREATE_SUB_KEY,
        CreateFlags::empty(),
        None,
        None,
    )
    .map_err(|error| error.to_string())?;
    let (own, _) = Key::create(
        Some(&parent),
        CHILD,
        KeyAccess::SET_VALUE,
        CreateFlags::empty(),
        None,
        None,
    )
    .map_err(|error| error.to_string())?;
    let lines: Vec<String> = all.iter().filter_map(line).collect();
    own.set_value(
        NAME.as_bytes(),
        ValueType::MULTI_SZ,
        &Data::MultiSz(lines).encode(),
    )
    .call()
    .map_err(|error| error.to_string())
}

/// Remembers `held`.
pub fn remember(held: Held) -> Result<(), String> {
    let mut all = read();
    all.retain(|h| !(h.ca == held.ca && h.request == held.request));
    all.push(held);
    let keep = all.len().saturating_sub(MOST);
    write(&all[keep..])
}

/// Forgets the request `request` at `ca`.
pub fn forget(ca: &str, request: i64) -> Result<(), String> {
    let mut all = read();
    let before = all.len();
    all.retain(|h| !(h.ca == ca && h.request == request));
    if all.len() == before {
        return Ok(());
    }
    write(&all)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_read_back_and_odd_ones_are_skipped() {
        let held = Held {
            ca: "issuing".into(),
            request: 42,
            out: PathBuf::from("/home/alice/www.p12"),
            key: PathBuf::from("/home/alice/www.p12.key"),
        };
        assert_eq!(parse(&line(&held).unwrap()), Some(held));
        assert_eq!(parse("issuing\tnot-a-number\t/a\t/b"), None);
        assert_eq!(parse("issuing\t1\t/a"), None);
        let tabbed = Held {
            out: PathBuf::from("/home/alice/a\tb.p12"),
            ..parse("issuing\t1\t/a\t/b").unwrap()
        };
        assert_eq!(line(&tabbed), None);
    }
}
