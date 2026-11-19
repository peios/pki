//! Registry values as read by the native layer, and their validation.

use std::collections::BTreeMap;

use crate::PolicyError;

/// One Registry value's data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegData {
    Sz(String),
    MultiSz(Vec<String>),
    Dword(u32),
    Binary(Vec<u8>),
}

/// The values of one Registry key. Value names are case-insensitive.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Values(BTreeMap<String, RegData>);

impl Values {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, name: &str, data: RegData) {
        self.0.insert(name.to_ascii_lowercase(), data);
    }

    pub(crate) fn get(&self, name: &str) -> Option<&RegData> {
        self.0.get(&name.to_ascii_lowercase())
    }

    pub(crate) fn sz(&self, name: &str) -> Result<Option<&str>, PolicyError> {
        match self.get(name) {
            None => Ok(None),
            Some(RegData::Sz(text)) => Ok(Some(text)),
            Some(_) => Err(wrong_type(name, "REG_SZ")),
        }
    }

    pub(crate) fn required_sz(&self, name: &str) -> Result<&str, PolicyError> {
        self.sz(name)?.ok_or_else(|| missing(name))
    }

    pub(crate) fn multi_sz(&self, name: &str) -> Result<&[String], PolicyError> {
        match self.get(name) {
            None => Err(missing(name)),
            Some(RegData::MultiSz(items)) => Ok(items),
            Some(_) => Err(wrong_type(name, "REG_MULTI_SZ")),
        }
    }

    pub(crate) fn dword(&self, name: &str) -> Result<Option<u32>, PolicyError> {
        match self.get(name) {
            None => Ok(None),
            Some(RegData::Dword(value)) => Ok(Some(*value)),
            Some(_) => Err(wrong_type(name, "REG_DWORD")),
        }
    }

    pub(crate) fn required_dword(&self, name: &str) -> Result<u32, PolicyError> {
        self.dword(name)?.ok_or_else(|| missing(name))
    }

    pub(crate) fn binary(&self, name: &str) -> Result<Option<&[u8]>, PolicyError> {
        match self.get(name) {
            None => Ok(None),
            Some(RegData::Binary(bytes)) if !bytes.is_empty() => Ok(Some(bytes)),
            Some(RegData::Binary(_)) => Err(PolicyError::InvalidConfiguration(format!(
                "{name} is empty"
            ))),
            Some(_) => Err(wrong_type(name, "REG_BINARY")),
        }
    }
}

fn missing(name: &str) -> PolicyError {
    PolicyError::InvalidConfiguration(format!("{name} is required"))
}

fn wrong_type(name: &str, expected: &str) -> PolicyError {
    PolicyError::InvalidConfiguration(format!("{name} must be {expected}"))
}
