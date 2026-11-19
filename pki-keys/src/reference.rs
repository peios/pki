use std::fmt;
use std::str::FromStr;

use crate::KeyError;

/// Identifies a stored key: the provider that holds it, and a locator that
/// only that provider interprets, such as a file path or a key name.
///
/// Its text form, `provider:locator`, is how configuration records a CA's
/// key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyReference {
    provider: String,
    locator: String,
}

impl KeyReference {
    /// Accepts a provider name of lowercase letters, digits and hyphens, and
    /// a non-empty locator without control characters.
    pub fn new(provider: &str, locator: &str) -> Result<Self, KeyError> {
        let provider_valid = !provider.is_empty()
            && provider
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
        if !provider_valid {
            return Err(KeyError::InvalidReference(format!(
                "{provider:?} is not a provider name"
            )));
        }
        if locator.is_empty() || locator.chars().any(char::is_control) {
            return Err(KeyError::InvalidReference(format!(
                "{locator:?} is not a key locator"
            )));
        }
        Ok(Self {
            provider: provider.to_string(),
            locator: locator.to_string(),
        })
    }

    pub fn provider(&self) -> &str {
        &self.provider
    }

    pub fn locator(&self) -> &str {
        &self.locator
    }
}

impl fmt::Display for KeyReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}:{}", self.provider, self.locator)
    }
}

impl FromStr for KeyReference {
    type Err = KeyError;

    fn from_str(text: &str) -> Result<Self, KeyError> {
        let (provider, locator) = text.split_once(':').ok_or_else(|| {
            KeyError::InvalidReference(format!("{text:?} is not provider:locator"))
        })?;
        Self::new(provider, locator)
    }
}
