//! Passphrases that protect keys at rest.

use peios_crypto::Secret;
use unicode_normalization::UnicodeNormalization;

use crate::KeyError;

/// The fewest characters a new passphrase may have: the minimum NIST SP
/// 800-63B-4 sets for a password used on its own.
///
/// A sealed key file can be attacked offline by anyone who copies it, so
/// nothing limits how many guesses they make. Argon2id makes each guess
/// costly; length is what makes guessing hopeless. There are no composition
/// rules, which push people towards predictable substitutions.
pub const MIN_PASSPHRASE_CHARS: usize = 15;

/// A passphrase for opening a key that already exists.
///
/// No strength rule applies, so keys sealed under an older rule still open.
/// The text is normalised to Unicode NFKC, so a passphrase typed on another
/// keyboard or system, which may encode the same characters differently,
/// gives the same key.
#[derive(Debug)]
pub struct Passphrase(Secret);

impl Passphrase {
    pub fn new(text: &str) -> Self {
        Self(normalise(text).0)
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        self.0.expose()
    }
}

/// A passphrase for sealing a key: at least [`MIN_PASSPHRASE_CHARS`]
/// characters once normalised.
///
/// Every path that seals a key takes this type, so no tool can seal a key
/// under a shorter passphrase.
#[derive(Debug)]
pub struct NewPassphrase(Passphrase);

impl NewPassphrase {
    pub fn new(text: &str) -> Result<Self, KeyError> {
        let (secret, chars) = normalise(text);
        if chars < MIN_PASSPHRASE_CHARS {
            return Err(KeyError::WeakPassphrase(format!(
                "it has {chars} characters and needs at least {MIN_PASSPHRASE_CHARS}"
            )));
        }
        Ok(Self(Passphrase(secret)))
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        self.0.bytes()
    }
}

/// The NFKC form of `text`, with its length in characters.
fn normalise(text: &str) -> (Secret, usize) {
    let normalised: String = text.nfkc().collect();
    let chars = normalised.chars().count();
    (Secret::from(normalised), chars)
}
