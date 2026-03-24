//! English-only BIP-39 mnemonic handling.

use bip39::{Language, Mnemonic};

/// Error returned when BIP-39 parsing or validation fails.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Bip39Error {
    /// The mnemonic uses an unsupported number of words.
    UnsupportedWordCount(usize),
    /// The mnemonic contains a word outside the English BIP-39 wordlist.
    UnknownWord(usize),
    /// The mnemonic checksum is invalid.
    InvalidChecksum,
    /// The mnemonic input could not be interpreted as a valid English phrase.
    InvalidPhrase,
}

impl core::fmt::Display for Bip39Error {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedWordCount(count) => {
                write!(formatter, "unsupported BIP-39 word count: {count}")
            }
            Self::UnknownWord(index) => write!(formatter, "unknown BIP-39 word at index {index}"),
            Self::InvalidChecksum => formatter.write_str("invalid BIP-39 checksum"),
            Self::InvalidPhrase => formatter.write_str("invalid BIP-39 mnemonic phrase"),
        }
    }
}

impl std::error::Error for Bip39Error {}

impl From<bip39::Error> for Bip39Error {
    fn from(value: bip39::Error) -> Self {
        match value {
            bip39::Error::BadWordCount(count) => Self::UnsupportedWordCount(count),
            bip39::Error::UnknownWord(index) => Self::UnknownWord(index),
            bip39::Error::InvalidChecksum => Self::InvalidChecksum,
            bip39::Error::BadEntropyBitCount(_) | bip39::Error::AmbiguousLanguages(_) => {
                Self::InvalidPhrase
            }
        }
    }
}

/// Validated English BIP-39 mnemonic phrase.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Bip39Mnemonic {
    inner: Mnemonic,
}

impl Bip39Mnemonic {
    /// Parses and validates an English BIP-39 mnemonic phrase.
    ///
    /// # Errors
    ///
    /// Returns an error if the phrase has an unsupported word count, contains
    /// words outside the English BIP-39 wordlist, or fails checksum validation.
    pub fn parse(mnemonic: &str) -> Result<Self, Bip39Error> {
        let inner = Mnemonic::parse_in(Language::English, mnemonic)?;
        Ok(Self { inner })
    }

    /// Returns `true` when `mnemonic` is a valid English BIP-39 phrase.
    #[must_use]
    pub fn is_valid(mnemonic: &str) -> bool {
        Self::parse(mnemonic).is_ok()
    }

    /// Returns the mnemonic entropy bytes.
    #[must_use]
    pub fn entropy(&self) -> Vec<u8> {
        self.inner.to_entropy()
    }

    /// Derives the canonical 64-byte BIP-39 seed.
    #[must_use]
    pub fn seed(&self, password: Option<&str>) -> [u8; 64] {
        self.inner.to_seed(password.unwrap_or_default())
    }

    /// Returns the number of words in the mnemonic phrase.
    #[must_use]
    pub fn word_count(&self) -> usize {
        self.inner.word_count()
    }
}

impl core::str::FromStr for Bip39Mnemonic {
    type Err = Bip39Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use core::fmt::Write as _;

    use super::{Bip39Error, Bip39Mnemonic};

    #[test]
    fn parses_and_derives_issue_vector_one() {
        let Ok(mnemonic) = Bip39Mnemonic::parse(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        ) else {
            panic!("vector one should parse");
        };

        assert_eq!(hex_encode(&mnemonic.entropy()), "00000000000000000000000000000000");
        assert_eq!(
            hex_encode(&mnemonic.seed(None)),
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
        );
    }

    #[test]
    fn parses_and_derives_issue_vector_two() {
        let Ok(mnemonic) = Bip39Mnemonic::parse(
            "mammal step public march absorb critic visa rent miss color erase exhaust south lift ordinary ceiling stay physical",
        ) else {
            panic!("vector two should parse");
        };

        assert_eq!(
            hex_encode(&mnemonic.entropy()),
            "86baaeb443e00c67bd2db28dc5b531a7bd0302e71127d4f4"
        );
        assert_eq!(
            hex_encode(&mnemonic.seed(None)),
            "d8c228addf9a9cfe5b7934223737815e2f709b3ac12b0c1b2aaec921e5d3a2e8aeea1df817af8159f981798dacd5a930a1fcd8570ba4845078c1b1d09fa060cb"
        );
    }

    #[test]
    fn parses_and_derives_issue_vector_three_with_password() {
        let Ok(mnemonic) = Bip39Mnemonic::parse(
            "culture flower sunny seat maximum begin design magnet side permit coin dial alter insect whisper series desk power cream afford regular strike poem ostrich",
        ) else {
            panic!("vector three should parse");
        };

        assert_eq!(
            hex_encode(&mnemonic.entropy()),
            "358b3365e12896288ef42fc7f464b59e8076ea3ea6203bf528cb823b4dae29c4"
        );
        assert_eq!(
            hex_encode(&mnemonic.seed(Some("test"))),
            "87ec3e2ae9294cb5500698e6e6ee8357aa56222badae0e6b4150492c95ede7ddfca27c952afafb388453def93fac72f5d7e099debd79e85c2088f9b3e7a65df6"
        );
    }

    #[test]
    fn rejects_invalid_checksum() {
        let Err(error) = Bip39Mnemonic::parse(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
        ) else {
            panic!("invalid checksum should fail");
        };

        assert_eq!(error, Bip39Error::InvalidChecksum);
        assert!(!Bip39Mnemonic::is_valid(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
        ));
    }

    #[test]
    fn rejects_unknown_words() {
        let Err(error) = Bip39Mnemonic::parse(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon nope",
        ) else {
            panic!("unknown word should fail");
        };

        assert_eq!(error, Bip39Error::UnknownWord(11));
    }

    #[test]
    fn rejects_unsupported_word_count() {
        let Err(error) = Bip39Mnemonic::parse(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
        ) else {
            panic!("11 words should fail");
        };

        assert_eq!(error, Bip39Error::UnsupportedWordCount(11));
    }

    fn hex_encode(bytes: &[u8]) -> String {
        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            let result = write!(&mut encoded, "{byte:02x}");
            assert!(result.is_ok(), "writing to a string should succeed");
        }
        encoded
    }
}
