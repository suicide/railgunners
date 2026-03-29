use railgun_core::{Bip39Error, Bip39Mnemonic, Bip39WordCount};

pub(crate) fn generate_mnemonic(word_count: Bip39WordCount) -> Result<Bip39Mnemonic, Bip39Error> {
    Bip39Mnemonic::generate(word_count)
}

pub(crate) fn validate_mnemonic(mnemonic: &str) -> Result<Bip39Mnemonic, Bip39Error> {
    Bip39Mnemonic::parse(mnemonic)
}

#[must_use]
pub(crate) fn mnemonic_seed_hex(mnemonic: &Bip39Mnemonic, password: Option<&str>) -> String {
    hex::encode(mnemonic.seed(password))
}
