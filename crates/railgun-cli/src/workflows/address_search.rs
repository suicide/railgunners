use railgun_core::{
    Bip39Error, Bip39Mnemonic, Bip39WordCount, encode_railgun_address, encode_shareable_viewing_key,
};
use railgun_types::{ChainScope, RailgunAddress, ShareableViewingKeyData};
use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    thread,
};

use crate::workflows::{
    keys::{derive_wallet_keys, pack_derived_spending_public_key},
    mnemonic::generate_mnemonic,
};

#[derive(Clone, Debug)]
pub(crate) struct AddressSearchOptions {
    pub(crate) target_addresses: Vec<RailgunAddress>,
    pub(crate) word_count: Bip39WordCount,
    pub(crate) index: u32,
    pub(crate) required_suffix: Option<String>,
    pub(crate) worker_count: usize,
    pub(crate) progress_every: u64,
    pub(crate) max_attempts: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AddressSearchMatch {
    minimum_target_address: RailgunAddress,
    derived_address: RailgunAddress,
    mnemonic: String,
    index: u32,
    word_count: usize,
    required_suffix: Option<String>,
    viewing_private_key_hex: String,
    packed_spending_public_key_hex: String,
    shareable_viewing_key: String,
    attempts: u64,
    worker_count: usize,
}

impl AddressSearchMatch {
    #[allow(clippy::too_many_arguments)]
    fn new(
        minimum_target_address: RailgunAddress,
        derived_address: RailgunAddress,
        mnemonic: String,
        index: u32,
        word_count: usize,
        required_suffix: Option<String>,
        viewing_private_key_hex: String,
        packed_spending_public_key_hex: String,
        shareable_viewing_key: String,
        attempts: u64,
        worker_count: usize,
    ) -> Self {
        Self {
            minimum_target_address,
            derived_address,
            mnemonic,
            index,
            word_count,
            required_suffix,
            viewing_private_key_hex,
            packed_spending_public_key_hex,
            shareable_viewing_key,
            attempts,
            worker_count,
        }
    }

    #[must_use]
    pub(crate) const fn minimum_target_address(&self) -> &RailgunAddress {
        &self.minimum_target_address
    }

    #[must_use]
    pub(crate) const fn derived_address(&self) -> &RailgunAddress {
        &self.derived_address
    }

    #[must_use]
    pub(crate) fn mnemonic(&self) -> &str {
        &self.mnemonic
    }

    #[must_use]
    pub(crate) const fn index(&self) -> u32 {
        self.index
    }

    #[must_use]
    pub(crate) const fn word_count(&self) -> usize {
        self.word_count
    }

    #[must_use]
    pub(crate) fn required_suffix(&self) -> Option<&str> {
        self.required_suffix.as_deref()
    }

    #[must_use]
    pub(crate) fn viewing_private_key_hex(&self) -> &str {
        &self.viewing_private_key_hex
    }

    #[must_use]
    pub(crate) fn packed_spending_public_key_hex(&self) -> &str {
        &self.packed_spending_public_key_hex
    }

    #[must_use]
    pub(crate) fn shareable_viewing_key(&self) -> &str {
        &self.shareable_viewing_key
    }

    #[must_use]
    pub(crate) const fn attempts(&self) -> u64 {
        self.attempts
    }

    #[must_use]
    pub(crate) const fn worker_count(&self) -> usize {
        self.worker_count
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum AddressSearchError {
    EmptyTargets,
    MaxAttemptsExceeded(u64),
    Bip39(Bip39Error),
    KeyDerivation(String),
    AddressEncoding(String),
    ViewingKeyEncoding(String),
    WorkerFailure,
}

impl fmt::Display for AddressSearchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyTargets => formatter.write_str("at least one --target-address is required"),
            Self::MaxAttemptsExceeded(attempts) => {
                write!(formatter, "no matching address found in {attempts} attempts")
            }
            Self::Bip39(error) => write!(formatter, "{error}"),
            Self::KeyDerivation(error)
            | Self::AddressEncoding(error)
            | Self::ViewingKeyEncoding(error) => write!(formatter, "{error}"),
            Self::WorkerFailure => formatter.write_str("all search workers exited unexpectedly"),
        }
    }
}

impl std::error::Error for AddressSearchError {}

impl From<Bip39Error> for AddressSearchError {
    fn from(value: Bip39Error) -> Self {
        Self::Bip39(value)
    }
}

pub(crate) fn search_lower_address(
    options: AddressSearchOptions,
    json: bool,
) -> Result<AddressSearchMatch, crate::error::CliError> {
    search_lower_address_with_generator(options, json, move |word_count| {
        generate_mnemonic(word_count)
    })
    .map_err(|error| crate::error::CliError::command(error.to_string(), json))
}

fn search_lower_address_with_generator<F>(
    options: AddressSearchOptions,
    json: bool,
    generator: F,
) -> Result<AddressSearchMatch, AddressSearchError>
where
    F: Fn(Bip39WordCount) -> Result<Bip39Mnemonic, Bip39Error> + Send + Sync + 'static,
{
    let minimum_target = options
        .target_addresses
        .iter()
        .min_by(|left, right| left.as_str().cmp(right.as_str()))
        .cloned()
        .ok_or(AddressSearchError::EmptyTargets)?;

    if options.max_attempts == Some(0) {
        return Err(AddressSearchError::MaxAttemptsExceeded(0));
    }

    let options = Arc::new(options);
    let generator = Arc::new(generator);
    let stop = Arc::new(AtomicBool::new(false));
    let attempts = Arc::new(AtomicU64::new(0));
    let (sender, receiver) = mpsc::channel();

    thread::scope(|scope| {
        for worker_id in 0..options.worker_count {
            let sender = sender.clone();
            let minimum_target = minimum_target.clone();
            let options = Arc::clone(&options);
            let generator = Arc::clone(&generator);
            let stop = Arc::clone(&stop);
            let attempts = Arc::clone(&attempts);

            scope.spawn(move || {
                worker_loop(
                    worker_id,
                    &minimum_target,
                    &options,
                    json,
                    generator.as_ref(),
                    &stop,
                    &attempts,
                    &sender,
                );
            });
        }

        drop(sender);

        match receiver.recv() {
            Ok(WorkerMessage::Found(found)) => {
                stop.store(true, Ordering::Relaxed);
                Ok(found)
            }
            Ok(WorkerMessage::Failed(error)) => {
                stop.store(true, Ordering::Relaxed);
                Err(error)
            }
            Err(_) => {
                let attempt_count = attempts.load(Ordering::Relaxed);
                if let Some(max_attempts) = options.max_attempts {
                    if attempt_count >= max_attempts {
                        return Err(AddressSearchError::MaxAttemptsExceeded(max_attempts));
                    }
                }
                Err(AddressSearchError::WorkerFailure)
            }
        }
    })
}

enum WorkerMessage {
    Found(AddressSearchMatch),
    Failed(AddressSearchError),
}

#[allow(clippy::too_many_arguments)]
fn worker_loop<F>(
    worker_id: usize,
    minimum_target: &RailgunAddress,
    options: &AddressSearchOptions,
    json: bool,
    generator: &F,
    stop: &AtomicBool,
    attempts: &AtomicU64,
    sender: &mpsc::Sender<WorkerMessage>,
) where
    F: Fn(Bip39WordCount) -> Result<Bip39Mnemonic, Bip39Error>,
{
    while !stop.load(Ordering::Relaxed) {
        let attempt = attempts.fetch_add(1, Ordering::Relaxed) + 1;
        if options.max_attempts.is_some_and(|max_attempts| attempt > max_attempts) {
            return;
        }

        let mnemonic = match generator(options.word_count) {
            Ok(mnemonic) => mnemonic,
            Err(error) => {
                let _ = sender.send(WorkerMessage::Failed(AddressSearchError::Bip39(error)));
                stop.store(true, Ordering::Relaxed);
                return;
            }
        };

        let phrase = mnemonic.phrase();
        let derived = match derive_wallet_keys(&mnemonic, options.index) {
            Ok(derived) => derived,
            Err(error) => {
                let _ = sender.send(WorkerMessage::Failed(AddressSearchError::KeyDerivation(
                    error.to_string(),
                )));
                stop.store(true, Ordering::Relaxed);
                return;
            }
        };
        let packed_spending_public_key =
            match pack_derived_spending_public_key(derived.spending_public_key()) {
                Ok(key) => key,
                Err(error) => {
                    let _ = sender.send(WorkerMessage::Failed(
                        AddressSearchError::ViewingKeyEncoding(error.to_string()),
                    ));
                    stop.store(true, Ordering::Relaxed);
                    return;
                }
            };
        let candidate_address = match encode_railgun_address(
            1,
            derived.master_public_key(),
            ChainScope::AllChains,
            derived.viewing_public_key(),
        ) {
            Ok(address) => address,
            Err(error) => {
                let _ = sender.send(WorkerMessage::Failed(AddressSearchError::AddressEncoding(
                    error.to_string(),
                )));
                stop.store(true, Ordering::Relaxed);
                return;
            }
        };

        if options.progress_every > 0 && attempt % options.progress_every == 0 && !json {
            eprintln!(
                "Attempts: {attempt} worker: {worker_id} currentAddress: {} targetMinimum: {}",
                candidate_address.as_str(),
                minimum_target.as_str(),
            );
        }

        if candidate_address.as_str() < minimum_target.as_str()
            && options
                .required_suffix
                .as_deref()
                .is_none_or(|suffix| candidate_address.as_str().ends_with(suffix))
        {
            let packed_spending_public_key_hex = hex::encode(packed_spending_public_key.as_bytes());
            let shareable_viewing_key =
                match encode_shareable_viewing_key(&ShareableViewingKeyData::new(
                    *derived.viewing_private_key(),
                    packed_spending_public_key,
                )) {
                    Ok(key) => key,
                    Err(error) => {
                        let _ = sender.send(WorkerMessage::Failed(
                            AddressSearchError::ViewingKeyEncoding(error.to_string()),
                        ));
                        stop.store(true, Ordering::Relaxed);
                        return;
                    }
                };
            let result = AddressSearchMatch::new(
                minimum_target.clone(),
                candidate_address,
                phrase,
                options.index,
                options.word_count.as_usize(),
                options.required_suffix.clone(),
                hex::encode(derived.viewing_private_key().as_bytes()),
                packed_spending_public_key_hex,
                shareable_viewing_key,
                attempt,
                options.worker_count,
            );
            stop.store(true, Ordering::Relaxed);
            let _ = sender.send(WorkerMessage::Found(result));
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AddressSearchError, AddressSearchOptions, search_lower_address_with_generator};
    use crate::workflows::keys::derive_wallet_keys;
    use railgun_core::{Bip39Mnemonic, Bip39WordCount, encode_railgun_address};
    use railgun_types::ChainScope;
    use railgun_types::RailgunAddress;
    use std::sync::{Arc, Mutex};

    fn address(value: &str) -> RailgunAddress {
        RailgunAddress::parse(value).unwrap_or_else(|_| panic!("test address should parse"))
    }

    #[test]
    fn rejects_empty_target_list() {
        let Err(error) = search_lower_address_with_generator(
            AddressSearchOptions {
                target_addresses: Vec::new(),
                word_count: Bip39WordCount::Words12,
                index: 0,
                required_suffix: None,
                worker_count: 1,
                progress_every: 0,
                max_attempts: Some(1),
            },
            true,
            |_| unreachable!("generator should not run"),
        ) else {
            panic!("empty target list should fail");
        };

        assert_eq!(error, AddressSearchError::EmptyTargets);
    }

    #[test]
    fn respects_zero_max_attempts() {
        let Err(error) = search_lower_address_with_generator(
            AddressSearchOptions {
                target_addresses: vec![address(
                    "0zk1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqunpd9kxwatwqyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqhshkca",
                )],
                word_count: Bip39WordCount::Words12,
                index: 0,
                required_suffix: None,
                worker_count: 1,
                progress_every: 0,
                max_attempts: Some(0),
            },
            true,
            |_| unreachable!("generator should not run"),
        ) else {
            panic!("zero max attempts should fail");
        };

        assert_eq!(error, AddressSearchError::MaxAttemptsExceeded(0));
    }

    #[test]
    fn finds_match_from_deterministic_generator() {
        let mnemonic = Bip39Mnemonic::parse(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap_or_else(|_| panic!("test mnemonic should parse"));
        let derived = derive_wallet_keys(&mnemonic, 0)
            .unwrap_or_else(|_| panic!("test wallet derivation should succeed"));
        let derived_address = encode_railgun_address(
            1,
            derived.master_public_key(),
            ChainScope::AllChains,
            derived.viewing_public_key(),
        )
        .unwrap_or_else(|_| panic!("test address encoding should succeed"));
        let candidate_targets = [
            "0zk1qy0000k0k4w2akdev8ju4z7yp4w4x0zz9ehxdqe9chsjuujeklwdtrv7j6fe3z53lug74ey6tjlpk2xlfdp2pnfnc4972qwpk9fvhafqtrv9ctnxgjhush3njwh",
            "0zk1qyduss9nnfyycfwt03fwds69c7z27rmmulcxsq3lvn0yhwjxfa7lnrv7j6fe3z53la7dxtysu5dtqp9lh6k6qeft3j5cvawwdq7zx6t9ltsncagyz06wk4n66nt",
            "0zk1qypste3j7z623g9h58a3tstj5gemj8um8ccnhsz4du7evyuajzy7frv7j6fe3z53llceke63aaj9n7s42ll44zlh604fh96ssa0hat208xwl9hqj3hhewetyj8c",
        ];
        let target_address = candidate_targets
            .into_iter()
            .map(address)
            .find(|target| derived_address.as_str() < target.as_str())
            .unwrap_or_else(|| {
                panic!("expected at least one target address greater than the derived address")
            });
        let phrases = Arc::new(Mutex::new(vec![
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_owned(),
        ]));
        let result = match search_lower_address_with_generator(
            AddressSearchOptions {
                target_addresses: vec![target_address.clone()],
                word_count: Bip39WordCount::Words12,
                index: 0,
                required_suffix: None,
                worker_count: 1,
                progress_every: 0,
                max_attempts: Some(1),
            },
            true,
            move |_| {
                let phrase = phrases
                    .lock()
                    .unwrap_or_else(|_| panic!("test phrase mutex should not poison"))
                    .pop()
                    .unwrap_or_else(|| panic!("test phrase should be available"));
                Bip39Mnemonic::parse(&phrase)
            },
        ) {
            Ok(result) => result,
            Err(error) => panic!("deterministic phrase should match: {error}"),
        };

        assert_eq!(result.index(), 0);
        assert_eq!(result.word_count(), 12);
        assert_eq!(result.attempts(), 1);
        assert_eq!(result.worker_count(), 1);
        assert_eq!(result.minimum_target_address(), &target_address);
        assert_eq!(result.derived_address(), &derived_address);
        assert_eq!(
            result.mnemonic(),
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        );
        assert!(result.derived_address().as_str().starts_with("0zk1"));
    }
}
