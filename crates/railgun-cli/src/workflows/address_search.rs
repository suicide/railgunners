use railgun_core::{
    Bip39Error, Bip39Mnemonic, Bip39WordCount, encode_railgun_address,
    encode_railgun_address_prefix, encode_shareable_viewing_key,
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

const ALL_CHAINS_ADDRESS_STEM: &str = "0zk1qy";

#[derive(Clone, Debug)]
pub(crate) struct AddressSearchOptions {
    pub(crate) lower_than_addresses: Vec<RailgunAddress>,
    pub(crate) leading_zeroes: Option<usize>,
    pub(crate) word_count: Bip39WordCount,
    pub(crate) index: u32,
    pub(crate) prefix: Option<String>,
    pub(crate) suffix: Option<String>,
    pub(crate) worker_count: usize,
    pub(crate) progress_every: u64,
    pub(crate) max_attempts: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AddressSearchMatch {
    minimum_lower_than_address: Option<RailgunAddress>,
    derived_address: RailgunAddress,
    mnemonic: String,
    index: u32,
    word_count: usize,
    prefix: Option<String>,
    leading_zeroes: Option<usize>,
    suffix: Option<String>,
    viewing_private_key_hex: String,
    packed_spending_public_key_hex: String,
    shareable_viewing_key: String,
    attempts: u64,
    worker_count: usize,
}

impl AddressSearchMatch {
    #[allow(clippy::too_many_arguments)]
    fn new(
        minimum_lower_than_address: Option<RailgunAddress>,
        derived_address: RailgunAddress,
        mnemonic: String,
        index: u32,
        word_count: usize,
        prefix: Option<String>,
        leading_zeroes: Option<usize>,
        suffix: Option<String>,
        viewing_private_key_hex: String,
        packed_spending_public_key_hex: String,
        shareable_viewing_key: String,
        attempts: u64,
        worker_count: usize,
    ) -> Self {
        Self {
            minimum_lower_than_address,
            derived_address,
            mnemonic,
            index,
            word_count,
            prefix,
            leading_zeroes,
            suffix,
            viewing_private_key_hex,
            packed_spending_public_key_hex,
            shareable_viewing_key,
            attempts,
            worker_count,
        }
    }

    #[must_use]
    pub(crate) fn minimum_lower_than_address(&self) -> Option<&RailgunAddress> {
        self.minimum_lower_than_address.as_ref()
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
    pub(crate) fn prefix(&self) -> Option<&str> {
        self.prefix.as_deref()
    }

    #[must_use]
    pub(crate) const fn leading_zeroes(&self) -> Option<usize> {
        self.leading_zeroes
    }

    #[must_use]
    pub(crate) fn suffix(&self) -> Option<&str> {
        self.suffix.as_deref()
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

pub(crate) fn search_address(
    options: AddressSearchOptions,
    json: bool,
) -> Result<AddressSearchMatch, crate::error::CliError> {
    search_address_with_generator(options, json, generate_mnemonic)
        .map_err(|error| crate::error::CliError::command(error.to_string(), json))
}

fn search_address_with_generator<F>(
    options: AddressSearchOptions,
    json: bool,
    generator: F,
) -> Result<AddressSearchMatch, AddressSearchError>
where
    F: Fn(Bip39WordCount) -> Result<Bip39Mnemonic, Bip39Error> + Send + Sync + 'static,
{
    let minimum_lower_than = options
        .lower_than_addresses
        .iter()
        .min_by(|left, right| left.as_str().cmp(right.as_str()))
        .cloned();

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
            let minimum_lower_than = minimum_lower_than.clone();
            let options = Arc::clone(&options);
            let generator = Arc::clone(&generator);
            let stop = Arc::clone(&stop);
            let attempts = Arc::clone(&attempts);

            scope.spawn(move || {
                worker_loop(
                    worker_id,
                    minimum_lower_than.as_ref(),
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
    minimum_lower_than: Option<&RailgunAddress>,
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
        let should_report_progress =
            options.progress_every != 0 && attempt % options.progress_every == 0;
        if options.max_attempts.is_some_and(|max_attempts| attempt > max_attempts) {
            return;
        }

        let mnemonic = match generator(options.word_count) {
            Ok(mnemonic) => mnemonic,
            Err(error) => {
                send_worker_failure(sender, stop, AddressSearchError::Bip39(error));
                return;
            }
        };

        let derived = match derive_wallet_keys(&mnemonic, options.index) {
            Ok(derived) => derived,
            Err(error) => {
                send_worker_failure(
                    sender,
                    stop,
                    AddressSearchError::KeyDerivation(error.to_string()),
                );
                return;
            }
        };
        let fast_stem_match = match matches_fast_stem_filters(&derived, options) {
            Ok(matches) => matches,
            Err(error) => {
                send_worker_failure(sender, stop, error);
                return;
            }
        };
        if !fast_stem_match {
            if should_report_progress {
                let candidate_address = match encode_railgun_address(
                    1,
                    derived.master_public_key(),
                    ChainScope::AllChains,
                    derived.viewing_public_key(),
                ) {
                    Ok(address) => address,
                    Err(error) => {
                        send_worker_failure(
                            sender,
                            stop,
                            AddressSearchError::AddressEncoding(error.to_string()),
                        );
                        return;
                    }
                };
                report_progress(
                    worker_id,
                    attempt,
                    &candidate_address,
                    minimum_lower_than,
                    options,
                    json,
                );
            }
            continue;
        }
        let candidate_address = match encode_railgun_address(
            1,
            derived.master_public_key(),
            ChainScope::AllChains,
            derived.viewing_public_key(),
        ) {
            Ok(address) => address,
            Err(error) => {
                send_worker_failure(
                    sender,
                    stop,
                    AddressSearchError::AddressEncoding(error.to_string()),
                );
                return;
            }
        };

        report_progress(worker_id, attempt, &candidate_address, minimum_lower_than, options, json);

        if matches_search_filters(&candidate_address, minimum_lower_than, options) {
            let packed_spending_public_key =
                match pack_derived_spending_public_key(derived.spending_public_key()) {
                    Ok(key) => key,
                    Err(error) => {
                        send_worker_failure(
                            sender,
                            stop,
                            AddressSearchError::ViewingKeyEncoding(error.to_string()),
                        );
                        return;
                    }
                };
            let result = match build_search_match(
                minimum_lower_than,
                candidate_address,
                mnemonic.phrase(),
                &derived,
                packed_spending_public_key,
                options,
                attempt,
            ) {
                Ok(result) => result,
                Err(error) => {
                    send_worker_failure(sender, stop, error);
                    return;
                }
            };
            stop.store(true, Ordering::Relaxed);
            let _ = sender.send(WorkerMessage::Found(result));
            return;
        }
    }
}

fn send_worker_failure(
    sender: &mpsc::Sender<WorkerMessage>,
    stop: &AtomicBool,
    error: AddressSearchError,
) {
    let _ = sender.send(WorkerMessage::Failed(error));
    stop.store(true, Ordering::Relaxed);
}

fn report_progress(
    worker_id: usize,
    attempt: u64,
    candidate_address: &RailgunAddress,
    minimum_lower_than: Option<&RailgunAddress>,
    options: &AddressSearchOptions,
    json: bool,
) {
    if options.progress_every == 0 || attempt % options.progress_every != 0 || json {
        return;
    }

    if let Some(minimum_lower_than) = minimum_lower_than {
        eprintln!(
            "Attempts: {attempt} worker: {worker_id} currentAddress: {} targetMinimum: {}",
            candidate_address.as_str(),
            minimum_lower_than.as_str(),
        );
    } else {
        eprintln!(
            "Attempts: {attempt} worker: {worker_id} currentAddress: {}",
            candidate_address.as_str(),
        );
    }
}

fn matches_search_filters(
    candidate_address: &RailgunAddress,
    minimum_lower_than: Option<&RailgunAddress>,
    options: &AddressSearchOptions,
) -> bool {
    let Some(candidate_suffix) = candidate_address.as_str().strip_prefix(ALL_CHAINS_ADDRESS_STEM)
    else {
        return false;
    };

    minimum_lower_than
        .is_none_or(|minimum_lower_than| candidate_address.as_str() < minimum_lower_than.as_str())
        && matches_stem_filters(candidate_suffix, options)
        && options
            .suffix
            .as_deref()
            .is_none_or(|suffix| candidate_address.as_str().ends_with(suffix))
}

fn matches_fast_stem_filters(
    derived: &crate::workflows::keys::DerivedWalletKeys,
    options: &AddressSearchOptions,
) -> Result<bool, AddressSearchError> {
    let Some(prefix_length) = required_stem_prefix_length(options) else {
        return Ok(true);
    };

    let candidate_prefix = encode_railgun_address_prefix(
        1,
        derived.master_public_key(),
        ChainScope::AllChains,
        derived.viewing_public_key(),
        prefix_length,
    )
    .map_err(|error| AddressSearchError::AddressEncoding(error.to_string()))?;
    let Some(candidate_suffix) = candidate_prefix.as_str().strip_prefix(ALL_CHAINS_ADDRESS_STEM)
    else {
        return Err(AddressSearchError::AddressEncoding(
            "all-chains address must use the 0zk1qy stem".to_owned(),
        ));
    };
    Ok(matches_stem_filters(candidate_suffix, options))
}

fn required_stem_prefix_length(options: &AddressSearchOptions) -> Option<usize> {
    let stem_relative_length =
        options.leading_zeroes.unwrap_or(0).max(options.prefix.as_ref().map_or(0, String::len));
    (stem_relative_length > 0).then_some(ALL_CHAINS_ADDRESS_STEM.len() + stem_relative_length)
}

fn matches_stem_filters(candidate_suffix: &str, options: &AddressSearchOptions) -> bool {
    options
        .leading_zeroes
        .is_none_or(|leading_zeroes| count_leading_zeroes(candidate_suffix) >= leading_zeroes)
        && options.prefix.as_deref().is_none_or(|prefix| candidate_suffix.starts_with(prefix))
}

fn count_leading_zeroes(value: &str) -> usize {
    value.bytes().take_while(|byte| *byte == b'0').count()
}

fn build_search_match(
    minimum_lower_than: Option<&RailgunAddress>,
    candidate_address: RailgunAddress,
    phrase: String,
    derived: &crate::workflows::keys::DerivedWalletKeys,
    packed_spending_public_key: railgun_types::PackedSpendingPublicKey,
    options: &AddressSearchOptions,
    attempt: u64,
) -> Result<AddressSearchMatch, AddressSearchError> {
    let packed_spending_public_key_hex = hex::encode(packed_spending_public_key.as_bytes());
    let shareable_viewing_key = encode_shareable_viewing_key(&ShareableViewingKeyData::new(
        *derived.viewing_private_key(),
        packed_spending_public_key,
    ))
    .map_err(|error| AddressSearchError::ViewingKeyEncoding(error.to_string()))?;

    Ok(AddressSearchMatch::new(
        minimum_lower_than.cloned(),
        candidate_address,
        phrase,
        options.index,
        options.word_count.as_usize(),
        options.prefix.clone(),
        options.leading_zeroes,
        options.suffix.clone(),
        hex::encode(derived.viewing_private_key().as_bytes()),
        packed_spending_public_key_hex,
        shareable_viewing_key,
        attempt,
        options.worker_count,
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        ALL_CHAINS_ADDRESS_STEM, AddressSearchError, AddressSearchMatch, AddressSearchOptions,
        count_leading_zeroes, matches_fast_stem_filters, matches_stem_filters,
        search_address_with_generator,
    };
    use crate::workflows::keys::derive_wallet_keys;
    use railgun_core::{Bip39Mnemonic, Bip39WordCount, encode_railgun_address};
    use railgun_types::ChainScope;
    use railgun_types::RailgunAddress;
    use std::{
        hint::black_box,
        sync::{Arc, Mutex},
        time::Instant,
    };

    fn address(value: &str) -> RailgunAddress {
        RailgunAddress::parse(value).unwrap_or_else(|_| panic!("test address should parse"))
    }

    fn candidate_target_greater_than(derived_address: &RailgunAddress) -> RailgunAddress {
        [
            "0zk1qy0000k0k4w2akdev8ju4z7yp4w4x0zz9ehxdqe9chsjuujeklwdtrv7j6fe3z53lug74ey6tjlpk2xlfdp2pnfnc4972qwpk9fvhafqtrv9ctnxgjhush3njwh",
            "0zk1qyduss9nnfyycfwt03fwds69c7z27rmmulcxsq3lvn0yhwjxfa7lnrv7j6fe3z53la7dxtysu5dtqp9lh6k6qeft3j5cvawwdq7zx6t9ltsncagyz06wk4n66nt",
            "0zk1qypste3j7z623g9h58a3tstj5gemj8um8ccnhsz4du7evyuajzy7frv7j6fe3z53llceke63aaj9n7s42ll44zlh604fh96ssa0hat208xwl9hqj3hhewetyj8c",
        ]
        .into_iter()
        .map(address)
        .find(|target| derived_address.as_str() < target.as_str())
        .unwrap_or_else(|| panic!("expected at least one target address greater than the derived address"))
    }

    fn deterministic_search_result(
        lower_than_addresses: Vec<RailgunAddress>,
        leading_zeroes: Option<usize>,
        prefix: Option<String>,
        suffix: Option<String>,
    ) -> AddressSearchMatch {
        let phrases = Arc::new(Mutex::new(vec![
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
                .to_owned(),
        ]));

        match search_address_with_generator(
            AddressSearchOptions {
                lower_than_addresses,
                leading_zeroes,
                word_count: Bip39WordCount::Words12,
                index: 0,
                prefix,
                suffix,
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
        }
    }

    #[test]
    fn supports_prefix_only_search_without_lower_bound() {
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
        let prefix = derived_address
            .as_str()
            .strip_prefix(ALL_CHAINS_ADDRESS_STEM)
            .unwrap_or_else(|| panic!("derived address should use the all-chains stem"))
            .chars()
            .take(4)
            .collect::<String>();

        let result = deterministic_search_result(Vec::new(), None, Some(prefix.clone()), None);

        assert_eq!(result.minimum_lower_than_address(), None);
        assert_eq!(result.prefix(), Some(prefix.as_str()));
        assert_eq!(result.derived_address(), &derived_address);
    }

    #[test]
    fn respects_zero_max_attempts() {
        let Err(error) = search_address_with_generator(
            AddressSearchOptions {
                lower_than_addresses: vec![address(
                    "0zk1qyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqunpd9kxwatwqyqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqhshkca",
                )],
                leading_zeroes: None,
                word_count: Bip39WordCount::Words12,
                index: 0,
                prefix: None,
                suffix: None,
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
        let target_address = candidate_target_greater_than(&derived_address);
        let result = deterministic_search_result(vec![target_address.clone()], None, None, None);

        assert_eq!(result.index(), 0);
        assert_eq!(result.word_count(), 12);
        assert_eq!(result.attempts(), 1);
        assert_eq!(result.worker_count(), 1);
        assert_eq!(result.minimum_lower_than_address(), Some(&target_address));
        assert_eq!(result.derived_address(), &derived_address);
        assert_eq!(
            result.mnemonic(),
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        );
        assert!(result.derived_address().as_str().starts_with("0zk1"));
    }

    #[test]
    fn finds_match_with_combined_prefix_and_suffix_filters() {
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
        let prefix = derived_address
            .as_str()
            .strip_prefix(ALL_CHAINS_ADDRESS_STEM)
            .unwrap_or_else(|| panic!("derived address should use the all-chains stem"))
            .chars()
            .take(4)
            .collect::<String>();
        let suffix = derived_address.as_str()[derived_address.as_str().len() - 4..].to_owned();
        let target_address = candidate_target_greater_than(&derived_address);
        let result = deterministic_search_result(
            vec![target_address.clone()],
            None,
            Some(prefix.clone()),
            Some(suffix.clone()),
        );

        assert_eq!(result.minimum_lower_than_address(), Some(&target_address));
        assert_eq!(result.prefix(), Some(prefix.as_str()));
        assert_eq!(result.suffix(), Some(suffix.as_str()));
    }

    #[test]
    fn supports_suffix_only_search_without_lower_bound() {
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
        let suffix = derived_address.as_str()[derived_address.as_str().len() - 4..].to_owned();

        let result = deterministic_search_result(Vec::new(), None, None, Some(suffix.clone()));

        assert_eq!(result.minimum_lower_than_address(), None);
        assert_eq!(result.suffix(), Some(suffix.as_str()));
        assert_eq!(result.derived_address(), &derived_address);
    }

    #[test]
    fn supports_leading_zeroes_only_search_without_lower_bound() {
        let result = deterministic_search_result(Vec::new(), Some(0), None, None);

        assert_eq!(result.minimum_lower_than_address(), None);
        assert_eq!(result.leading_zeroes(), Some(0));
    }

    #[test]
    fn finds_match_with_combined_leading_zeroes_and_prefix_filters() {
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
        let stem_suffix = derived_address
            .as_str()
            .strip_prefix(ALL_CHAINS_ADDRESS_STEM)
            .unwrap_or_else(|| panic!("derived address should use the all-chains stem"));
        let leading_zeroes = count_leading_zeroes(stem_suffix);
        let prefix = stem_suffix.chars().take(leading_zeroes + 2).collect::<String>();

        let result = deterministic_search_result(
            Vec::new(),
            Some(leading_zeroes),
            Some(prefix.clone()),
            None,
        );

        assert_eq!(result.leading_zeroes(), Some(leading_zeroes));
        assert_eq!(result.prefix(), Some(prefix.as_str()));
    }

    fn full_address_matches_stem_filters(
        derived: &crate::workflows::keys::DerivedWalletKeys,
        options: &AddressSearchOptions,
    ) -> bool {
        let candidate_address = encode_railgun_address(
            1,
            derived.master_public_key(),
            ChainScope::AllChains,
            derived.viewing_public_key(),
        )
        .unwrap_or_else(|_| panic!("benchmark address encoding should succeed"));
        let candidate_suffix = candidate_address
            .as_str()
            .strip_prefix(ALL_CHAINS_ADDRESS_STEM)
            .unwrap_or_else(|| panic!("benchmark address should use the all-chains stem"));
        matches_stem_filters(candidate_suffix, options)
    }

    #[test]
    #[ignore = "benchmark"]
    fn bench_fast_stem_filters_against_full_address_filtering() {
        const ITERATIONS: u32 = 2_048;

        let mnemonic = Bip39Mnemonic::parse(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap_or_else(|_| panic!("test mnemonic should parse"));
        let derived_keys = (0..ITERATIONS)
            .map(|index| {
                derive_wallet_keys(&mnemonic, index)
                    .unwrap_or_else(|_| panic!("benchmark wallet derivation should succeed"))
            })
            .collect::<Vec<_>>();
        let options = AddressSearchOptions {
            lower_than_addresses: Vec::new(),
            leading_zeroes: Some(4),
            word_count: Bip39WordCount::Words12,
            index: 0,
            prefix: Some("0000".to_owned()),
            suffix: None,
            worker_count: 1,
            progress_every: 0,
            max_attempts: None,
        };

        let fast_start = Instant::now();
        let fast_match_count = derived_keys
            .iter()
            .filter(|derived| {
                black_box(
                    matches_fast_stem_filters(derived, &options)
                        .unwrap_or_else(|_| panic!("fast stem filtering should succeed")),
                )
            })
            .count();
        let fast_elapsed = fast_start.elapsed();

        let full_start = Instant::now();
        let full_match_count = derived_keys
            .iter()
            .filter(|derived| black_box(full_address_matches_stem_filters(derived, &options)))
            .count();
        let full_elapsed = full_start.elapsed();

        assert_eq!(fast_match_count, full_match_count);
        eprintln!(
            "fast stem filter: {:?}, full address filter: {:?}, speedup: {:.2}x over {} candidates",
            fast_elapsed,
            full_elapsed,
            full_elapsed.as_secs_f64() / fast_elapsed.as_secs_f64(),
            ITERATIONS,
        );
    }

    #[test]
    #[ignore = "benchmark"]
    fn bench_end_to_end_derive_and_filter_attempts() {
        const ITERATIONS: u32 = 2_048;

        let mnemonic = Bip39Mnemonic::parse(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap_or_else(|_| panic!("test mnemonic should parse"));
        let options = AddressSearchOptions {
            lower_than_addresses: Vec::new(),
            leading_zeroes: Some(4),
            word_count: Bip39WordCount::Words12,
            index: 0,
            prefix: Some("0000".to_owned()),
            suffix: None,
            worker_count: 1,
            progress_every: 0,
            max_attempts: None,
        };

        let fast_start = Instant::now();
        let fast_match_count = (0..ITERATIONS)
            .filter(|index| {
                let derived = derive_wallet_keys(&mnemonic, *index)
                    .unwrap_or_else(|_| panic!("benchmark wallet derivation should succeed"));
                black_box(
                    matches_fast_stem_filters(&derived, &options)
                        .unwrap_or_else(|_| panic!("fast stem filtering should succeed")),
                )
            })
            .count();
        let fast_elapsed = fast_start.elapsed();

        let full_start = Instant::now();
        let full_match_count = (0..ITERATIONS)
            .filter(|index| {
                let derived = derive_wallet_keys(&mnemonic, *index)
                    .unwrap_or_else(|_| panic!("benchmark wallet derivation should succeed"));
                black_box(full_address_matches_stem_filters(&derived, &options))
            })
            .count();
        let full_elapsed = full_start.elapsed();

        assert_eq!(fast_match_count, full_match_count);
        eprintln!(
            "end-to-end fast path: {:?} ({:.0} attempts/s), full path: {:?} ({:.0} attempts/s), speedup: {:.2}x over {} attempts",
            fast_elapsed,
            f64::from(ITERATIONS) / fast_elapsed.as_secs_f64(),
            full_elapsed,
            f64::from(ITERATIONS) / full_elapsed.as_secs_f64(),
            full_elapsed.as_secs_f64() / fast_elapsed.as_secs_f64(),
            ITERATIONS,
        );
    }
}
