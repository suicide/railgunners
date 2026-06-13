use railgunners_core::{
    Bip39Error, Bip39Mnemonic, Bip39WordCount, SearchCandidateKeys, encode_railgun_address,
    encode_railgun_address_prefix_data, encode_shareable_viewing_key,
};
use railgunners_types::{ChainScope, RailgunAddress, ShareableViewingKeyData};
use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    thread,
};

use crate::workflows::{keys::pack_derived_spending_public_key, mnemonic::generate_mnemonic};

const ALL_CHAINS_ADDRESS_STEM: &str = "0zk1qy";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SearchSeedMode {
    Bip39,
    Raw,
}

impl SearchSeedMode {
    #[must_use]
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Bip39 => "bip39",
            Self::Raw => "raw",
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct AddressSearchOptions {
    pub(crate) lower_than_addresses: Vec<RailgunAddress>,
    pub(crate) leading_zeroes: Option<usize>,
    pub(crate) seed_mode: SearchSeedMode,
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
    seed_mode: SearchSeedMode,
    mnemonic: Option<String>,
    raw_seed_hex: Option<String>,
    index: u32,
    word_count: Option<usize>,
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
        seed_mode: SearchSeedMode,
        mnemonic: Option<String>,
        raw_seed_hex: Option<String>,
        index: u32,
        word_count: Option<usize>,
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
            seed_mode,
            mnemonic,
            raw_seed_hex,
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
    pub(crate) const fn seed_mode(&self) -> SearchSeedMode {
        self.seed_mode
    }

    #[must_use]
    pub(crate) fn mnemonic(&self) -> Option<&str> {
        self.mnemonic.as_deref()
    }

    #[must_use]
    pub(crate) fn raw_seed_hex(&self) -> Option<&str> {
        self.raw_seed_hex.as_deref()
    }

    #[must_use]
    pub(crate) const fn index(&self) -> u32 {
        self.index
    }

    #[must_use]
    pub(crate) const fn word_count(&self) -> Option<usize> {
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
    match options.seed_mode {
        SearchSeedMode::Bip39 => search_address_with_generator(options, json, generate_mnemonic),
        SearchSeedMode::Raw => search_address_with_seed_generator(options, json, generate_seed),
    }
    .map_err(|error| crate::error::CliError::command(error.to_string(), json))
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum SearchSecretMaterial {
    Bip39 { mnemonic: Bip39Mnemonic, phrase: String, word_count: usize },
    RawSeed { seed: [u8; 64] },
}

#[derive(Clone, Debug)]
struct GeneratedSearchCandidate {
    candidate: SearchCandidateKeys,
    secret_material: SearchSecretMaterial,
}

fn search_address_with_generator<F>(
    options: AddressSearchOptions,
    json: bool,
    generator: F,
) -> Result<AddressSearchMatch, AddressSearchError>
where
    F: Fn(Bip39WordCount) -> Result<Bip39Mnemonic, Bip39Error> + Send + Sync + 'static,
{
    search_address_with_candidate_generator(options, json, move |options| {
        let mnemonic = generator(options.word_count).map_err(AddressSearchError::Bip39)?;
        let phrase = mnemonic.phrase();
        let seed = mnemonic.seed(None);
        let candidate = railgunners_core::derive_search_keys_from_seed(&seed, options.index)
            .map_err(|error| AddressSearchError::KeyDerivation(error.to_string()))?;
        Ok(GeneratedSearchCandidate {
            candidate,
            secret_material: SearchSecretMaterial::Bip39 {
                mnemonic,
                phrase,
                word_count: options.word_count.as_usize(),
            },
        })
    })
}

fn search_address_with_seed_generator<F>(
    options: AddressSearchOptions,
    json: bool,
    generator: F,
) -> Result<AddressSearchMatch, AddressSearchError>
where
    F: Fn() -> Result<[u8; 64], String> + Send + Sync + 'static,
{
    search_address_with_candidate_generator(options, json, move |options| {
        let seed = generator().map_err(AddressSearchError::KeyDerivation)?;
        let candidate = railgunners_core::derive_search_keys_from_seed(&seed, options.index)
            .map_err(|error| AddressSearchError::KeyDerivation(error.to_string()))?;
        Ok(GeneratedSearchCandidate {
            candidate,
            secret_material: SearchSecretMaterial::RawSeed { seed },
        })
    })
}

fn search_address_with_candidate_generator<F>(
    options: AddressSearchOptions,
    json: bool,
    generator: F,
) -> Result<AddressSearchMatch, AddressSearchError>
where
    F: Fn(&AddressSearchOptions) -> Result<GeneratedSearchCandidate, AddressSearchError>
        + Send
        + Sync
        + 'static,
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
                Ok(*found)
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
    Found(Box<AddressSearchMatch>),
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
    F: Fn(&AddressSearchOptions) -> Result<GeneratedSearchCandidate, AddressSearchError>,
{
    while !stop.load(Ordering::Relaxed) {
        let attempt = attempts.fetch_add(1, Ordering::Relaxed) + 1;
        let should_report_progress =
            options.progress_every != 0 && attempt % options.progress_every == 0;
        if options.max_attempts.is_some_and(|max_attempts| attempt > max_attempts) {
            return;
        }

        let candidate = match generator(options) {
            Ok(candidate) => candidate,
            Err(error) => {
                send_worker_failure(sender, stop, error);
                return;
            }
        };
        let fast_stem_match = match matches_fast_stem_filters(&candidate.candidate, options) {
            Ok(matches) => matches,
            Err(error) => {
                send_worker_failure(sender, stop, error);
                return;
            }
        };
        if !fast_stem_match {
            if should_report_progress {
                let prefix = candidate_address_prefix(&candidate.candidate);
                report_progress_prefix(
                    worker_id,
                    attempt,
                    &prefix,
                    minimum_lower_than,
                    options,
                    json,
                );
            }
            continue;
        }
        let candidate_address = match encode_full_address(&candidate.candidate) {
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
                match pack_derived_spending_public_key(candidate.candidate.spending_public_key()) {
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
                &candidate.secret_material,
                &candidate.candidate,
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
            let _ = sender.send(WorkerMessage::Found(Box::new(result)));
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

fn report_progress_prefix(
    worker_id: usize,
    attempt: u64,
    candidate_prefix: &str,
    minimum_lower_than: Option<&RailgunAddress>,
    options: &AddressSearchOptions,
    json: bool,
) {
    if options.progress_every == 0 || attempt % options.progress_every != 0 || json {
        return;
    }

    if let Some(minimum_lower_than) = minimum_lower_than {
        eprintln!(
            "Attempts: {attempt} worker: {worker_id} currentAddressPrefix: {candidate_prefix} targetMinimum: {}",
            minimum_lower_than.as_str(),
        );
    } else {
        eprintln!(
            "Attempts: {attempt} worker: {worker_id} currentAddressPrefix: {candidate_prefix}",
        );
    }
}

fn candidate_address_prefix(candidate: &SearchCandidateKeys) -> String {
    let payload = encode_search_payload(candidate);
    encode_railgun_address_prefix_data(&payload, ALL_CHAINS_ADDRESS_STEM.len() + 12)
}

fn encode_search_payload(candidate: &SearchCandidateKeys) -> [u8; 73] {
    let mut payload = [0_u8; 73];
    payload[0] = 1;
    let master_bytes = candidate.master_public_key().value().to_bytes_be();
    let offset = 33 - master_bytes.len();
    payload[offset..33].copy_from_slice(&master_bytes);
    let network_id = railgunners_core::encode_network_id(ChainScope::AllChains)
        .unwrap_or_else(|_| panic!("all-chains network id should encode"));
    payload[33..41].copy_from_slice(network_id.as_bytes());
    payload
}

fn encode_full_address(
    candidate: &SearchCandidateKeys,
) -> Result<RailgunAddress, railgunners_core::AddressEncodingError> {
    let viewing_public_key =
        railgunners_core::derive_viewing_public_key(candidate.viewing_private_key());
    encode_railgun_address(
        1,
        candidate.master_public_key(),
        ChainScope::AllChains,
        &viewing_public_key,
    )
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
    candidate: &SearchCandidateKeys,
    options: &AddressSearchOptions,
) -> Result<bool, AddressSearchError> {
    let Some(prefix_length) = required_stem_prefix_length(options) else {
        return Ok(true);
    };

    let payload = encode_search_payload(candidate);
    let candidate_prefix = encode_railgun_address_prefix_data(&payload, prefix_length);
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
    secret_material: &SearchSecretMaterial,
    derived: &SearchCandidateKeys,
    packed_spending_public_key: railgunners_types::PackedSpendingPublicKey,
    options: &AddressSearchOptions,
    attempt: u64,
) -> Result<AddressSearchMatch, AddressSearchError> {
    let packed_spending_public_key_hex = hex::encode(packed_spending_public_key.as_bytes());
    let shareable_viewing_key = encode_shareable_viewing_key(&ShareableViewingKeyData::new(
        *derived.viewing_private_key(),
        packed_spending_public_key,
    ))
    .map_err(|error| AddressSearchError::ViewingKeyEncoding(error.to_string()))?;

    let (seed_mode, mnemonic, raw_seed_hex, word_count) = match secret_material {
        SearchSecretMaterial::Bip39 { phrase, word_count, .. } => {
            (SearchSeedMode::Bip39, Some(phrase.clone()), None, Some(*word_count))
        }
        SearchSecretMaterial::RawSeed { seed } => {
            (SearchSeedMode::Raw, None, Some(hex::encode(seed)), None)
        }
    };

    Ok(AddressSearchMatch::new(
        minimum_lower_than.cloned(),
        candidate_address,
        seed_mode,
        mnemonic,
        raw_seed_hex,
        options.index,
        word_count,
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

fn generate_seed() -> Result<[u8; 64], String> {
    let mut seed = [0_u8; 64];
    getrandom::fill(&mut seed).map_err(|error| format!("failed to generate raw seed: {error}"))?;
    Ok(seed)
}

#[cfg(test)]
mod tests {
    use super::{
        ALL_CHAINS_ADDRESS_STEM, AddressSearchError, AddressSearchMatch, AddressSearchOptions,
        SearchSeedMode, count_leading_zeroes, matches_fast_stem_filters, matches_stem_filters,
        search_address_with_generator, search_address_with_seed_generator,
    };
    use railgunners_core::{
        Bip39Mnemonic, Bip39WordCount, SearchCandidateKeys, derive_master_public_key,
        derive_nullifying_key, derive_spending_node, derive_spending_public_key,
        derive_viewing_node, derive_viewing_public_key, encode_railgun_address,
        spending_private_key_from_node, viewing_private_key_from_node,
    };
    use railgunners_types::ChainScope;
    use railgunners_types::RailgunAddress;
    use std::{
        hint::black_box,
        sync::{Arc, Mutex},
        time::Instant,
    };

    fn address(value: &str) -> RailgunAddress {
        RailgunAddress::parse(value).unwrap_or_else(|_| panic!("test address should parse"))
    }

    fn expected_address_for(
        mnemonic: &Bip39Mnemonic,
        index: u32,
    ) -> (SearchCandidateKeys, RailgunAddress) {
        let seed = mnemonic.seed(None);
        let candidate = railgunners_core::derive_search_keys_from_seed(&seed, index)
            .unwrap_or_else(|_| panic!("test search key derivation should succeed"));
        let viewing_public_key = derive_viewing_public_key(candidate.viewing_private_key());
        let address = encode_railgun_address(
            1,
            candidate.master_public_key(),
            ChainScope::AllChains,
            &viewing_public_key,
        )
        .unwrap_or_else(|_| panic!("test address encoding should succeed"));
        (candidate, address)
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
                seed_mode: SearchSeedMode::Bip39,
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

    fn deterministic_raw_seed_search_result(
        lower_than_addresses: Vec<RailgunAddress>,
        leading_zeroes: Option<usize>,
        prefix: Option<String>,
        suffix: Option<String>,
    ) -> AddressSearchMatch {
        let mnemonic = Bip39Mnemonic::parse(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap_or_else(|_| panic!("test mnemonic should parse"));
        let seed = mnemonic.seed(None);

        match search_address_with_seed_generator(
            AddressSearchOptions {
                lower_than_addresses,
                leading_zeroes,
                seed_mode: SearchSeedMode::Raw,
                word_count: Bip39WordCount::Words12,
                index: 0,
                prefix,
                suffix,
                worker_count: 1,
                progress_every: 0,
                max_attempts: Some(1),
            },
            true,
            move || Ok(seed),
        ) {
            Ok(result) => result,
            Err(error) => panic!("deterministic raw seed should match: {error}"),
        }
    }

    #[test]
    fn supports_prefix_only_search_without_lower_bound() {
        let mnemonic = Bip39Mnemonic::parse(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap_or_else(|_| panic!("test mnemonic should parse"));
        let (_, derived_address) = expected_address_for(&mnemonic, 0);
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
                seed_mode: SearchSeedMode::Bip39,
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
        let (_, derived_address) = expected_address_for(&mnemonic, 0);
        let target_address = candidate_target_greater_than(&derived_address);
        let result = deterministic_search_result(vec![target_address.clone()], None, None, None);

        assert_eq!(result.index(), 0);
        assert_eq!(result.seed_mode(), SearchSeedMode::Bip39);
        assert_eq!(result.word_count(), Some(12));
        assert_eq!(result.attempts(), 1);
        assert_eq!(result.worker_count(), 1);
        assert_eq!(result.minimum_lower_than_address(), Some(&target_address));
        assert_eq!(result.derived_address(), &derived_address);
        assert_eq!(
            result.mnemonic(),
            Some(
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            )
        );
        assert!(result.derived_address().as_str().starts_with("0zk1"));
    }

    #[test]
    fn finds_match_with_combined_prefix_and_suffix_filters() {
        let mnemonic = Bip39Mnemonic::parse(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap_or_else(|_| panic!("test mnemonic should parse"));
        let (_, derived_address) = expected_address_for(&mnemonic, 0);
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
        let (_, derived_address) = expected_address_for(&mnemonic, 0);
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
        let (_, derived_address) = expected_address_for(&mnemonic, 0);
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

    #[test]
    fn supports_raw_seed_search_without_mnemonic_output() {
        let result = deterministic_raw_seed_search_result(Vec::new(), Some(0), None, None);

        assert_eq!(result.seed_mode(), SearchSeedMode::Raw);
        assert_eq!(result.word_count(), None);
        assert_eq!(result.mnemonic(), None);
        assert!(result.raw_seed_hex().is_some());
    }

    fn full_address_matches_stem_filters(
        candidate: &SearchCandidateKeys,
        options: &AddressSearchOptions,
    ) -> bool {
        let viewing_public_key =
            railgunners_core::derive_viewing_public_key(candidate.viewing_private_key());
        let candidate_address = encode_railgun_address(
            1,
            candidate.master_public_key(),
            ChainScope::AllChains,
            &viewing_public_key,
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
                let seed = mnemonic.seed(None);
                railgunners_core::derive_search_keys_from_seed(&seed, index)
                    .unwrap_or_else(|_| panic!("benchmark search key derivation should succeed"))
            })
            .collect::<Vec<_>>();
        let options = AddressSearchOptions {
            lower_than_addresses: Vec::new(),
            leading_zeroes: Some(4),
            seed_mode: SearchSeedMode::Bip39,
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
            seed_mode: SearchSeedMode::Bip39,
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
                let seed = mnemonic.seed(None);
                let derived = railgunners_core::derive_search_keys_from_seed(&seed, *index)
                    .unwrap_or_else(|_| panic!("benchmark search key derivation should succeed"));
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
                let seed = mnemonic.seed(None);
                let derived = railgunners_core::derive_search_keys_from_seed(&seed, *index)
                    .unwrap_or_else(|_| panic!("benchmark search key derivation should succeed"));
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

    #[test]
    #[ignore = "benchmark"]
    fn bench_end_to_end_raw_seed_attempts() {
        const ITERATIONS: u32 = 2_048;

        let seeds = (0..ITERATIONS)
            .map(|index| {
                let mut seed = [0_u8; 64];
                seed[..4].copy_from_slice(&index.to_be_bytes());
                seed
            })
            .collect::<Vec<_>>();
        let options = AddressSearchOptions {
            lower_than_addresses: Vec::new(),
            leading_zeroes: Some(4),
            seed_mode: SearchSeedMode::Raw,
            word_count: Bip39WordCount::Words12,
            index: 0,
            prefix: Some("0000".to_owned()),
            suffix: None,
            worker_count: 1,
            progress_every: 0,
            max_attempts: None,
        };

        let start = Instant::now();
        let match_count = seeds
            .iter()
            .filter(|seed| {
                let derived = railgunners_core::derive_search_keys_from_seed(&seed[..], 0)
                    .unwrap_or_else(|_| panic!("raw seed derivation should succeed"));
                black_box(
                    matches_fast_stem_filters(&derived, &options)
                        .unwrap_or_else(|_| panic!("fast stem filtering should succeed")),
                )
            })
            .count();
        let elapsed = start.elapsed();

        eprintln!(
            "raw seed end-to-end: {:?} ({:.0} attempts/s) over {} attempts, matches: {}",
            elapsed,
            f64::from(ITERATIONS) / elapsed.as_secs_f64(),
            ITERATIONS,
            match_count,
        );
    }

    #[test]
    #[ignore = "benchmark"]
    #[allow(clippy::too_many_lines)]
    fn bench_derivation_stage_breakdown() {
        const ITERATIONS: u32 = 2_048;

        let mnemonic = Bip39Mnemonic::parse(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        )
        .unwrap_or_else(|_| panic!("test mnemonic should parse"));

        let seed_start = Instant::now();
        for _ in 0..ITERATIONS {
            black_box(mnemonic.seed(None));
        }
        let seed_elapsed = seed_start.elapsed();

        let seed = mnemonic.seed(None);

        let spending_node_start = Instant::now();
        let spending_nodes = (0..ITERATIONS)
            .map(|index| {
                black_box(
                    derive_spending_node(&seed, index)
                        .unwrap_or_else(|_| panic!("spending node derivation should succeed")),
                )
            })
            .collect::<Vec<_>>();
        let spending_node_elapsed = spending_node_start.elapsed();

        let viewing_node_start = Instant::now();
        let viewing_nodes = (0..ITERATIONS)
            .map(|index| {
                black_box(
                    derive_viewing_node(&seed, index)
                        .unwrap_or_else(|_| panic!("viewing node derivation should succeed")),
                )
            })
            .collect::<Vec<_>>();
        let viewing_node_elapsed = viewing_node_start.elapsed();

        let spending_public_start = Instant::now();
        let spending_public_keys =
            spending_nodes
                .iter()
                .map(|node| {
                    let private_key = spending_private_key_from_node(node);
                    black_box(derive_spending_public_key(&private_key).unwrap_or_else(|_| {
                        panic!("spending public key derivation should succeed")
                    }))
                })
                .collect::<Vec<_>>();
        let spending_public_elapsed = spending_public_start.elapsed();

        let viewing_public_start = Instant::now();
        let viewing_private_keys =
            viewing_nodes.iter().map(viewing_private_key_from_node).collect::<Vec<_>>();
        let viewing_public_keys = viewing_private_keys
            .iter()
            .map(|private_key| black_box(derive_viewing_public_key(private_key)))
            .collect::<Vec<_>>();
        let viewing_public_elapsed = viewing_public_start.elapsed();

        let nullifying_start = Instant::now();
        let nullifying_keys = viewing_private_keys
            .iter()
            .map(|private_key| {
                black_box(
                    derive_nullifying_key(private_key)
                        .unwrap_or_else(|_| panic!("nullifying key derivation should succeed")),
                )
            })
            .collect::<Vec<_>>();
        let nullifying_elapsed = nullifying_start.elapsed();

        let master_public_start = Instant::now();
        let master_public_keys = spending_public_keys
            .iter()
            .zip(&nullifying_keys)
            .map(|(spending_public_key, nullifying_key)| {
                black_box(
                    derive_master_public_key(spending_public_key, nullifying_key)
                        .unwrap_or_else(|_| panic!("master public key derivation should succeed")),
                )
            })
            .collect::<Vec<_>>();
        let master_public_elapsed = master_public_start.elapsed();

        black_box(viewing_public_keys);
        black_box(master_public_keys);

        let total_elapsed = seed_elapsed
            + spending_node_elapsed
            + viewing_node_elapsed
            + spending_public_elapsed
            + viewing_public_elapsed
            + nullifying_elapsed
            + master_public_elapsed;

        eprintln!(
            concat!(
                "seed: {:?} ({:.0} ops/s), ",
                "spending node: {:?} ({:.0} ops/s), ",
                "viewing node: {:?} ({:.0} ops/s), ",
                "spending public: {:?} ({:.0} ops/s), ",
                "viewing public: {:?} ({:.0} ops/s), ",
                "nullifying: {:?} ({:.0} ops/s), ",
                "master public: {:?} ({:.0} ops/s), ",
                "summed total: {:?} ({:.0} attempts/s equivalent)"
            ),
            seed_elapsed,
            f64::from(ITERATIONS) / seed_elapsed.as_secs_f64(),
            spending_node_elapsed,
            f64::from(ITERATIONS) / spending_node_elapsed.as_secs_f64(),
            viewing_node_elapsed,
            f64::from(ITERATIONS) / viewing_node_elapsed.as_secs_f64(),
            spending_public_elapsed,
            f64::from(ITERATIONS) / spending_public_elapsed.as_secs_f64(),
            viewing_public_elapsed,
            f64::from(ITERATIONS) / viewing_public_elapsed.as_secs_f64(),
            nullifying_elapsed,
            f64::from(ITERATIONS) / nullifying_elapsed.as_secs_f64(),
            master_public_elapsed,
            f64::from(ITERATIONS) / master_public_elapsed.as_secs_f64(),
            total_elapsed,
            f64::from(ITERATIONS) / total_elapsed.as_secs_f64(),
        );
    }
}
