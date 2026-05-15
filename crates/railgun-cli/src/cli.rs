use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "railguncli")]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Subcommand, Debug)]
pub(crate) enum Command {
    /// Show the workspace version.
    Version,
    /// Describe the current scaffold.
    ScaffoldInfo,
    /// Encode, decode, and validate 0zk addresses.
    #[command(subcommand)]
    Address(AddressCommand),
    /// Run mnemonic-related offline workflows.
    #[command(subcommand)]
    Mnemonic(MnemonicCommand),
    /// Derive and inspect Railgun keys.
    #[command(subcommand)]
    Keys(KeysCommand),
    /// Inspect and verify local proving artifacts.
    #[command(subcommand)]
    Artifacts(ArtifactsCommand),
    /// Create and inspect shareable viewing keys.
    #[command(subcommand)]
    ViewingKey(ViewingKeyCommand),
}

#[derive(Subcommand, Debug)]
pub(crate) enum AddressCommand {
    /// Encode a canonical 0zk address.
    Encode {
        /// Address version. Defaults to 1.
        #[arg(long, default_value_t = 1)]
        version: u8,
        /// The 32-byte master public key in hex.
        #[arg(long = "master-public-key")]
        master_public_key: String,
        /// Optional chain type override. Defaults to all-chains.
        #[arg(long = "chain-type")]
        chain_type: Option<u8>,
        /// Optional chain id override. Defaults to all-chains.
        #[arg(long = "chain-id")]
        chain_id: Option<u64>,
        /// The 32-byte viewing public key in hex.
        #[arg(long = "viewing-public-key")]
        viewing_public_key: String,
        /// Emit stable machine-readable output.
        #[arg(long)]
        json: bool,
    },
    /// Decode a canonical 0zk address.
    Decode {
        /// The encoded 0zk address.
        #[arg(long)]
        address: String,
        /// Emit stable machine-readable output.
        #[arg(long)]
        json: bool,
    },
    /// Validate a canonical 0zk address.
    Validate {
        /// The encoded 0zk address.
        #[arg(long)]
        address: String,
        /// Emit stable machine-readable output.
        #[arg(long)]
        json: bool,
    },
    /// Search for an all-chains index-0 0zk address matching optional filters.
    Search {
        /// Optional lower bounds. When provided, the search matches addresses smaller than the minimum.
        #[arg(long = "lower-than")]
        lower_than_addresses: Vec<String>,
        /// Optional minimum number of literal `0` characters immediately after the all-chains `0zk1qy` stem.
        #[arg(long = "leading-zeroes")]
        leading_zeroes: Option<usize>,
        /// Number of BIP-39 words to generate.
        #[arg(long = "word-count", default_value_t = 12)]
        word_count: usize,
        /// The canonical Railgun wallet index.
        #[arg(long, default_value_t = 0)]
        index: u32,
        /// Optional required prefix fragment immediately after the all-chains `0zk1qy` stem.
        #[arg(long = "prefix")]
        prefix: Option<String>,
        /// Optional required suffix fragment at the end of the address.
        #[arg(long = "suffix")]
        suffix: Option<String>,
        /// Number of worker threads to run concurrently.
        #[arg(long)]
        jobs: Option<usize>,
        /// Emit progress every N attempts on stderr. Defaults to 0 for no progress output.
        #[arg(long = "progress-every", default_value_t = 0)]
        progress_every: u64,
        /// Optional global attempt cap across all workers.
        #[arg(long = "max-attempts")]
        max_attempts: Option<u64>,
        /// Explicitly allow secret-bearing output.
        #[arg(long)]
        show_secrets: bool,
        /// Emit stable machine-readable output.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
pub(crate) enum MnemonicCommand {
    /// Generate a new BIP-39 mnemonic.
    Generate {
        /// Number of BIP-39 words to generate.
        #[arg(long, default_value_t = 12)]
        words: usize,
        /// Emit stable machine-readable output.
        #[arg(long)]
        json: bool,
    },
    /// Validate a BIP-39 mnemonic.
    Validate {
        /// The mnemonic phrase to validate.
        #[arg(long)]
        mnemonic: String,
        /// Emit stable machine-readable output.
        #[arg(long)]
        json: bool,
    },
    /// Export the 64-byte BIP-39 seed as lowercase hex.
    Seed {
        /// The mnemonic phrase to derive from.
        #[arg(long)]
        mnemonic: String,
        /// Optional BIP-39 password.
        #[arg(long)]
        password: Option<String>,
        /// Explicitly allow secret-bearing output.
        #[arg(long)]
        show_secrets: bool,
        /// Emit stable machine-readable output.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
pub(crate) enum KeysCommand {
    /// Derive canonical Railgun keys from a mnemonic and wallet index.
    Derive {
        /// The mnemonic phrase to derive from.
        #[arg(long)]
        mnemonic: String,
        /// The canonical Railgun wallet index.
        #[arg(long, default_value_t = 0)]
        index: u32,
        /// Explicitly allow secret-bearing output.
        #[arg(long)]
        show_secrets: bool,
        /// Emit stable machine-readable output.
        #[arg(long)]
        json: bool,
    },
    /// Inspect a viewing private key.
    InspectViewingPrivate {
        /// The 32-byte viewing private key in hex.
        #[arg(long = "private-key")]
        private_key: String,
        /// Emit stable machine-readable output.
        #[arg(long)]
        json: bool,
    },
    /// Inspect a spending private key.
    InspectSpendingPrivate {
        /// The 32-byte spending private key in hex.
        #[arg(long = "private-key")]
        private_key: String,
        /// Emit stable machine-readable output.
        #[arg(long)]
        json: bool,
    },
    /// Inspect master-public-key inputs.
    InspectMasterPublic {
        /// The spending public key x coordinate as unsigned decimal.
        #[arg(long = "spending-public-key-x")]
        spending_public_key_x: String,
        /// The spending public key y coordinate as unsigned decimal.
        #[arg(long = "spending-public-key-y")]
        spending_public_key_y: String,
        /// The nullifying key as unsigned decimal.
        #[arg(long = "nullifying-key")]
        nullifying_key: String,
        /// Emit stable machine-readable output.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
pub(crate) enum ArtifactsCommand {
    /// Verify local artifacts against the canonical SHA-256 catalog.
    Verify {
        /// Canonical variant string such as `01x01` or `POI_3x3`.
        #[arg(long)]
        variant: String,
        /// Local path to the decompressed zkey artifact.
        #[arg(long)]
        zkey: String,
        /// Optional local path to the decompressed wasm artifact.
        #[arg(long)]
        wasm: Option<String>,
        /// Optional local path to the decompressed dat artifact.
        #[arg(long)]
        dat: Option<String>,
        /// Emit stable machine-readable output.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
pub(crate) enum ViewingKeyCommand {
    /// Encode a shareable viewing key from view-only material.
    Encode {
        /// The 32-byte viewing private key in hex.
        #[arg(long = "viewing-private-key")]
        viewing_private_key: String,
        /// The packed 32-byte spending public key in hex.
        #[arg(long = "packed-spending-public-key")]
        packed_spending_public_key: String,
        /// Explicitly allow secret-bearing output.
        #[arg(long)]
        show_secrets: bool,
        /// Emit stable machine-readable output.
        #[arg(long)]
        json: bool,
    },
    /// Decode and inspect a shareable viewing key.
    Decode {
        /// Shareable viewing key hex payload.
        #[arg(long = "shareable-viewing-key")]
        shareable_viewing_key: String,
        /// Optional chain type for address derivation. Defaults to all-chains.
        #[arg(long = "chain-type")]
        chain_type: Option<u8>,
        /// Optional chain id for address derivation. Defaults to all-chains.
        #[arg(long = "chain-id")]
        chain_id: Option<u64>,
        /// Explicitly allow secret-bearing output.
        #[arg(long)]
        show_secrets: bool,
        /// Emit stable machine-readable output.
        #[arg(long)]
        json: bool,
    },
}
