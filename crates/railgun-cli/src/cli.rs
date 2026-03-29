use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "railgun-rs")]
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
    /// Run mnemonic-related offline workflows.
    #[command(subcommand)]
    Mnemonic(MnemonicCommand),
    /// Derive and inspect Railgun keys.
    #[command(subcommand)]
    Keys(KeysCommand),
    /// Create and inspect shareable viewing keys.
    #[command(subcommand)]
    ViewingKey(ViewingKeyCommand),
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
