//! Railgun hardened key derivation.

use core::{fmt, str::FromStr};

use hmac::{Hmac, Mac};
use sha2::Sha512;

type HmacSha512 = Hmac<Sha512>;

const CURVE_SEED: &[u8] = b"babyjubjub seed";
const HARDENED_OFFSET: u32 = 0x8000_0000;
const NODE_COMPONENT_LENGTH: usize = 32;
const BIP39_SEED_LENGTH: usize = 64;
const SPENDING_PATH_PREFIX: [u32; 4] = [44, 1984, 0, 0];
const VIEWING_PATH_PREFIX: [u32; 4] = [420, 1984, 0, 0];

/// Error returned when hardened key derivation input is invalid or unsupported.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KeyDerivationError {
    /// The seed is not the canonical 64-byte BIP-39 seed.
    InvalidSeedLength(usize),
    /// The derivation path is malformed.
    InvalidPath,
    /// The derivation path must begin with the root marker.
    InvalidPathRoot,
    /// The derivation path contains a segment without the hardened marker.
    NonHardenedSegment,
    /// The derivation path contains a segment that cannot be represented.
    InvalidSegmentValue,
    /// An internal cryptographic primitive rejected input unexpectedly.
    DerivationFailure,
}

impl fmt::Display for KeyDerivationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSeedLength(length) => {
                write!(formatter, "invalid BIP-39 seed length: expected 64 bytes, got {length}")
            }
            Self::InvalidPath => formatter.write_str("invalid hardened derivation path"),
            Self::InvalidPathRoot => formatter.write_str("derivation path must start with 'm'"),
            Self::NonHardenedSegment => {
                formatter.write_str("derivation path segments must be hardened")
            }
            Self::InvalidSegmentValue => {
                formatter.write_str("derivation path segment is out of range")
            }
            Self::DerivationFailure => {
                formatter.write_str("failed to derive hardened Railgun key material")
            }
        }
    }
}

impl std::error::Error for KeyDerivationError {}

/// Hardened child index constrained to the non-hardened numeric range.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HardenedIndex(u32);

impl HardenedIndex {
    /// The largest supported non-hardened numeric segment value.
    pub const MAX: u32 = HARDENED_OFFSET - 1;

    /// Creates a hardened index from its numeric segment value.
    ///
    /// # Errors
    ///
    /// Returns an error if `value` exceeds the representable hardened range.
    pub fn new(value: u32) -> Result<Self, KeyDerivationError> {
        if value > Self::MAX {
            return Err(KeyDerivationError::InvalidSegmentValue);
        }

        Ok(Self(value))
    }

    /// Returns the numeric segment value before the hardened offset is applied.
    #[must_use]
    pub const fn value(self) -> u32 {
        self.0
    }

    #[must_use]
    const fn child_number(self) -> u32 {
        self.0 + HARDENED_OFFSET
    }
}

impl fmt::Display for HardenedIndex {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}'", self.0)
    }
}

impl TryFrom<u32> for HardenedIndex {
    type Error = KeyDerivationError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// Parsed hardened derivation path rooted at `m`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DerivationPath {
    segments: Vec<HardenedIndex>,
}

impl DerivationPath {
    /// Creates a path from validated hardened segments.
    ///
    /// # Errors
    ///
    /// Returns an error if no segments are provided.
    pub fn new(segments: Vec<HardenedIndex>) -> Result<Self, KeyDerivationError> {
        if segments.is_empty() {
            return Err(KeyDerivationError::InvalidPath);
        }

        Ok(Self { segments })
    }

    /// Returns the validated hardened segments in derivation order.
    #[must_use]
    pub fn segments(&self) -> &[HardenedIndex] {
        &self.segments
    }
}

impl fmt::Display for DerivationPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("m")?;
        for segment in &self.segments {
            write!(formatter, "/{segment}")?;
        }
        Ok(())
    }
}

impl FromStr for DerivationPath {
    type Err = KeyDerivationError;

    fn from_str(path: &str) -> Result<Self, Self::Err> {
        let mut components = path.split('/');
        let Some(root) = components.next() else {
            return Err(KeyDerivationError::InvalidPath);
        };

        if root != "m" {
            return Err(KeyDerivationError::InvalidPathRoot);
        }

        let mut segments = Vec::new();

        for component in components {
            if component.is_empty() {
                return Err(KeyDerivationError::InvalidPath);
            }

            let Some(raw_value) = component.strip_suffix('\'') else {
                return Err(KeyDerivationError::NonHardenedSegment);
            };

            let value = raw_value.parse::<u32>().map_err(|_| KeyDerivationError::InvalidPath)?;
            segments.push(HardenedIndex::new(value)?);
        }

        Self::new(segments)
    }
}

/// Railgun wallet node material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WalletNode {
    chain_code: [u8; NODE_COMPONENT_LENGTH],
    chain_key: [u8; NODE_COMPONENT_LENGTH],
}

impl WalletNode {
    /// Creates a wallet node from raw node material.
    #[must_use]
    pub const fn new(
        chain_code: [u8; NODE_COMPONENT_LENGTH],
        chain_key: [u8; NODE_COMPONENT_LENGTH],
    ) -> Self {
        Self { chain_code, chain_key }
    }

    /// Returns the 32-byte chain code.
    #[must_use]
    pub const fn chain_code(&self) -> &[u8; NODE_COMPONENT_LENGTH] {
        &self.chain_code
    }

    /// Returns the 32-byte chain key.
    #[must_use]
    pub const fn chain_key(&self) -> &[u8; NODE_COMPONENT_LENGTH] {
        &self.chain_key
    }

    /// Derives a hardened child node.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying HMAC primitive fails unexpectedly.
    pub fn derive_child(self, index: HardenedIndex) -> Result<Self, KeyDerivationError> {
        derive_hardened_child(self, index)
    }

    /// Derives a descendant node along the provided path.
    ///
    /// # Errors
    ///
    /// Returns an error if hardened child derivation fails unexpectedly.
    pub fn derive_path(self, path: &DerivationPath) -> Result<Self, KeyDerivationError> {
        let mut node = self;
        for segment in path.segments() {
            node = node.derive_child(*segment)?;
        }
        Ok(node)
    }
}

/// Returns the canonical Railgun spending path for `wallet_index`.
///
/// # Errors
///
/// Returns an error if `wallet_index` exceeds the supported hardened range.
pub fn spending_path(wallet_index: u32) -> Result<DerivationPath, KeyDerivationError> {
    canonical_path(SPENDING_PATH_PREFIX, wallet_index)
}

/// Returns the canonical Railgun viewing path for `wallet_index`.
///
/// # Errors
///
/// Returns an error if `wallet_index` exceeds the supported hardened range.
pub fn viewing_path(wallet_index: u32) -> Result<DerivationPath, KeyDerivationError> {
    canonical_path(VIEWING_PATH_PREFIX, wallet_index)
}

/// Derives the Railgun master node from a canonical 64-byte BIP-39 seed.
///
/// # Errors
///
/// Returns an error if `seed` is not exactly 64 bytes long or if the
/// underlying HMAC primitive fails unexpectedly.
pub fn derive_master_node(seed: &[u8]) -> Result<WalletNode, KeyDerivationError> {
    let seed_array: [u8; BIP39_SEED_LENGTH] =
        seed.try_into().map_err(|_| KeyDerivationError::InvalidSeedLength(seed.len()))?;
    derive_master_node_from_seed(seed_array)
}

/// Derives a node from a seed and hardened path.
///
/// # Errors
///
/// Returns an error if the seed length is invalid or if derivation fails.
pub fn derive_node(seed: &[u8], path: &DerivationPath) -> Result<WalletNode, KeyDerivationError> {
    derive_master_node(seed)?.derive_path(path)
}

/// Derives a node from a seed and path string.
///
/// # Errors
///
/// Returns an error if the path is malformed, contains non-hardened segments,
/// or if the seed length is invalid.
pub fn derive_node_from_str(seed: &[u8], path: &str) -> Result<WalletNode, KeyDerivationError> {
    let path = DerivationPath::from_str(path)?;
    derive_node(seed, &path)
}

/// Derives the canonical Railgun spending node for `wallet_index`.
///
/// # Errors
///
/// Returns an error if `wallet_index` is invalid, the seed length is invalid,
/// or derivation fails.
pub fn derive_spending_node(
    seed: &[u8],
    wallet_index: u32,
) -> Result<WalletNode, KeyDerivationError> {
    let path = spending_path(wallet_index)?;
    derive_node(seed, &path)
}

/// Derives the canonical Railgun viewing node for `wallet_index`.
///
/// # Errors
///
/// Returns an error if `wallet_index` is invalid, the seed length is invalid,
/// or derivation fails.
pub fn derive_viewing_node(
    seed: &[u8],
    wallet_index: u32,
) -> Result<WalletNode, KeyDerivationError> {
    let path = viewing_path(wallet_index)?;
    derive_node(seed, &path)
}

fn canonical_path(
    prefix: [u32; 4],
    wallet_index: u32,
) -> Result<DerivationPath, KeyDerivationError> {
    let mut segments = Vec::with_capacity(prefix.len() + 1);
    for segment in prefix {
        segments.push(HardenedIndex::new(segment)?);
    }
    segments.push(HardenedIndex::new(wallet_index)?);
    DerivationPath::new(segments)
}

fn derive_master_node_from_seed(
    seed: [u8; BIP39_SEED_LENGTH],
) -> Result<WalletNode, KeyDerivationError> {
    let digest = hmac_sha512(CURVE_SEED, &seed)?;
    Ok(split_wallet_node(digest))
}

fn derive_hardened_child(
    node: WalletNode,
    index: HardenedIndex,
) -> Result<WalletNode, KeyDerivationError> {
    let mut preimage = [0_u8; 1 + NODE_COMPONENT_LENGTH + 4];
    preimage[0] = 0;
    preimage[1..=NODE_COMPONENT_LENGTH].copy_from_slice(node.chain_key());
    preimage[1 + NODE_COMPONENT_LENGTH..].copy_from_slice(&index.child_number().to_be_bytes());

    let digest = hmac_sha512(node.chain_code(), &preimage)?;
    Ok(split_wallet_node(digest))
}

fn hmac_sha512(key: &[u8], message: &[u8]) -> Result<[u8; 64], KeyDerivationError> {
    let mut mac =
        HmacSha512::new_from_slice(key).map_err(|_| KeyDerivationError::DerivationFailure)?;
    mac.update(message);
    let bytes = mac.finalize().into_bytes();
    let mut output = [0_u8; 64];
    output.copy_from_slice(&bytes);
    Ok(output)
}

fn split_wallet_node(digest: [u8; 64]) -> WalletNode {
    let mut chain_key = [0_u8; NODE_COMPONENT_LENGTH];
    chain_key.copy_from_slice(&digest[..NODE_COMPONENT_LENGTH]);

    let mut chain_code = [0_u8; NODE_COMPONENT_LENGTH];
    chain_code.copy_from_slice(&digest[NODE_COMPONENT_LENGTH..]);

    WalletNode::new(chain_code, chain_key)
}

#[cfg(test)]
mod tests {
    use super::{
        DerivationPath, HARDENED_OFFSET, HardenedIndex, KeyDerivationError, WalletNode,
        derive_master_node, derive_node_from_str, derive_spending_node, derive_viewing_node,
        spending_path, viewing_path,
    };

    #[test]
    fn derives_master_node_from_issue_vector() {
        let seed = hex_decode(
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
        );

        let Ok(node) = derive_master_node(&seed) else {
            panic!("master derivation should succeed");
        };

        assert_eq!(
            hex_encode(node.chain_code()),
            "30d550bc2f61a7c206a1eba3704502da77f366fe69721265b3b7e2c7f05eeabc"
        );
        assert_eq!(
            hex_encode(node.chain_key()),
            "1fafc64161d1807e294cc9fded180ca2009aaaedf4cbd7359d4aaa3bb462f411"
        );
    }

    #[test]
    fn derives_all_research_master_vectors() {
        let vectors = [
            (
                "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
                "30d550bc2f61a7c206a1eba3704502da77f366fe69721265b3b7e2c7f05eeabc",
                "1fafc64161d1807e294cc9fded180ca2009aaaedf4cbd7359d4aaa3bb462f411",
            ),
            (
                "d8c228addf9a9cfe5b7934223737815e2f709b3ac12b0c1b2aaec921e5d3a2e8aeea1df817af8159f981798dacd5a930a1fcd8570ba4845078c1b1d09fa060cb",
                "b37268d31994f4bbe422feffb3e1dcb35b61b76c0c1ebea2ded5fb0e37aa0809",
                "c544e07e1007d25b6a3a7ddba8f1e20c2c23c9baec8e9a6200dd6c3b2f8df6a5",
            ),
            (
                "243c1266228fc9ff370d567ba4f805dfacc516375aecf4657cf870a4b551020d92d9b45a8181154f531c1358f742f42078a1620fca6251b1c4ec5fa6e1cf5c3a",
                "8bf4df70930efcf3ce0e8501464891837fa591b3b0924d9110b18152b8a85d37",
                "73eb04585b9ecc409c76a2949f099193be82198eb6abab1594be4138070f19d6",
            ),
            (
                "87ec3e2ae9294cb5500698e6e6ee8357aa56222badae0e6b4150492c95ede7ddfca27c952afafb388453def93fac72f5d7e099debd79e85c2088f9b3e7a65df6",
                "5a7496d62dab5d3bef668bcff39eef421ea6b9544dba30805858989dc6611e36",
                "5c8f71501f449b499feddb89d865f15d35d24586b6447b7c9b7385d0bf217fd4",
            ),
        ];

        for (seed, expected_chain_code, expected_chain_key) in vectors {
            let seed = hex_decode(seed);
            let Ok(node) = derive_master_node(&seed) else {
                panic!("research master vector should succeed");
            };

            assert_eq!(hex_encode(node.chain_code()), expected_chain_code);
            assert_eq!(hex_encode(node.chain_key()), expected_chain_key);
        }
    }

    #[test]
    fn derives_hardened_child_from_issue_vector() {
        let node = WalletNode::new(
            hex_array("30d550bc2f61a7c206a1eba3704502da77f366fe69721265b3b7e2c7f05eeabc"),
            hex_array("1fafc64161d1807e294cc9fded180ca2009aaaedf4cbd7359d4aaa3bb462f411"),
        );

        let Ok(index) = HardenedIndex::new(0) else {
            panic!("zero should be valid");
        };
        let Ok(child) = node.derive_child(index) else {
            panic!("child derivation should succeed");
        };

        assert_eq!(
            hex_encode(child.chain_code()),
            "e8e6a1bbce8bab145fe8225435dc98d20d53bd32318ce3ede560b8feef3394a5"
        );
        assert_eq!(
            hex_encode(child.chain_key()),
            "67d7d19d00e6e3b3517fe68ac46505dd207df6e8fe3aa06ba3face352e7599ef"
        );
    }

    #[test]
    fn derives_all_research_child_vectors() {
        let vectors = [
            (
                "30d550bc2f61a7c206a1eba3704502da77f366fe69721265b3b7e2c7f05eeabc",
                "1fafc64161d1807e294cc9fded180ca2009aaaedf4cbd7359d4aaa3bb462f411",
                0,
                "e8e6a1bbce8bab145fe8225435dc98d20d53bd32318ce3ede560b8feef3394a5",
                "67d7d19d00e6e3b3517fe68ac46505dd207df6e8fe3aa06ba3face352e7599ef",
            ),
            (
                "30d550bc2f61a7c206a1eba3704502da77f366fe69721265b3b7e2c7f05eeabc",
                "1fafc64161d1807e294cc9fded180ca2009aaaedf4cbd7359d4aaa3bb462f411",
                12,
                "ff90a1dcb6531d437dc959b6e03f308dd4d9db7e489bdb30d8b4b1894a9e1344",
                "9606ae0c844601e0af4d518dce577983ad756dea08726d92c080ed2ca3f5f31d",
            ),
            (
                "b37268d31994f4bbe422feffb3e1dcb35b61b76c0c1ebea2ded5fb0e37aa0809",
                "c544e07e1007d25b6a3a7ddba8f1e20c2c23c9baec8e9a6200dd6c3b2f8df6a5",
                1,
                "30c3769638ef70c9179a7b18a507318d2353831c2d7990056334cbf14ed4a2cf",
                "0b20d68e515add21c2686d88b8ae02d82912741ed66cb776b6a2eec628ce5fef",
            ),
        ];

        for (parent_chain_code, parent_chain_key, index, expected_chain_code, expected_chain_key) in
            vectors
        {
            let node = WalletNode::new(hex_array(parent_chain_code), hex_array(parent_chain_key));
            let Ok(index) = HardenedIndex::new(index) else {
                panic!("research child index should be valid");
            };
            let Ok(child) = node.derive_child(index) else {
                panic!("research child vector should succeed");
            };

            assert_eq!(hex_encode(child.chain_code()), expected_chain_code);
            assert_eq!(hex_encode(child.chain_key()), expected_chain_key);
        }
    }

    #[test]
    fn exposes_canonical_spending_path() {
        let Ok(path) = spending_path(0) else {
            panic!("canonical spending path should build");
        };

        assert_eq!(path.to_string(), "m/44'/1984'/0'/0'/0'");
    }

    #[test]
    fn exposes_canonical_viewing_path() {
        let Ok(path) = viewing_path(0) else {
            panic!("canonical viewing path should build");
        };

        assert_eq!(path.to_string(), "m/420'/1984'/0'/0'/0'");
    }

    #[test]
    fn derives_spending_and_viewing_nodes_deterministically() {
        let seed = hex_decode(
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
        );

        let Ok(spending_a) = derive_spending_node(&seed, 0) else {
            panic!("spending derivation should succeed");
        };
        let Ok(spending_b) = derive_node_from_str(&seed, "m/44'/1984'/0'/0'/0'") else {
            panic!("path derivation should succeed");
        };
        let Ok(viewing_a) = derive_viewing_node(&seed, 0) else {
            panic!("viewing derivation should succeed");
        };
        let Ok(viewing_b) = derive_viewing_node(&seed, 0) else {
            panic!("repeat viewing derivation should succeed");
        };

        assert_eq!(spending_a, spending_b);
        assert_eq!(viewing_a, viewing_b);
    }

    #[test]
    fn derives_non_zero_spending_indexes_consistently() {
        let seed = hex_decode(
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
        );

        let Ok(index_zero) = derive_spending_node(&seed, 0) else {
            panic!("index zero spending derivation should succeed");
        };
        let Ok(index_hundred) = derive_spending_node(&seed, 100) else {
            panic!("index one hundred spending derivation should succeed");
        };
        let Ok(index_hundred_from_path) = derive_node_from_str(&seed, "m/44'/1984'/0'/0'/100'")
        else {
            panic!("index one hundred spending path derivation should succeed");
        };

        assert_eq!(index_hundred, index_hundred_from_path);
        assert_ne!(index_zero, index_hundred);
    }

    #[test]
    fn derives_non_zero_viewing_indexes_consistently() {
        let seed = hex_decode(
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
        );

        let Ok(index_zero) = derive_viewing_node(&seed, 0) else {
            panic!("index zero viewing derivation should succeed");
        };
        let Ok(index_twelve) = derive_viewing_node(&seed, 12) else {
            panic!("index twelve viewing derivation should succeed");
        };
        let Ok(index_twelve_from_path) = derive_node_from_str(&seed, "m/420'/1984'/0'/0'/12'")
        else {
            panic!("index twelve viewing path derivation should succeed");
        };

        assert_eq!(index_twelve, index_twelve_from_path);
        assert_ne!(index_zero, index_twelve);
    }

    #[test]
    fn exposes_non_zero_canonical_paths() {
        let Ok(spending) = spending_path(100) else {
            panic!("non-zero spending path should build");
        };
        let Ok(viewing) = viewing_path(12) else {
            panic!("non-zero viewing path should build");
        };

        assert_eq!(spending.to_string(), "m/44'/1984'/0'/0'/100'");
        assert_eq!(viewing.to_string(), "m/420'/1984'/0'/0'/12'");
    }

    #[test]
    fn parses_valid_hardened_path() {
        let Ok(path) = "m/44'/1984'/0'/0'/1'".parse::<DerivationPath>() else {
            panic!("path should parse");
        };

        assert_eq!(path.to_string(), "m/44'/1984'/0'/0'/1'");
    }

    #[test]
    fn parses_research_valid_path_examples() {
        let vectors = [
            ("m/0'/1'/1'", [0, 1, 1]),
            ("m/12'/0'/15'", [12, 0, 15]),
            ("m/1'/91'/12'", [1, 91, 12]),
        ];

        for (path, expected) in vectors {
            let Ok(parsed) = path.parse::<DerivationPath>() else {
                panic!("research path example should parse");
            };
            let actual: Vec<u32> =
                parsed.segments().iter().map(|segment| segment.value()).collect();
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn rejects_non_hardened_path_segment() {
        let Err(error) = "m/44/1984'/0'/0'/0'".parse::<DerivationPath>() else {
            panic!("non-hardened path should fail");
        };

        assert_eq!(error, KeyDerivationError::NonHardenedSegment);
    }

    #[test]
    fn rejects_malformed_path() {
        let Err(error) = "m//0'".parse::<DerivationPath>() else {
            panic!("malformed path should fail");
        };

        assert_eq!(error, KeyDerivationError::InvalidPath);
    }

    #[test]
    fn rejects_research_invalid_path_examples() {
        for path in ["m/0/0", "railgun", "m/0'/0'/x"] {
            let Err(_) = path.parse::<DerivationPath>() else {
                panic!("research invalid path should fail");
            };
        }
    }

    #[test]
    fn rejects_invalid_root() {
        let Err(error) = "n/0'".parse::<DerivationPath>() else {
            panic!("invalid root should fail");
        };

        assert_eq!(error, KeyDerivationError::InvalidPathRoot);
    }

    #[test]
    fn rejects_out_of_range_segment() {
        let Err(error) = format!("m/{HARDENED_OFFSET}'").parse::<DerivationPath>() else {
            panic!("out-of-range segment should fail");
        };

        assert_eq!(error, KeyDerivationError::InvalidSegmentValue);
    }

    #[test]
    fn rejects_empty_path() {
        let Err(error) = "m".parse::<DerivationPath>() else {
            panic!("empty path should fail");
        };

        assert_eq!(error, KeyDerivationError::InvalidPath);
    }

    #[test]
    fn rejects_invalid_seed_length() {
        let Err(error) = derive_master_node(&[7_u8; 63]) else {
            panic!("invalid seed length should fail");
        };

        assert_eq!(error, KeyDerivationError::InvalidSeedLength(63));
    }

    fn hex_array<const N: usize>(value: &str) -> [u8; N] {
        let bytes = hex_decode(value);
        let mut array = [0_u8; N];
        array.copy_from_slice(&bytes);
        array
    }

    fn hex_decode(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0, "hex input must be even-length");
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|chunk| {
                let Ok(text) = core::str::from_utf8(chunk) else {
                    panic!("test hex should be utf-8");
                };
                let Ok(byte) = u8::from_str_radix(text, 16) else {
                    panic!("test hex should be valid");
                };
                byte
            })
            .collect()
    }

    fn hex_encode(bytes: &[u8]) -> String {
        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            use core::fmt::Write as _;
            let result = write!(&mut encoded, "{byte:02x}");
            assert!(result.is_ok(), "writing to a string should succeed");
        }
        encoded
    }
}
