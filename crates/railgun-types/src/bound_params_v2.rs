use crate::{Address, ChainId, CommitmentCiphertextV2, ParseDomainError};

const UINT48_MAX: u64 = (1_u64 << 48) - 1;

/// Canonical 32-byte adapt parameter payload bound into V2 transactions.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AdaptParams([u8; 32]);

impl AdaptParams {
    /// Length of canonical adapt params in bytes.
    pub const LENGTH: usize = 32;

    /// Creates adapt params from raw bytes.
    #[must_use]
    pub const fn new(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    /// Creates adapt params from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns an error if `bytes` is not exactly 32 bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ParseDomainError> {
        let array: [u8; Self::LENGTH] = bytes
            .try_into()
            .map_err(|_| ParseDomainError::new("adapt params must be exactly 32 bytes"))?;
        Ok(Self::new(array))
    }

    /// Returns the raw adapt-params bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}

/// V2 `minGasPrice` value constrained to the Solidity `uint48` width.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MinGasPrice(u64);

impl MinGasPrice {
    /// Creates a validated `minGasPrice` value.
    ///
    /// # Errors
    ///
    /// Returns an error if `value` exceeds the Solidity `uint48` range.
    pub fn new(value: u64) -> Result<Self, ParseDomainError> {
        if value > UINT48_MAX {
            return Err(ParseDomainError::new("min gas price must fit within 48 bits"));
        }

        Ok(Self(value))
    }

    /// Returns the inner numeric value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Canonical V2 unshield flag bound into proof inputs.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum V2UnshieldFlag {
    /// No public unshield output is present.
    None = 0,
    /// A normal unshield output is present.
    Unshield = 1,
    /// An unshield output is present and may override the recipient.
    Override = 2,
}

impl V2UnshieldFlag {
    /// Returns the canonical numeric discriminator.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for V2UnshieldFlag {
    type Error = ParseDomainError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::Unshield),
            2 => Ok(Self::Override),
            _ => Err(ParseDomainError::new("v2 unshield flag is unsupported")),
        }
    }
}

/// Reduced V2 bound params hash encoded as canonical 32-byte big-endian field bytes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BoundParamsHash([u8; 32]);

impl BoundParamsHash {
    /// Length of a bound params hash in bytes.
    pub const LENGTH: usize = 32;

    /// Creates a bound params hash from raw bytes.
    #[must_use]
    pub const fn new(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    /// Creates a bound params hash from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns an error if `bytes` is not exactly 32 bytes long.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ParseDomainError> {
        let array: [u8; Self::LENGTH] = bytes
            .try_into()
            .map_err(|_| ParseDomainError::new("bound params hash must be exactly 32 bytes"))?;
        Ok(Self::new(array))
    }

    /// Returns the raw hash bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}

/// Canonical V2 bound params model used for ABI encoding and transaction hashing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct V2BoundParams {
    tree_number: u16,
    min_gas_price: MinGasPrice,
    unshield: V2UnshieldFlag,
    chain_id: ChainId,
    adapt_contract: Address,
    adapt_params: AdaptParams,
    commitment_ciphertext: Vec<CommitmentCiphertextV2>,
}

impl V2BoundParams {
    /// Creates V2 bound params from explicit validated components.
    #[must_use]
    pub fn new(
        tree_number: u16,
        min_gas_price: MinGasPrice,
        unshield: V2UnshieldFlag,
        chain_id: ChainId,
        adapt_contract: Address,
        adapt_params: AdaptParams,
        commitment_ciphertext: Vec<CommitmentCiphertextV2>,
    ) -> Self {
        Self {
            tree_number,
            min_gas_price,
            unshield,
            chain_id,
            adapt_contract,
            adapt_params,
            commitment_ciphertext,
        }
    }

    /// Returns the bound UTXO tree number.
    #[must_use]
    pub const fn tree_number(&self) -> u16 {
        self.tree_number
    }

    /// Returns the broadcaster gas floor.
    #[must_use]
    pub const fn min_gas_price(&self) -> MinGasPrice {
        self.min_gas_price
    }

    /// Returns the canonical unshield flag.
    #[must_use]
    pub const fn unshield(&self) -> V2UnshieldFlag {
        self.unshield
    }

    /// Returns the replay-protection chain identifier.
    #[must_use]
    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    /// Returns the bound adapt contract address.
    #[must_use]
    pub const fn adapt_contract(&self) -> Address {
        self.adapt_contract
    }

    /// Returns the opaque 32-byte adapt params payload.
    #[must_use]
    pub const fn adapt_params(&self) -> &AdaptParams {
        &self.adapt_params
    }

    /// Returns the bound commitment ciphertext entries.
    #[must_use]
    pub fn commitment_ciphertext(&self) -> &[CommitmentCiphertextV2] {
        &self.commitment_ciphertext
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        BlindedViewingPublicKey, CommitmentCiphertextV2, ParseDomainError, V2CiphertextBlock,
        V2CiphertextBundle,
    };

    use super::{AdaptParams, BoundParamsHash, MinGasPrice, V2BoundParams, V2UnshieldFlag};

    #[test]
    fn rejects_invalid_adapt_params_length() {
        let Err(error) = AdaptParams::from_slice(&[7_u8; 31]) else {
            panic!("invalid adapt params length should fail");
        };

        assert_eq!(error, ParseDomainError::new("adapt params must be exactly 32 bytes"));
    }

    #[test]
    fn rejects_invalid_min_gas_price_width() {
        let Err(error) = MinGasPrice::new(1_u64 << 48) else {
            panic!("invalid min gas price width should fail");
        };

        assert_eq!(error, ParseDomainError::new("min gas price must fit within 48 bits"));
    }

    #[test]
    fn rejects_invalid_unshield_flag() {
        let Err(error) = V2UnshieldFlag::try_from(3_u8) else {
            panic!("invalid unshield flag should fail");
        };

        assert_eq!(error, ParseDomainError::new("v2 unshield flag is unsupported"));
    }

    #[test]
    fn rejects_invalid_bound_params_hash_length() {
        let Err(error) = BoundParamsHash::from_slice(&[9_u8; 31]) else {
            panic!("invalid bound params hash length should fail");
        };

        assert_eq!(error, ParseDomainError::new("bound params hash must be exactly 32 bytes"));
    }

    #[test]
    fn bound_params_preserves_commitment_ciphertext_entries() {
        let entry = CommitmentCiphertextV2::new(
            V2CiphertextBundle::new(
                V2CiphertextBlock::new([1_u8; 32]),
                [
                    V2CiphertextBlock::new([2_u8; 32]),
                    V2CiphertextBlock::new([3_u8; 32]),
                    V2CiphertextBlock::new([4_u8; 32]),
                ],
                vec![5_u8],
                vec![6_u8],
            ),
            BlindedViewingPublicKey::new([7_u8; 32]),
            BlindedViewingPublicKey::new([8_u8; 32]),
        );
        let params = V2BoundParams::new(
            0,
            MinGasPrice::new(3000).unwrap_or_else(|_| panic!("min gas price should be valid")),
            V2UnshieldFlag::None,
            crate::ChainId::new(1).unwrap_or_else(|_| panic!("chain id should be valid")),
            crate::Address::new([0_u8; 20]),
            AdaptParams::new([0_u8; 32]),
            vec![entry.clone()],
        );

        assert_eq!(params.commitment_ciphertext(), &[entry]);
    }
}
