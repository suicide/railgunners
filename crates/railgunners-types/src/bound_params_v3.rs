use crate::{Address, CommitmentCiphertextV3};

/// V3 `minGasPrice` value carried in the global bound params tuple.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct V3MinGasPrice(u128);

impl V3MinGasPrice {
    /// Creates a V3 min-gas-price value.
    #[must_use]
    pub const fn new(value: u128) -> Self {
        Self(value)
    }

    /// Returns the inner numeric value.
    #[must_use]
    pub const fn get(self) -> u128 {
        self.0
    }
}

/// V3-specific chain identifier constrained to the exact Solidity `uint128` ABI width.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct V3ChainId(u128);

impl V3ChainId {
    /// Creates a V3 chain identifier.
    #[must_use]
    pub const fn new(value: u128) -> Self {
        Self(value)
    }

    /// Returns the inner numeric value.
    #[must_use]
    pub const fn get(self) -> u128 {
        self.0
    }
}

/// V3 local bound params committed into the transaction hash.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct V3BoundParamsLocal {
    tree_number: u32,
    commitment_ciphertext: Vec<CommitmentCiphertextV3>,
}

impl V3BoundParamsLocal {
    /// Creates V3 local bound params from explicit components.
    #[must_use]
    pub fn new(tree_number: u32, commitment_ciphertext: Vec<CommitmentCiphertextV3>) -> Self {
        Self { tree_number, commitment_ciphertext }
    }

    /// Returns the bound UTXO tree number.
    #[must_use]
    pub const fn tree_number(&self) -> u32 {
        self.tree_number
    }

    /// Returns the local commitment ciphertext entries.
    #[must_use]
    pub fn commitment_ciphertext(&self) -> &[CommitmentCiphertextV3] {
        &self.commitment_ciphertext
    }
}

/// V3 global bound params committed into the transaction hash.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct V3BoundParamsGlobal {
    min_gas_price: V3MinGasPrice,
    chain_id: V3ChainId,
    sender_ciphertext: Vec<u8>,
    to: Address,
    data: Vec<u8>,
}

impl V3BoundParamsGlobal {
    /// Creates V3 global bound params from explicit components.
    #[must_use]
    pub fn new(
        min_gas_price: V3MinGasPrice,
        chain_id: V3ChainId,
        sender_ciphertext: Vec<u8>,
        to: Address,
        data: Vec<u8>,
    ) -> Self {
        Self { min_gas_price, chain_id, sender_ciphertext, to, data }
    }

    /// Returns the broadcaster gas floor.
    #[must_use]
    pub const fn min_gas_price(&self) -> V3MinGasPrice {
        self.min_gas_price
    }

    /// Returns the V3-specific replay-protection chain identifier.
    #[must_use]
    pub const fn chain_id(&self) -> V3ChainId {
        self.chain_id
    }

    /// Returns the sender metadata ciphertext preserved in global bound params.
    #[must_use]
    pub fn sender_ciphertext(&self) -> &[u8] {
        &self.sender_ciphertext
    }

    /// Returns the bound recipient/call target address.
    #[must_use]
    pub const fn to(&self) -> Address {
        self.to
    }

    /// Returns the opaque bound call data.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

/// Canonical V3 bound params model with explicit local/global separation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct V3BoundParams {
    local: V3BoundParamsLocal,
    global: V3BoundParamsGlobal,
}

impl V3BoundParams {
    /// Creates canonical V3 bound params from explicit local and global sections.
    #[must_use]
    pub const fn new(local: V3BoundParamsLocal, global: V3BoundParamsGlobal) -> Self {
        Self { local, global }
    }

    /// Returns the local V3 bound params section.
    #[must_use]
    pub const fn local(&self) -> &V3BoundParamsLocal {
        &self.local
    }

    /// Returns the global V3 bound params section.
    #[must_use]
    pub const fn global(&self) -> &V3BoundParamsGlobal {
        &self.global
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        BlindedViewingPublicKey, CommitmentCiphertextV3, V3CiphertextBundle, V3StoredNonce,
    };

    use super::{V3BoundParams, V3BoundParamsGlobal, V3BoundParamsLocal, V3ChainId, V3MinGasPrice};

    #[test]
    fn v3_global_preserves_empty_dynamic_fields() {
        let global = V3BoundParamsGlobal::new(
            V3MinGasPrice::new(1),
            V3ChainId::new(1),
            Vec::new(),
            crate::Address::new([0_u8; 20]),
            Vec::new(),
        );

        assert!(global.sender_ciphertext().is_empty());
        assert!(global.data().is_empty());
    }

    #[test]
    fn v3_bound_params_preserves_local_global_split() {
        let local = V3BoundParamsLocal::new(
            0,
            vec![CommitmentCiphertextV3::new(
                V3CiphertextBundle::new(V3StoredNonce::new([1_u8; 16]), vec![2_u8; 48], Vec::new()),
                BlindedViewingPublicKey::new([3_u8; 32]),
                BlindedViewingPublicKey::new([4_u8; 32]),
            )],
        );
        let global = V3BoundParamsGlobal::new(
            V3MinGasPrice::new(5),
            V3ChainId::new(6),
            vec![7_u8; 8],
            crate::Address::new([8_u8; 20]),
            vec![9_u8; 10],
        );
        let params = V3BoundParams::new(local, global);

        assert_eq!(params.local().tree_number(), 0);
        assert_eq!(params.global().min_gas_price(), V3MinGasPrice::new(5));
        assert_eq!(params.global().chain_id(), V3ChainId::new(6));
        assert_eq!(params.global().sender_ciphertext(), &[7_u8; 8]);
        assert_eq!(params.global().data(), &[9_u8; 10]);
    }
}
