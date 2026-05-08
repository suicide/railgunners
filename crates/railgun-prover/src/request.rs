//! Typed proof request models.

use crate::PreparedCircuitInputs;

/// Prepared proving request for a Railgun transaction circuit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransactionProofRequest {
    inputs: PreparedCircuitInputs,
}

impl TransactionProofRequest {
    /// Creates a Railgun transaction proof request.
    #[must_use]
    pub fn new(inputs: PreparedCircuitInputs) -> Self {
        Self { inputs }
    }

    /// Returns prepared circuit inputs for proving.
    #[must_use]
    pub fn inputs(&self) -> &PreparedCircuitInputs {
        &self.inputs
    }
}

/// Prepared proving request for a Proof of Innocence circuit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PoiProofRequest {
    inputs: PreparedCircuitInputs,
}

impl PoiProofRequest {
    /// Creates a POI proof request.
    #[must_use]
    pub fn new(inputs: PreparedCircuitInputs) -> Self {
        Self { inputs }
    }

    /// Returns prepared circuit inputs for proving.
    #[must_use]
    pub fn inputs(&self) -> &PreparedCircuitInputs {
        &self.inputs
    }
}
