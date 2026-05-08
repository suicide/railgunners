//! Typed proof request and result models.

use serde_json::{Map, Value};

use crate::ProverError;

/// Proof family represented at the prover interface boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProofFamily {
    /// Standard RAILGUN transaction proving circuits.
    RailgunTransaction,
    /// Proof of Innocence circuits.
    Poi,
}

/// Prepared circuit input object for a prover backend.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedCircuitInputs {
    object: Map<String, Value>,
}

impl PreparedCircuitInputs {
    /// Creates prepared circuit inputs from a JSON value.
    ///
    /// # Errors
    ///
    /// Returns an error when the value is not a JSON object.
    pub fn from_value(value: Value) -> Result<Self, ProverError> {
        match value {
            Value::Object(object) => Ok(Self { object }),
            _ => Err(ProverError::InvalidPreparedInputs(
                "prepared circuit inputs must be a JSON object",
            )),
        }
    }

    /// Returns the prepared circuit inputs as a JSON object.
    #[must_use]
    pub fn as_object(&self) -> &Map<String, Value> {
        &self.object
    }

    /// Returns the prepared circuit inputs as a JSON value.
    #[must_use]
    pub fn to_value(&self) -> Value {
        Value::Object(self.object.clone())
    }
}

/// Ordered public signals used for local proof verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicSignals(Vec<String>);

impl PublicSignals {
    /// Creates a typed ordered public-signal list.
    #[must_use]
    pub fn new(signals: Vec<String>) -> Self {
        Self(signals)
    }

    /// Returns the ordered public signals.
    #[must_use]
    pub fn as_slice(&self) -> &[String] {
        &self.0
    }
}

/// Typed public-input wrapper for Railgun transaction proof verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransactionPublicInputs {
    signals: PublicSignals,
}

impl TransactionPublicInputs {
    /// Creates typed Railgun transaction public inputs.
    #[must_use]
    pub fn new(signals: Vec<String>) -> Self {
        Self { signals: PublicSignals::new(signals) }
    }

    /// Returns the ordered public signals.
    #[must_use]
    pub fn signals(&self) -> &PublicSignals {
        &self.signals
    }
}

/// Typed public-input wrapper for Proof of Innocence proof verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PoiPublicInputs {
    signals: PublicSignals,
}

impl PoiPublicInputs {
    /// Creates typed POI public inputs.
    #[must_use]
    pub fn new(signals: Vec<String>) -> Self {
        Self { signals: PublicSignals::new(signals) }
    }

    /// Returns the ordered public signals.
    #[must_use]
    pub fn signals(&self) -> &PublicSignals {
        &self.signals
    }
}

/// Typed Groth16 proof data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Groth16Proof {
    a: [String; 2],
    b: [[String; 2]; 2],
    c: [String; 2],
}

impl Groth16Proof {
    /// Creates a typed Groth16 proof from canonical point strings.
    #[must_use]
    pub fn new(pi_a: [String; 2], pi_b: [[String; 2]; 2], pi_c: [String; 2]) -> Self {
        Self { a: pi_a, b: pi_b, c: pi_c }
    }

    /// Returns proof point `pi_a`.
    #[must_use]
    pub fn pi_a(&self) -> &[String; 2] {
        &self.a
    }

    /// Returns proof point `pi_b`.
    #[must_use]
    pub fn pi_b(&self) -> &[[String; 2]; 2] {
        &self.b
    }

    /// Returns proof point `pi_c`.
    #[must_use]
    pub fn pi_c(&self) -> &[String; 2] {
        &self.c
    }
}

/// Result returned by a prover backend after successful proving.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedProof {
    proof: Groth16Proof,
    public_signals: Option<PublicSignals>,
}

impl GeneratedProof {
    /// Creates a generated proof result.
    #[must_use]
    pub fn new(proof: Groth16Proof, public_signals: Option<PublicSignals>) -> Self {
        Self { proof, public_signals }
    }

    /// Returns the proof data.
    #[must_use]
    pub fn proof(&self) -> &Groth16Proof {
        &self.proof
    }

    /// Returns public signals emitted by the backend when available.
    #[must_use]
    pub fn public_signals(&self) -> Option<&PublicSignals> {
        self.public_signals.as_ref()
    }
}
