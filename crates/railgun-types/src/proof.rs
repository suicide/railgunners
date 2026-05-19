/// Typed Groth16 proof data shared across proving and POI flows.
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

#[cfg(test)]
mod tests {
    use super::Groth16Proof;

    #[test]
    fn exposes_groth16_points() {
        let proof = Groth16Proof::new(
            ["a0".to_owned(), "a1".to_owned()],
            [["b00".to_owned(), "b01".to_owned()], ["b10".to_owned(), "b11".to_owned()]],
            ["c0".to_owned(), "c1".to_owned()],
        );

        assert_eq!(proof.pi_a(), &["a0".to_owned(), "a1".to_owned()]);
        assert_eq!(proof.pi_b()[0], ["b00".to_owned(), "b01".to_owned()]);
        assert_eq!(proof.pi_c(), &["c0".to_owned(), "c1".to_owned()]);
    }
}
