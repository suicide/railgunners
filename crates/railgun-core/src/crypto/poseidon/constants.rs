use std::sync::OnceLock;

use ark_bn254::Fr;
use num_bigint::BigUint;
use num_traits::Num;
use serde::Deserialize;

// Vendored from pinned upstream Circom-compatible constants file:
// https://github.com/logos-storage/rs-poseidon/blob/bdbb8ba2735406e6e7b747abd3bc6711d55370aa/src/poseidon/poseidon_constants_opt.json
// Upstream parsing model:
// https://github.com/logos-storage/rs-poseidon/blob/bdbb8ba2735406e6e7b747abd3bc6711d55370aa/src/poseidon/constants.rs
// Upstream compatibility claim:
// https://github.com/logos-storage/rs-poseidon/blob/bdbb8ba2735406e6e7b747abd3bc6711d55370aa/README.md
// Deeper provenance chain:
// https://github.com/iden3/circomlibjs/blob/main/src/poseidon_opt.js
// https://github.com/iden3/circomlibjs/blob/main/src/poseidon_constants_opt.js
// Verification data for the vendored copy:
// - upstream GitHub blob SHA: 29aec839cfa22c3bbd517ff1f92269b7437c33aa
// - upstream raw SHA-256:     86759f8bcb4103b24c122d6e3505b6c3077e92b6f95bd0857207a0e50601ead1
// - local file SHA-256:       86759f8bcb4103b24c122d6e3505b6c3077e92b6f95bd0857207a0e50601ead1
const CONSTANTS_JSON: &str = include_str!("poseidon_constants_opt.json");

pub(super) struct PoseidonConstants {
    pub(super) c: Vec<Vec<Fr>>,
    pub(super) s: Vec<Vec<Fr>>,
    pub(super) m: Vec<Vec<Vec<Fr>>>,
    pub(super) p: Vec<Vec<Vec<Fr>>>,
}

#[derive(Deserialize)]
struct RawPoseidonConstants {
    #[serde(rename = "C")]
    c: Vec<Vec<String>>,
    #[serde(rename = "S")]
    s: Vec<Vec<String>>,
    #[serde(rename = "M")]
    m: Vec<Vec<Vec<String>>>,
    #[serde(rename = "P")]
    p: Vec<Vec<Vec<String>>>,
}

static POSEIDON_CONSTANTS: OnceLock<PoseidonConstants> = OnceLock::new();

pub(super) fn poseidon_constants() -> &'static PoseidonConstants {
    POSEIDON_CONSTANTS.get_or_init(|| {
        let raw = serde_json::from_str::<RawPoseidonConstants>(CONSTANTS_JSON)
            .unwrap_or_else(|error| panic!("poseidon constants JSON should parse: {error}"));

        PoseidonConstants {
            c: raw.c.into_iter().map(parse_row).collect(),
            s: raw.s.into_iter().map(parse_row).collect(),
            m: raw
                .m
                .into_iter()
                .map(|matrix| matrix.into_iter().map(parse_row).collect())
                .collect(),
            p: raw
                .p
                .into_iter()
                .map(|matrix| matrix.into_iter().map(parse_row).collect())
                .collect(),
        }
    })
}

fn parse_row(values: Vec<String>) -> Vec<Fr> {
    values.into_iter().map(|value| parse_field(&value)).collect()
}

fn parse_field(value: &str) -> Fr {
    let trimmed = value.strip_prefix("0x").unwrap_or(value);
    let field = BigUint::from_str_radix(trimmed, 16).unwrap_or_else(|error| {
        panic!("poseidon constant should parse as hex field element: {error}")
    });
    Fr::from(field)
}
