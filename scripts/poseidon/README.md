# Poseidon Vector Generator

This script workspace generates committed Poseidon oracle fixtures from public upstream implementations.

Primary oracles:

- `@railgun-community/circomlibjs` for generic Poseidon vectors
- `@railgun-community/engine` for canonical RAILGUN txid and txid-leaf behavior

## Install

From the repository root:

```sh
npm install --prefix scripts/poseidon
```

## Generate fixtures

```sh
node scripts/poseidon/generate-vectors.mjs
```

## Check committed fixtures without rewriting

```sh
node scripts/poseidon/generate-vectors.mjs --check
```

## Output files

Fixtures are written to:

- `crates/railgun-core/testdata/poseidon/circomlibjs.json`
- `crates/railgun-core/testdata/poseidon/engine-txid.json`

## Notes

- The committed JSON fixtures are the stable offline oracle for Rust tests.
- Regeneration depends on Node and the public npm packages above, but normal Rust test runs do not.
