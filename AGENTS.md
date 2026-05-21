# AGENTS.md

## Project overview

`railgun-rs` is a modular Rust SDK for the RAILGUN privacy system. It provides shared protocol libraries, thin WASM bindings, and a small CLI built on the same public APIs. The main technologies are Rust, Cargo, and Nix.

If this file conflicts with `ARCHITECTURE_CONSTITUTION.md`, the constitution wins.

## How to run and build

- Recommended environment: `nix develop`
- Fetch dependencies: `cargo fetch`
- Check the workspace: `cargo check`
- Build the workspace: `cargo build`
- Build the CLI package: `cargo build -p railgun-cli`
- Run the CLI locally: `cargo run -p railgun-cli -- --help`
- Build with pinned Nix config: `nix build .#default`

## Testing and verification

- Format: `cargo fmt --all --check`
- Lint: `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- Dependency policy: `cargo deny check`
- Tests: `cargo test --workspace`
- Broad final verification: `nix flake check`

Changes are not complete until the smallest relevant crate-level checks pass. Run workspace-level checks for shared changes. Prefer `nix flake check` before finishing broad or cross-cutting work.

## Project structure

- `crates/railgun-types/` - shared domain types and validated primitives
- `crates/railgun-core/` - shared protocol traits, errors, crypto, and core logic
- `crates/railgun-artifacts/` - proving-artifact metadata and optional downloads
- `crates/railgun-broadcaster/` - typed broadcaster models and helpers
- `crates/railgun-poi/` - typed Proof of Innocence models, validation, and optional transports
- `crates/railgun-prover/` - proving abstractions and helpers
- `crates/railgun-wasm/` - thin WASM bindings over Rust logic
- `crates/railgun-cli/` - thin operational CLI using public library APIs

## Code and git workflow

- Read first: `ARCHITECTURE_CONSTITUTION.md`, `ARCHITECTURE.md`, `CONTRIBUTING.md`, `VISION.md`, `README.md`
- Make the smallest change that fits the correct architectural layer.
- Use crate-scoped commands while iterating; use workspace-wide commands when the change is shared.
- Keep docs in sync when commands, workflow, architecture, or crate boundaries change.
- Follow repo tooling rather than local style preferences: `rustfmt`, workspace `clippy` lints, and `cargo deny`.
- No branch naming or commit message convention is documented here; do not invent one.

## Constraints and boundaries

- Must preserve layering: `core/domain -> adapters -> bindings/apps`.
- Must keep vendor-specific integrations out of core crates.
- Must keep `railgun-wasm` thin; do not move protocol logic into bindings.
- Must keep `railgun-cli` thin; if the CLI needs new behavior, add it to public library APIs first.
- Must prefer typed domain models over raw strings, bytes, or maps for protocol concepts.
- Must use fallible validation at boundaries when invalid input is possible.
- Must keep defaults optional; do not hard-wire one external stack.
- Must avoid exposing secrets or privacy-sensitive material through unsafe convenience APIs.
- Should prefer `core` over `std` in reusable/core code where practical.
- Should avoid new crates or heavy dependencies unless a real boundary justifies them.
- Never bypass the architecture constitution to satisfy a task; surface the conflict instead.

## Links to deeper docs

- `ARCHITECTURE_CONSTITUTION.md` - binding architectural rules
- `ARCHITECTURE.md` - workspace layering and crate responsibilities
- `CONTRIBUTING.md` - contribution flow and dependency guidance
- `VISION.md` - goals and non-goals
- `README.md` - current workspace status and CLI usage
