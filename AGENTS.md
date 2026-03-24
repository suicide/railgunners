# AGENTS.md

This file gives coding agents the operating rules for `railgun-rs`.

Read these first:
- `ARCHITECTURE_CONSTITUTION.md`
- `ARCHITECTURE.md`
- `CONTRIBUTING.md`
- `VISION.md`
- `README.md`

If this file conflicts with the architecture constitution, the constitution wins.

## Repository Summary

`railgun-rs` is a modular Rust implementation of the RAILGUN privacy system libraries.

Current workspace crates:
- `crates/railgun-types` for shared domain primitives
- `crates/railgun-core` for shared protocol traits and errors
- `crates/railgun-wasm` for thin WASM-facing bindings
- `crates/railgun-cli` for a minimal CLI surface

The repository is still in scaffolding stage. Favor small, architecture-preserving changes.

## External Rule Files

This repository currently does not contain `.cursorrules`, `.cursor/rules/`, or `.github/copilot-instructions.md`.
If any are added later, merge their guidance into your behavior.

## Architectural Directives

- Keep core crates free of vendor-specific integration dependencies.
- Put concrete integrations in adapter crates only when real feature work justifies them.
- Keep `railgun-wasm` thin; do not place protocol logic there.
- Keep `railgun-cli` thin; it must consume public library APIs.
- Prefer capability-based abstractions over vendor-shaped traits.
- Prefer typed domain models over raw strings, bytes, or maps.
- Keep defaults optional; do not hard-wire one major dependency stack.
- Do not add new crates unless a real boundary is needed.
- Every change should clearly belong to domain/core logic, binding logic, CLI/application logic, or future adapter logic.
- `railgun-types` stays small, stable, and reusable.
- `railgun-core` owns shared traits, errors, and protocol abstractions.
- `railgun-wasm` translates Rust APIs for JS/WASM consumers.
- `railgun-cli` exposes operational commands, not private internals.

## Build, Lint, And Test Commands

Run commands from the repository root.

Build:

```sh
cargo check
cargo build
cargo build -p railgun-cli
nix build .#default
```

The default Nix package builds the CLI package.

Format and lint:

```sh
cargo fmt --all
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo deny check
nix flake check
```

Workspace lint settings in `Cargo.toml` include `unsafe_code = "forbid"`, `missing_docs = "warn"`, clippy `all`, and clippy `pedantic`. `deny.toml` defines dependency policy. The Nix flake uses `crane` for Rust checks.

Tests:

```sh
cargo test --workspace
cargo test -p railgun-core
cargo test -p railgun-types
cargo test -p railgun-core test_name -- --exact --nocapture
cargo test -p railgun-core --test test_file
cargo test -p railgun-core module_name::test_name
```

There are currently no tests in the repository, but these are the expected commands once tests exist.

## Local Development Environment

If you use Nix:

```sh
nix develop
```

The dev shell provides a pinned Rust toolchain via `fenix` plus `cargo`, `clippy`, `rustfmt`, `rust-analyzer`, `cargo-deny`, `cargo-edit`, `cargo-watch`, and `nixfmt`.

## Rust Version And Edition

- Edition: `2024`
- MSRV: `1.85`

These are configured in the workspace and `clippy.toml`.

## Code Style Guidelines

Formatting:
- Always run `cargo fmt --all` after substantive Rust edits.
- Follow `rustfmt.toml`; do not hand-format against repository rules.
- Keep expressions and control flow readable; do not fight rustfmt.

Imports:
- Keep imports explicit and minimal.
- Prefer grouped imports when they improve clarity, for example `use railgun_types::{Address, ChainId, TxHash};`.
- In reusable/core code, prefer `core` over `std` where practical.
- Do not leave unused imports behind.
- Avoid wildcard imports unless there is a strong local reason.

Types and APIs:
- Public APIs should use domain types, not loose strings or unvalidated bytes.
- Add dedicated types for protocol concepts when semantic distinction matters.
- Prefer fallible constructors for validated values.
- Use `#[must_use]` on constructors, getters, and helpers where ignoring the value is likely a bug.
- Avoid exposing vendor-specific types from core crates.
- Do not shape core APIs around one downstream integration library.
- Values that should usually be typed include addresses, chain IDs, transaction hashes, commitments, nullifiers, Merkle roots, and proof artifacts.

Naming and errors:
- `snake_case` for functions, modules, locals, and fields
- `PascalCase` for structs, enums, traits, and type aliases
- `SCREAMING_SNAKE_CASE` for constants
- Trait names should describe capabilities, not vendors
- Error types should have clear domain names such as `ParseDomainError` or `RailgunError`
- Prefer typed error enums or structs over stringly failures
- Implement `Display` and `std::error::Error` for public error types
- Document public `Result`-returning items with a `# Errors` section
- Validate inputs at the boundary where they enter the domain model
- Avoid `unwrap` and `expect` in library code unless the invariant is strong and obvious

Documentation:
- Public items should have rustdoc comments.
- Explain invariants, validation rules, and the meaning of typed values.
- Keep comments focused on why or invariants, not on obvious syntax.

## Dependency, WASM, And CLI Rules

- Do not add heavy ecosystem dependencies to core crates casually.
- If a dependency represents an integration choice, it likely belongs in a future adapter crate.
- Keep defaults optional.
- Keep WASM code as a translation surface over Rust logic.
- Do not duplicate protocol behavior in `railgun-wasm`.
- Be explicit about serialization boundaries and JS-facing types.
- The CLI should remain narrow and operational.
- If the CLI needs behavior unavailable through public APIs, improve the library first.

## Before Adding Code

Answer these questions first:
1. Which crate should own this change?
2. Is this domain logic, binding logic, CLI logic, or future adapter logic?
3. Does this need a new typed value?
4. Does this introduce a dependency into the correct layer?
5. Will this design still make sense for Rust, WASM, and CLI consumers?

If the answer is unclear, refine the design before implementing.

## Expected Validation Before Finishing

Run the smallest relevant set, then prefer the full set for broader changes:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo check
cargo deny check
nix flake check
```

If you add tests, also run the smallest relevant `cargo test` command and then `cargo test --workspace` when reasonable.

## Agent Behavior Summary

- Make minimal changes that preserve architecture.
- Prefer typed, validated APIs.
- Keep core code portable and vendor-neutral.
- Keep WASM and CLI thin.
- Update docs when architecture or conventions change.
- Do not invent abstractions or crates before actual feature work justifies them.
