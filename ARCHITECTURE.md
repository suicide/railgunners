# Architecture

This document explains how the repository should be shaped in practice.

The binding architectural rules live in `ARCHITECTURE_CONSTITUTION.md`. This document expands those rules into a concrete workspace model and implementation approach.

## Architectural Overview

The repository should be organized as a layered Cargo workspace with a strict dependency direction:

`domain/core -> adapters -> bindings/apps`

In practice, that means:

- core crates define types, protocol logic, validation, errors, and capability traits
- adapter crates implement those traits using concrete third-party libraries
- binding crates expose core behavior to other runtimes such as WASM
- application crates such as the CLI consume public APIs from the library crates

No lower layer may depend on a higher one.

## Recommended Workspace Layout

The exact crate set can evolve, but the initial workspace should follow a shape close to this:

```text
.
├── crates/
│   ├── railgun-types/
│   ├── railgun-core/
│   ├── railgun-wallet/
│   ├── railgun-chain/
│   ├── railgun-storage/
│   ├── railgun-broadcaster/
│   ├── railgun-poi/
│   ├── railgun-wasm/
│   └── railgun-cli/
├── adapters/
│   ├── alloy/
│   └── indexeddb/
└── docs and top-level project files
```

This layout communicates intent clearly:

- `crates/` contains first-party domain, protocol, binding, and app surfaces
- `adapters/` contains optional integrations with external ecosystems

## Layer Responsibilities

### `railgun-types`

This crate should contain shared domain types and validated primitives used across the workspace.

Examples include:

- addresses
- chain IDs
- hashes
- Merkle roots
- nullifiers
- commitments
- token identifiers
- typed wrappers for protocol artifacts

This crate should stay small, stable, and heavily reused.

### `railgun-core`

This crate should define the most broadly shared protocol abstractions and logic.

Examples include:

- core errors
- serialization traits or helpers
- protocol capability traits
- shared validation rules
- common request or response models that are not tied to one integration

`railgun-core` should not become a grab bag. If a subsystem develops meaningful complexity, it should graduate into its own crate.

### Domain-Specific Crates

Crates such as `railgun-wallet`, `railgun-chain`, `railgun-storage`, `railgun-broadcaster`, and `railgun-poi` should each own one clear area of responsibility.

Examples:

- `railgun-wallet` for wallet-facing domain workflows and state transitions
- `railgun-chain` for chain interaction traits and chain-facing models
- `railgun-storage` for storage traits and storage data modeling
- `railgun-broadcaster` for broadcaster-facing models and client traits
- `railgun-poi` for Proof of Innocence models and capability traits

The exact split can change, but each crate must have a narrow purpose.

### Adapter Crates

Adapters implement concrete integrations without polluting core APIs.

Examples:

- `adapters/alloy` for EVM chain access using `alloy`
- `adapters/indexeddb` for browser persistence using IndexedDB-based tooling

Adapter crates may include convenience helpers, but those helpers must not define the required shape of core APIs.

### `railgun-wasm`

This crate should expose a JavaScript-friendly surface while remaining a thin translation layer.

It should be responsible for:

- exported WASM functions and classes
- JS-friendly error translation
- async interop and boundary handling
- serialization or conversion at the FFI edge

It should not contain alternate business logic.

### `railgun-cli`

This crate should expose a focused command-line interface over public workspace APIs.

Initial CLI responsibilities should remain simple, such as:

- key generation
- key inspection
- address derivation
- validation or encoding helpers

If the CLI requires logic that is unavailable through public crates, the library surface should be improved rather than bypassed.

## Capability Boundaries

The workspace should abstract stable capabilities rather than third-party libraries.

Typical capability boundaries include:

- chain provider
- contract caller
- signer or key source
- storage backend
- broadcaster client
- Proof of Innocence client
- transport client
- proving backend

Traits at these boundaries should be designed around what the SDK needs, not around mirroring one vendor's API.

## Public API Design Rules

Public APIs should:

- accept and return domain types rather than loosely typed values
- validate external input early
- avoid leaking vendor-specific types from core crates
- expose explicit errors rather than generic string failures
- preserve room for multiple implementations

Builders are appropriate when workflows have multiple stages, but built artifacts should be validated and typed.

## Defaults and Features

The project should provide sane defaults without making them mandatory.

That means:

- default integrations should live in adapter crates or feature-gated modules
- core crates should compile without heavyweight ecosystem bindings where possible
- features should be used to separate optional surfaces such as `wasm`, `cli`, and concrete integrations

Feature flags should reduce coupling, not hide architectural confusion.

## Serialization and Versioning

Serialization should be treated as part of the protocol surface.

Important data models should have:

- explicit format choices
- documented encoding expectations
- compatibility considerations
- versioning when interpretation can change

This matters especially at boundaries between:

- Rust and WASM
- library crates and storage
- SDK and network services

## Security Considerations

The architecture should assume that the codebase handles privacy-sensitive and secret material.

Design implications include:

- careful separation of public and private data
- explicit key-handling flows
- minimizing raw secret exposure in APIs
- avoiding hidden persistence or logging of sensitive values
- keeping security-sensitive workflows visible in the type system where practical

## Decision Checklist

Before adding a new module, crate, or dependency, contributors should ask:

1. Which layer does this belong to?
2. Is this a domain concept, capability trait, adapter implementation, binding concern, or app concern?
3. Does this introduce a vendor dependency into the wrong layer?
4. Does this preserve strong typing at the public boundary?
5. Will this design still make sense for Rust, WASM, and CLI consumers?

If any answer is unclear, the design should be refined before implementation.
