# Vision

This repository aims to provide a modular Rust implementation of the RAILGUN privacy system libraries.

The goal is to make it possible for developers to build wallets and other applications that interact with:

- RAILGUN smart contracts
- broadcasters
- Proof of Innocence infrastructure
- related protocol data, proofs, and local state

The project is built for both native Rust consumers and JavaScript consumers through WASM, including browser and Node environments.

## What We Are Building

We are building a protocol SDK.

That means this repository should provide:

- reusable library crates
- strong domain types and protocol modeling
- optional adapter crates for common integrations
- WASM bindings for JavaScript environments
- a small CLI for useful operational tasks such as key handling

## Who This Is For

This project is intended for developers who want to:

- build wallets on top of RAILGUN
- integrate RAILGUN into applications or services
- consume RAILGUN functionality from Rust directly
- consume RAILGUN functionality from browser or Node applications via WASM
- choose their own surrounding stack where possible

## Core Product Principles

### Typed By Default

Protocol concepts should be represented with explicit Rust types rather than raw strings or loosely structured values.

The type system should prevent common classes of misuse and make invalid states difficult to represent.

### Modular By Design

Consumers should be able to use only the parts of the system they need.

The repository should be organized into focused crates with clear responsibilities rather than a single monolithic package.

### Portable Across Runtimes

The same core protocol logic should power native Rust, WASM bindings, and the CLI.

Platform-specific surfaces should stay thin and should not become alternate implementations of the protocol.

### Integrations Are Optional

The project should provide sane defaults, but it must not require one major external stack.

Developers should be able to adopt default adapters or bring their own implementations when they need different provider, storage, or transport libraries.

### Safe Over Convenient

The project handles privacy-sensitive data, keys, and proof-related state.

Convenience APIs are valuable only when they do not erode correctness, safety, or clarity.

## Non-Goals

This repository is not intended to be:

- a full end-user wallet application
- a monolithic framework that dictates all surrounding infrastructure
- an SDK that hard-codes one EVM, transport, or storage library
- a dumping ground for issue-specific implementations without architectural discipline

## Success Criteria

The project is successful if it becomes straightforward for a developer to:

- construct typed RAILGUN interactions in Rust
- use the same underlying logic from WASM in browser or Node environments
- adopt only the crates and features they need
- choose default adapters or supply their own implementations
- build tooling and apps without fighting vendor lock-in or stringly typed APIs

## How This Vision Is Enforced

The rules that protect this direction are defined in `ARCHITECTURE_CONSTITUTION.md`.

That document is the source of truth for architectural constraints and must be followed by both human contributors and AI agents.
