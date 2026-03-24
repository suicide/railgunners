# Architecture Constitution

This document defines the non-negotiable architectural rules for this repository.

It exists to keep issue-driven development coherent, preserve modularity, and give both human contributors and AI agents the same durable guardrails.

If a feature request, pull request, code generation step, or refactor conflicts with this document, this document wins unless it is explicitly updated.

## 1. Project Identity

This repository is a RAILGUN protocol SDK implemented in Rust with first-class WASM support and a supporting CLI.

The project provides library building blocks for wallets and other applications that interact with:

- RAILGUN smart contracts
- broadcasters
- Proof of Innocence infrastructure
- related protocol data, proofs, and local state

This repository is not an end-user wallet application, opinionated backend product, or a monolithic framework that requires one external stack.

## 2. Primary Goals

Every architectural decision should optimize for these goals:

1. Strongly typed protocol modeling
2. Modular composition
3. Cross-platform support for native Rust, browsers, and Node via WASM
4. Optional integrations with sane defaults
5. Long-term maintainability under issue-driven development
6. Security-conscious handling of secrets, proofs, and protocol state

## 3. Layering Rules

The codebase is organized into architectural layers. Every module and crate must belong clearly to one layer.

### 3.1 Domain and Core

Domain and core crates contain:

- protocol types
- validation logic
- state transitions
- serialization rules
- errors
- traits for external capabilities

Domain and core crates must not depend on ecosystem-specific integration libraries such as `alloy`, browser storage APIs, IndexedDB wrappers, or specific HTTP clients unless a dependency is unavoidable and belongs to the protocol itself.

### 3.2 Adapter Layer

Adapter crates contain concrete integrations with external libraries and platforms.

Examples include:

- EVM client integrations
- storage backend implementations
- transport implementations
- default broadcaster or POI clients

Adapters depend on core crates. Core crates must never depend on adapters.

### 3.3 Binding Layer

Binding crates expose existing Rust functionality to other runtimes such as WASM.

Bindings must stay thin. They should translate types, errors, and async boundaries, but they must not become alternate homes for protocol logic.

### 3.4 Application Layer

Application surfaces such as the CLI consume public library APIs.

The CLI must not bypass core library boundaries by duplicating logic or reaching into private implementation details that external users cannot access.

## 4. Capability-Based Abstractions

This project abstracts stable capabilities, not vendor-specific APIs.

Good abstraction seams include:

- chain provider or contract caller
- signer or key source
- storage backend
- transport client
- broadcaster client
- Proof of Innocence client
- proving backend

Contributors must not create traits merely to hide the name of a dependency. A trait is justified only when it models a real capability that multiple implementations can provide.

## 5. Dependency Policy

### 5.1 Core Dependency Policy

Core crates should prefer small, stable, broadly useful dependencies.

Core crates must not take hard dependencies on major ecosystem integration stacks when those stacks are optional implementation choices.

Examples of libraries that belong at the edge rather than in core include:

- `alloy`
- IndexedDB-specific libraries
- browser-only APIs
- runtime-specific transport clients

### 5.2 Default Implementations

This repository may provide default implementations to improve developer experience.

However:

- defaults must remain optional
- defaults should live in adapter crates or clearly feature-gated modules
- defaults must not define the shape of core public APIs

The project should be easy to start with, but it must not silently lock consumers into one dependency stack.

## 6. Type System Policy

This project is compiler-driven. Public APIs should use the type system to prevent invalid states and reduce protocol misuse.

### 6.1 Required Type Discipline

Protocol concepts should be represented by dedicated types whenever validation or semantic distinction matters.

Examples include:

- addresses
- chain identifiers
- transaction hashes
- nullifiers
- commitments
- Merkle roots
- token identifiers
- encrypted payloads
- proof artifacts
- block numbers and other protocol-specific counters where confusion is costly

### 6.2 Avoid Stringly APIs

Public APIs must avoid using raw `String`, `&str`, `Vec<u8>`, or untyped maps for validated domain concepts unless there is a strong interoperability reason and the boundary is clearly documented.

### 6.3 Validation

Constructors and conversions should be fallible when invalid input is possible.

Unchecked constructors must be rare, explicit, and justified.

## 7. Cross-Platform Rule

Rust library code is the source of truth.

Native Rust, WASM, and CLI surfaces should all rely on the same underlying domain and protocol logic.

Contributors must not fork business logic across runtimes unless there is a documented platform-specific constraint.

If behavior must differ across runtimes, the difference must be isolated behind traits, features, or bindings rather than duplicated protocol rules.

## 8. WASM Rule

WASM is a first-class target, not an afterthought.

That means:

- bindings must be intentionally designed
- async behavior must be clear
- serialization boundaries must be stable
- browser and Node use cases must both be considered where relevant

At the same time, WASM ergonomics must not force low-quality core Rust APIs. The correct approach is to keep core APIs sound and add binding-layer translations where needed.

## 9. CLI Rule

The CLI exists to expose a small, useful operational surface over the SDK.

It is expected to support basic tasks such as:

- key generation and inspection
- derivation and validation helpers
- protocol encoding or decoding helpers
- selected offline utility workflows

The CLI must remain a thin consumer of library APIs. If the CLI needs functionality that is not available through public crates, contributors should first improve the library surface.

## 10. Serialization and Versioning Rule

Protocol evolution must be explicit.

The project must version and document any data format or protocol behavior whose interpretation may change over time, including when relevant:

- serialized domain types
- proof artifacts
- note formats
- transaction payloads
- storage records
- network-facing request and response models

Silent format drift is not acceptable.

## 11. Security Rule

Security-sensitive material requires explicit handling.

Contributors must design APIs so that secrets and privacy-critical data are difficult to misuse accidentally.

This includes:

- minimizing raw secret exposure
- preferring typed wrappers for sensitive values
- avoiding convenience APIs that encourage unsafe persistence or logging
- separating public metadata from private state where possible

Convenience must not override safety.

## 12. Crate Placement Rule

Before adding code, contributors should be able to answer all of the following:

1. Is this domain logic, adapter logic, binding logic, or application logic?
2. Which public types does it operate on?
3. Which capability boundary does it cross?
4. Does it introduce an external dependency into the correct layer?

If those questions cannot be answered clearly, the design likely needs refinement before implementation.

## 13. Guidance for Developers and AI

When implementing a feature:

1. Start from the domain model and required types.
2. Identify whether the work belongs in core, an adapter, a binding, or the CLI.
3. Introduce or refine capability traits only when a real boundary exists.
4. Keep defaults optional.
5. Preserve compatibility with native Rust and WASM unless the feature is intentionally platform-specific.
6. Prefer explicit, validated APIs over convenience shortcuts.

When uncertain, choose the design that keeps protocol logic more typed, more modular, and less coupled to vendor libraries.

## 14. Amendment Rule

This constitution is intentionally durable but not immutable.

If the project needs to change these rules, contributors should update this document explicitly rather than violating it implicitly in code.
