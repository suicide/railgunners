# Contributing

Thank you for contributing.

This repository is intended to be developed by both human contributors and AI agents. The goal of this document is to keep contributions consistent with the project's architecture and long-term direction.

Before making changes, read `ARCHITECTURE_CONSTITUTION.md` and `ARCHITECTURE.md`.

## Working Principles

- preserve modularity
- prefer typed domain models over stringly shortcuts
- keep vendor-specific code at the edges
- treat WASM and CLI as first-class consumers of library APIs
- favor explicitness over convenience when security or protocol correctness is involved

## Contribution Flow

When working on an issue or feature:

1. Identify which layer owns the change.
2. Identify the domain types involved.
3. Identify the capability boundary, if any.
4. Decide whether the work belongs in a core crate, adapter crate, binding crate, or application crate.
5. Implement the smallest change that preserves the architectural rules.

If the correct layer is unclear, stop and refine the design before writing code.

## Rules for Developers

### Preserve Layer Boundaries

Do not add adapter-specific dependencies to core crates.

Examples of what not to do:

- adding `alloy` directly to a core protocol crate
- making storage abstractions assume IndexedDB semantics
- placing protocol logic inside the WASM layer
- teaching the CLI private workflows that bypass public library APIs

### Prefer Domain Types

Do not expose raw strings, byte arrays, or untyped maps for protocol concepts unless the boundary truly requires it.

When a value has protocol meaning, use a dedicated type and validate it.

### Keep Defaults Optional

It is good to provide easy starting points for users, but those defaults must not become hidden requirements.

If a new integration is added, keep it isolated to an adapter crate or feature-gated module.

### Keep Bindings Thin

WASM bindings should translate and expose existing logic. They should not become a second implementation of the protocol.

### Keep the CLI Honest

If the CLI needs functionality that library users cannot access, improve the library rather than bypassing it.

## Rules for AI Agents

AI-generated changes must follow the same architectural rules as human-written code.

When implementing a task, AI should:

1. Determine the correct architectural layer first.
2. Reuse or extend domain types before introducing raw values.
3. Avoid adding external dependencies to core crates unless clearly justified.
4. Keep vendor-specific logic in adapter crates.
5. Keep WASM code as a binding surface, not a business-logic surface.
6. Avoid convenience-driven shortcuts that weaken typing or modularity.

If a requested change conflicts with the architecture constitution, the AI should prefer the constitution and surface the conflict clearly.

## Adding New Dependencies

When proposing a new dependency, contributors should be able to explain:

- why it is needed
- which crate should own it
- why that layer is the correct place
- whether it is optional or mandatory
- whether it affects Rust-only, WASM-only, or shared code

Dependencies that shape integration behavior should normally live in adapter crates.

## Adding New Crates or Modules

When adding a crate or major module:

- give it a narrow responsibility
- document its layer and purpose
- avoid overlapping ownership with existing crates
- prefer moving reusable concepts into shared domain crates only when there is real reuse

Do not create a new crate just because a file feels large. Create one when it clarifies boundaries.

## Public API Expectations

Public APIs should aim to be:

- strongly typed
- validated at boundaries
- explicit about failure
- compatible with modular reuse
- reasonable to expose through WASM and CLI surfaces

Avoid designing APIs around the shape of one external vendor library.

## Documentation Expectations

When making architectural or cross-cutting changes, update the relevant docs.

At minimum, contributors should keep aligned:

- `ARCHITECTURE_CONSTITUTION.md`
- `ARCHITECTURE.md`
- `VISION.md`
- `CONTRIBUTING.md`

If code changes require new conventions, document them close to the affected crate as well.

## Scope Discipline

Issues will describe features over time. Contributors should implement the requested feature without turning unrelated assumptions into architecture.

If a feature reveals a missing abstraction, add the abstraction carefully. If it only needs one concrete implementation for now, avoid pretending there are many unless the boundary is already clear.

## When In Doubt

Prefer the option that is:

- more typed
- more modular
- less coupled to vendor libraries
- easier to reuse from Rust, WASM, and CLI
- safer for secrets and privacy-sensitive state

If there is still uncertainty, resolve it in architecture first and implementation second.
