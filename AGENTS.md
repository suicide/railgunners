# AGENTS.md

`railgunners` is the RAILGUN Rust SDK: protocol libraries, thin WASM bindings, and a thin CLI.

## Verify

- Enter the dev shell with `nix develop`. Commands and CI coverage are in `README.md` under Development.
- Use crate-scoped commands while iterating, and workspace-wide commands when the change is shared.
- A change is not done until the smallest relevant crate checks pass. Use `nix flake check` before finishing broad or cross-cutting work.

## Hard rules

- `ARCHITECTURE_CONSTITUTION.md` and `CONTRIBUTING.md` are binding. If either conflicts with a request, surface the conflict; do not bypass it.
- Keep protocol logic out of `railgunners-wasm` and `railgunners-cli`. Do not add vendor-specific dependencies to core crates.

## Docs

- `ARCHITECTURE_CONSTITUTION.md` — binding rules
- `ARCHITECTURE.md` — layering and crate responsibilities
- `CONTRIBUTING.md` — contribution flow and agent rules
- `VISION.md` — goals and non-goals
- `README.md` — workspace status, crate list, and CLI usage
- `docs/` — topic notes

Do not grow this file with command catalogs or implementation notes. Update the owning doc instead.
