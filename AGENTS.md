# AGENTS.md

`railgunners` is the RAILGUN Rust SDK: protocol libraries, thin WASM bindings, and a thin CLI. If this file conflicts with `ARCHITECTURE_CONSTITUTION.md`, the constitution wins. Surface the conflict; do not bypass it.

## Verify

- Enter the dev shell with `nix develop`. Commands and CI coverage are in `README.md` under Development.
- Use crate-scoped commands while iterating, and workspace-wide commands when the change is shared.
- A change is not done until the smallest relevant crate checks pass. Use `nix flake check` before finishing broad or cross-cutting work.

## Hard rules

- Preserve layering: `core/domain -> adapters -> bindings/apps`. Keep vendor-specific integrations out of core crates.
- Keep `railgunners-wasm` and `railgunners-cli` thin. New CLI behavior goes into public library APIs first.
- Prefer typed domain models and fallible validation at boundaries. Do not expose secrets or privacy-sensitive material through convenience APIs.
- Prefer `core` over `std` in reusable core code where practical. Avoid new crates or heavy dependencies unless a real boundary justifies them.
- Prefer module-scoped names over long flat names. See `CONTRIBUTING.md`.
- No branch or commit-message convention is documented. Do not invent one.

## Docs

- `ARCHITECTURE_CONSTITUTION.md` — binding rules
- `ARCHITECTURE.md` — layering and crate responsibilities
- `CONTRIBUTING.md` — contribution flow and agent rules
- `VISION.md` — goals and non-goals
- `README.md` — workspace status, crate list, and CLI usage
- `docs/` — topic notes

Do not grow this file with command catalogs or implementation notes. Update the owning doc instead.
