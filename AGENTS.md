# Repository Guidelines

## Project Structure & Module Organization

- `src/bin/killswitch.rs`: CLI entry point (delegates to `killswitch::cli`).
- `src/cli/`: Argument parsing (clap), dispatch, and user-facing actions.
- `src/killswitch/`: Core domain logic (network detection, pf rule generation).
- Root docs: `IMPLEMENTATION.md`.
- CI/config: `.github/workflows/` (format/lint/test/coverage), `.justfile` (local automation).

## Build, Test, and Development Commands

Prefer `just` (see `.justfile`):

- `just test`: Runs format check, clippy, and `cargo test`.
- `just fmt`: Checks formatting via `cargo fmt --all -- --check`.
- `just clippy`: Lints all targets/features via `cargo clippy --all-targets --all-features`.

Equivalent Cargo commands:

- `cargo build`: Builds the crate.
- `cargo test`: Runs unit tests (mostly inline `#[test]` modules).
- `cargo run -- --help`: Runs the CLI and shows flags (use `--print` to avoid applying pf rules).

## Coding Style & Naming Conventions

- Rust style: run `cargo fmt` (CI enforces formatting).
- Lints are strict: `Cargo.toml` denies warnings and uses `clippy::pedantic`; avoid `unwrap()`, `expect()`, and `panic!` in production code.
- Naming: modules/functions `snake_case`, types/traits `CamelCase`, constants `SCREAMING_SNAKE_CASE`.
- Prefer explicit error handling with `anyhow::Result` and `?`.

## Testing Guidelines

- Run `just test` before pushing.
- Tests live alongside code (e.g., `src/cli/**`, `src/killswitch/**`).
- Test names follow `test_<component>_<scenario>`; only relax lints in tests when needed (e.g., `#[allow(clippy::unwrap_used)]`).

## Commit & Pull Request Guidelines

- Branching: use git-flow; open PRs against `develop` (not `main`). See `.github/PULL_REQUEST_TEMPLATE.md`.
- Commit messages in this repo are short and action-oriented (e.g., “fix workflow”, “update dependencies”, “bump version to X”). Keep the subject imperative and include an issue/PR reference when relevant.
- PRs should include: what/why summary, how it was tested (`just test` output or notes), and any behavior/safety impact (killswitch changes can affect networking).
