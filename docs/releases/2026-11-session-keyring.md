# November 2026 release: opt-in Linux session authentication

This release adds explicit session-keyring authentication for Linux environments
where 1Password desktop-app integration cannot be used, including restricted
desktop agent environments. It includes PR #71.

## Changes

- Opt in with `--session-keyring`; select a dedicated CLI configuration with
  `--session-config`. Without the option, existing authentication is unchanged.
- Manage manual sign-in with `auth login`, `auth status`, and `auth logout`.
  Credentials reside in the OS session keyring and are sent only to internal
  `op` commands. Executed targets, plugins, and other external tools do not
  inherit authentication credentials.
- Resolve item references using `op read` in this mode. Desktop SDK, Developer
  Environment operations, and native Environment delegation are disabled or
  rejected while this option is enabled.
- Drain captured tool stdout and stderr concurrently to avoid false timeouts
  when tools produce output larger than the pipe buffer.

## Usage and compatibility

```sh
opz --session-keyring --session-config ~/.config/opz-manual auth login
opz --session-keyring --session-config ~/.config/opz-manual auth status
opz --session-keyring --session-config ~/.config/opz-manual run --vault VAULT ITEM -- COMMAND
```

No migration is required for existing users. The optional keyring mode is
Linux-only and requires an available Secret Service session collection. Manual
sessions expire; sign in again when needed. Session keyring storage is cleared
at logout. It does not isolate processes running as the same OS user or add
per-chat or per-vault authorization. Only run trusted target programs: they
receive the application secrets explicitly requested for execution.

The Linux implementation uses `secret-service` 6.0.0-rc.1 with encrypted
transport. This prerelease dependency avoids the unmaintained dependencies
pulled in by the older stable line; dependency policy checks pass.

## Validation

PR #71 passed subagent review after fixing a non-Linux clippy failure and a
large-output timeout defect. Local validation passed 194 unit tests, 30 hermetic
CLI tests, additional CLI/skill tests, Windows/macOS cross-target clippy,
dependency and release-policy checks, release build, and package publish dry-run.
Live Linux Desktop session status and wrapper interoperability were verified.
Native interactive login/logout have hermetic coverage but were not exercised
against a real account during this release preparation.

Publication requires Linux/macOS/Windows CI and release-policy checks, followed
by the repository's CalVer, cargo-dist, crates.io Trusted Publishing, archive
smoke, and cargo-binstall verification workflows. Their final results are
recorded in the published GitHub release notes.

## Publication recovery

The initial `2026.11.0` crate was published, but its cargo-dist release could not
complete because the default macOS 14 ARM runner was retired. The follow-up
release explicitly selects macOS 15 ARM and Intel runners while preserving
cargo-dist 0.31.0. The existing crate and immutable tag are not overwritten.
