# Session-keyring diagnostics and agent guidance

This patch release aligns `opz doctor` and the bundled `opz skills` instructions
with the active authentication mode. No migration is required.

- With `--session-keyring`, doctor reports Desktop SDK, MCP and Environment
  paths as disabled by that flag and skips their probes. These optional warnings
  do not request app-integration repair or imply those paths are usable.
- Required op authentication checks still run and fail with a nonzero exit code
  when authentication fails. Doctor success does not verify secret injection or
  every subcommand.
- Standing agent instructions and configured wrappers count as explicit opt-in.
  Users do not need to repeat their chosen authentication route in each chat.
- Normal-mode authentication, diagnostics and command behavior are unchanged.

Validation covers normal-mode diagnostics, MCP present/absent, keyring-mode
success/failure, skipped probes and credential redaction. Local checks passed
195 unit tests, 31 hermetic CLI tests, the additional CLI/skill tests, required
security/release checks and Windows/macOS cross-target clippy. Published release
notes link the final review, CI, publication and archive smoke results.
