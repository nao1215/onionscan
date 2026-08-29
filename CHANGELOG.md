# Changelog

## Unreleased

### Changed

- Dependencies updated (`github.com/nao1215/tornago` 0.4.0 to 0.4.1, `modernc.org/sqlite` 1.56.0 to 1.57.0, `github.com/golang/geo`, `github.com/go-errors/errors`, `github.com/fatih/color`, `github.com/spf13/pflag` and the tablewriter chain), holding `modernc.org/libc` at the version `modernc.org/sqlite` declares. The `go` directive stays at 1.25.0.
- The unit-test matrix runs the newest Go release alongside the go.mod floor, and the coverage and release jobs build with the current stable toolchain instead of the floor.

## v0.2.2 - 2026-08-23

### Fixed

- Prevent canceled non-HTTP protocol scans from retaining blocked dial goroutines by requiring context-aware proxy dialers.
- Inject version, commit, and build date into the CLI variables used by release binaries.
- Make Tor-backed E2E coverage resilient to transient circuit construction failures.

### Changed

- Add a tornago-hosted onion fixture and five atago scenarios covering version, init, scan, compare, batch, external Tor, and embedded Tor behavior.
- Combine unit and E2E coverage across production packages and raise the enforced threshold to 95%.
- Expand boundary and failure-path tests across the CLI, crawler, database, deanonymization analyzers, model, pipeline, protocols, reports, and Tor client.
- Migrate the GoReleaser configuration to schema version 2 and the current Homebrew cask format.
- Use the standard library SHA-3 implementation for Tor v3 checksum validation.

### Dependencies

- Update actions/checkout and actions/setup-go to version 7.
- Update github.com/nao1215/markdown to 1.0.0.
- Update modernc.org/sqlite to 1.56.0.
- Update golang.org/x/crypto to 0.55.0, golang.org/x/net to 0.58.0, golang.org/x/sync to 0.22.0, and golang.org/x/text to 0.41.0.

[Full changes](https://github.com/nao1215/onionscan/compare/v0.2.1...v0.2.2)
