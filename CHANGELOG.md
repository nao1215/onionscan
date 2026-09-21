# Changelog

## Unreleased

### Changed

- Building from source now needs Go 1.26 or later (was 1.25). golang.org/x/net, x/sync and x/text, which this update takes, declare `go 1.26.0`, and Go 1.26 and 1.27 are the two releases the Go team still supports. Prebuilt binaries are unaffected.

## v0.2.3 - 2026-09-12

### Changed

- Dependencies updated (`github.com/nao1215/tornago` 0.4.0 to 0.4.1, `modernc.org/sqlite` 1.56.0 to 1.57.0, `github.com/golang/geo`, `github.com/go-errors/errors`, `github.com/fatih/color`, `github.com/spf13/pflag` and the tablewriter chain), holding `modernc.org/libc` at the version `modernc.org/sqlite` declares. The `go` directive stays at 1.25.0.
- The unit-test matrix runs the newest Go release alongside the go.mod floor, and the coverage and release jobs build with the current stable toolchain instead of the floor.
- Dependencies updated again on 2026-09-12: `modernc.org/sqlite` 1.58.0, `modernc.org/libc` 1.75.7, `github.com/mattn/go-runewidth` 0.0.30, `github.com/stretchr/testify` 1.12.1 and `github.com/jessevdk/go-flags` 1.6.1. The golang.org/x bumps are not taken: that family now declares `go 1.26.0`, and the floor here is 1.25.0.
- The E2E suite runs with atago v0.22.0. The five scenarios were run locally against a tornago-hosted onion service before the pin moved.

### Removed

- The Go Report Card badge. The service is retired and its badge now answers `go report: retired`, which is a line of README saying nothing about this repository.

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
