# Testing

How each kind of test in this repository is run, what it covers and where it runs in CI. The README lists the bug classes each one catches.

## Unit tests

```shell
make test
```

The Go tests of every package, with `-short`, which skips the opt-in real-Tor integration tests. CI runs them on Linux, macOS and Windows with the Go version in `go.mod` and the latest Go (`.github/workflows/unit_test.yml`).

## End-to-end tests

```shell
make e2e
```

[atago](https://github.com/nao1215/atago) runs the real `onionscan` binary from the scenarios in `e2e/atago/`. `e2e/run.sh` builds the binary and a fixture that serves a local HTTP site as an ephemeral Tor v3 onion service through [tornago](https://github.com/nao1215/tornago), so a scan never reaches a public onion site. It needs `tor` on `PATH`.

`make coverage` runs the unit tests and the E2E suite with coverage-instrumented binaries and writes one profile; CI runs it on every pull request (`.github/workflows/coverage.yml`).

The real-Tor Go integration tests kept for focused debugging are opt-in:

```shell
make test-integration
```

## Snapshot tests

`e2e/atago/compare-snapshot.atago.yaml` writes a fixed scan history with `bench/gendb` (two scans of 30 findings, three new and three resolved) and pins the output of `onionscan compare` in text, JSON and Markdown, and of `compare --list`, to the files in `e2e/atago/snapshots/`. atago replaces the scan dates with a placeholder. The suite needs neither Tor nor the network and runs with `make e2e`. After an intended change of the output, put a fresh `onionscan` and `onionscan-e2e-gendb` (built from `./bench/gendb`) on `PATH`, refresh the files and review the diff:

```shell
atago snapshot update e2e/atago/compare-snapshot.atago.yaml
```

## Property-based and metamorphic tests

Written with [rapid](https://github.com/flyingmutant/rapid). Every `go test` draws 100 cases per property; the nightly `rapid properties` job of `.github/workflows/fuzz.yml` draws 100 000. A failure prints the seed and writes the case under the package's `testdata/rapid/`.

| File | Properties |
|---|---|
| `cmd/onionscan/compare_property_test.go` | `compare` reports exactly the findings only in the current scan as new, only in the previous scan as resolved, and the rest as unchanged; lists them in report order; finds no change between a scan and itself. Metamorphic: comparing the scans the other way round swaps new and resolved and reverses the risk direction. |
| `internal/log/secure_handler_property_test.go` | No value under a sensitive key reaches the text or JSON log, whether it arrives on the record, through `Logger.With`, in a group or behind a `slog.LogValuer`; values under ordinary keys are kept. |

```shell
go test ./cmd/onionscan ./internal/log -run '^TestProperty' -rapid.checks=100000
```

## Fuzzing

`go test` runs every `Fuzz*` target over its seed corpus and `testdata/fuzz/`. `.github/workflows/fuzz.yml` discovers the targets and fuzzes each for five minutes every night.

| Target | Input |
|---|---|
| `FuzzNormalizeAddress`, `FuzzComputeV3AddressFromPublicKey`, `FuzzExtractAddresses` (`internal/tor/onion_test.go`) | Onion addresses typed by a user and found in page text |
| `FuzzParserParse` (`internal/crawler/crawler_test.go`) | Crawled HTML |

```shell
go test -run '^$' -fuzz '^FuzzNormalizeAddress$' -fuzztime 1m ./internal/tor
```

## Mutation testing

[gremlins](https://github.com/go-gremlins/gremlins) v0.6.0 changes one expression at a time and reruns the tests; a mutant that no test notices (lived) points at code whose result nothing checks. `.github/workflows/mutation.yml` mutates the whole module every Sunday and, on a pull request, only the lines it changes. Each mutant runs under a 4 GiB memory cap so a mutant that allocates without bound is killed instead of taking the runner down.

```shell
ulimit -v 4194304
gremlins unleash --workers 2 --timeout-coefficient 30 .
```

Baseline, 2026-11-19, the whole module: 756 killed, 170 lived, 139 not covered, test efficacy (killed / (killed + lived)) 81.64%, mutator coverage 86.95%. The most lived mutants are in `internal/report/markdown.go`, `internal/pipeline/steps.go`, `internal/deanon/pdf.go`, `internal/deanon/social.go` and `internal/crawler/spider.go`. The score is a record to compare later runs with, not a gate: some lived mutants are equivalent to the original code.

## Benchmarks

```shell
make bench
make bench-compare
```

[himorime](https://github.com/nao1215/himorime) measures the binary end to end from `bench/himorime.yaml`. On a pull request `.github/workflows/bench.yml` builds the base and the head and measures them in interleaved rounds on the same runner; see `bench/README.md`.
