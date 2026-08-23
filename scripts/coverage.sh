#!/usr/bin/env bash
# Merge package-level unit coverage with runtime coverage from the real CLI
# exercised by atago. Both producers use atomic covdata so Go can combine them
# into one coverage.out consumed by octocov and local tooling.
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

COVERAGE_ROOT="$REPO_ROOT/.coverage"
rm -rf "$COVERAGE_ROOT"
mkdir -p "$COVERAGE_ROOT/unit" "$COVERAGE_ROOT/e2e" "$COVERAGE_ROOT/merged"

echo ">> unit coverage"
go test -short -count=1 -cover -covermode=atomic -coverpkg=./... ./... \
	-args -test.gocoverdir="$COVERAGE_ROOT/unit"

echo ">> atago E2E coverage"
COVER=1 GOCOVERDIR="$COVERAGE_ROOT/e2e" "$REPO_ROOT/e2e/run.sh"

echo ">> merge unit and E2E coverage"
go tool covdata merge -i="$COVERAGE_ROOT/unit,$COVERAGE_ROOT/e2e" -o="$COVERAGE_ROOT/merged"
go tool covdata textfmt -i="$COVERAGE_ROOT/merged" -o="$REPO_ROOT/coverage.out"
go tool cover -func=coverage.out | tail -n 1
go tool cover -html=coverage.out -o coverage.html
echo ">> wrote coverage.out and coverage.html"
