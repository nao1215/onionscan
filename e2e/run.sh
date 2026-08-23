#!/usr/bin/env bash
# Build OnionScan and its tornago-backed onion fixture, then execute the real
# CLI through atago. The fixture owns both the onion service and the Tor SOCKS
# proxy, so the suite never depends on a public third-party onion site.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"

if ! command -v atago >/dev/null 2>&1; then
	echo "e2e: atago is not installed; see https://github.com/nao1215/atago" >&2
	exit 127
fi
if ! command -v tor >/dev/null 2>&1; then
	echo "e2e: tor is not installed" >&2
	exit 127
fi

E2E_TMP="$(mktemp -d "${TMPDIR:-/tmp}/onionscan-e2e.XXXXXX")"
cleanup() {
	chmod -R u+w "$E2E_TMP" >/dev/null 2>&1 || true
	rm -rf "$E2E_TMP"
}
trap cleanup EXIT

mkdir -p "$E2E_TMP/bin"

COVER_FLAGS=()
if [ -n "${COVER:-}" ]; then
	COVER_FLAGS=(-cover -covermode=atomic -coverpkg=./...)
	echo "e2e: building coverage-instrumented OnionScan"
fi

echo "e2e: building OnionScan and the tornago onion service"
(
	cd "$REPO_ROOT"
	go build "${COVER_FLAGS[@]}" \
		-ldflags '-X main.version=v0.0.0-e2e -X main.commit=e2e -X main.date=1970-01-01T00:00:00Z' \
		-o "$E2E_TMP/bin/onionscan" ./cmd/onionscan
	go build -o "$E2E_TMP/bin/onionscan-e2e-site" ./e2e/tornago-site
)

export PATH="$E2E_TMP/bin:$PATH"
atago run --parallel 1 "$@" "$SCRIPT_DIR/atago"
