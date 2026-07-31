#!/usr/bin/env bash
# Trace-first curl probe — thin wrapper around docker-curl.sh (same pattern as
# docker-7zz, plus stderr / unknown-BSD capture under .tmp/kh-curl-probe/).
#
# Usage:
#   ./scripts/docker-curl-probe.sh --version
#   ./scripts/docker-curl-probe.sh -sS -o /Volumes/linux/out/body http://example.com/
#
# Equivalent:
#   KH_CURL_PROBE=1 ./scripts/docker-curl.sh …

set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export KH_CURL_PROBE=1
exec "$ROOT/scripts/docker-curl.sh" "$@"
