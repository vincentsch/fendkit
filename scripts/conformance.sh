#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
# The scorer splits fixture commands on spaces, including their paths.
tmp=$(mktemp -d /tmp/conformline-conformance.XXXXXXXX)
trap 'rm -rf "$tmp"' EXIT
CGO_ENABLED=0 go build -trimpath -o "$tmp/conformline" ./cmd/conformline
code=0
"$tmp/conformline" demo --offline --out "$tmp/demo" > "$tmp/demo.log" || code=$?
if [ "$code" -ne 11 ]; then cat "$tmp/demo.log"; echo "Offline demo: expected exit 11, got $code" >&2; exit 1; fi
root="$tmp/demo/acme-booking"
go run github.com/vincentsch/rungrad/cmd/rungrad@v0.3.2 score "$tmp/conformline" \
 --manifest auto --strict \
 --read "incident list --dir $root" \
 --mutate "incident new --type exploited-vulnerability --aware 2026-10-01T09:15:00Z --title test --dir $root" \
 --not-found "incident show inc-99 --dir $root"
