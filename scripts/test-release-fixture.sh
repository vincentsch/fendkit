#!/usr/bin/env bash
# Sourced by release consumers. Each caller owns its fixture and server.
start_release_fixture() {
 fixture_root=$(mktemp -d "${TMPDIR:-/tmp}/fendkit-release.XXXXXXXX")
 fixture_server=
 trap stop_release_fixture EXIT
 trap 'exit 130' INT
 trap 'exit 143' TERM
 mkdir -p "$fixture_root/releases/latest/download" "$fixture_root/releases/download/v0.1.0"
 cp dist/fendkit-* dist/checksums.txt "$fixture_root/releases/latest/download/"
 cp dist/fendkit-* dist/checksums.txt "$fixture_root/releases/download/v0.1.0/"
 # Bind port zero, then publish the chosen port without a reserve/rebind race.
 python3 -u -m http.server --bind 127.0.0.1 --directory "$fixture_root" 0 > "$fixture_root/server.log" 2>&1 &
 fixture_server=$!
 fixture_port=
 for attempt in $(seq 1 100); do
  fixture_port=$(sed -n 's/.* port \([0-9]*\) .*/\1/p' "$fixture_root/server.log" | head -1)
  if [ -n "$fixture_port" ] && curl -fsS "http://127.0.0.1:$fixture_port/releases/latest/download/checksums.txt" -o /dev/null; then break; fi
  if ! kill -0 "$fixture_server" 2>/dev/null; then echo 'Release fixture server stopped' >&2; return 1; fi
  sleep 0.05
 done
 [ -n "$fixture_port" ] || { echo 'Release fixture server did not start' >&2; return 1; }
 export FENDKIT_RELEASES_URL="http://127.0.0.1:$fixture_port/releases"
}

stop_release_fixture() {
 if [ -n "${fixture_server:-}" ]; then
  kill "$fixture_server" 2>/dev/null || true
  wait "$fixture_server" 2>/dev/null || true
 fi
 if [ -n "${fixture_root:-}" ]; then rm -rf "$fixture_root"; fi
}
