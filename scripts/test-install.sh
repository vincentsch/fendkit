#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/test-release-fixture.sh
start_release_fixture
export INSTALL_DIR="$fixture_root/install with spaces"
unset CONFORMLINE_VERSION
bash install.sh > "$fixture_root/latest.log"
"$INSTALL_DIR/conformline" --version
export CONFORMLINE_VERSION=v0.1.0
bash install.sh > "$fixture_root/pinned.log"
"$INSTALL_DIR/conformline" --version
os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$(uname -m)" in x86_64|amd64) arch=amd64 ;; arm64|aarch64) arch=arm64 ;; esac
asset="conformline-$os-$arch"
release="$fixture_root/releases/download/v0.1.0"
expect_failure() {
 local message=$1
 shift
 if "$@" > "$fixture_root/failure.log" 2>&1; then echo "Expected failure: $message" >&2; exit 1; fi
 if ! grep -F "$message" "$fixture_root/failure.log" >/dev/null; then cat "$fixture_root/failure.log"; exit 1; fi
}
# A failed verification must leave the installed bytes unchanged.
cp "$INSTALL_DIR/conformline" "$fixture_root/original"
printf 'corrupted download\n' > "$release/$asset"
expect_failure 'Checksum mismatch' bash install.sh
cmp "$fixture_root/original" "$INSTALL_DIR/conformline"
cp "dist/$asset" "$release/$asset"
sed "/  $asset\$/d" dist/checksums.txt > "$release/checksums.txt"
expect_failure 'Missing checksum entry' bash install.sh
cmp "$fixture_root/original" "$INSTALL_DIR/conformline"
cp dist/checksums.txt "$release/checksums.txt"
rm "$release/$asset"
expect_failure 'Binary download failed' bash install.sh
cmp "$fixture_root/original" "$INSTALL_DIR/conformline"
cp "dist/$asset" "$release/$asset"
mv "$release/checksums.txt" "$release/saved-checksums"
expect_failure 'Checksum download failed' bash install.sh
mv "$release/saved-checksums" "$release/checksums.txt"
mkdir "$fixture_root/stubs"
printf '#!/bin/sh\necho unsupported\n' > "$fixture_root/stubs/uname"
chmod +x "$fixture_root/stubs/uname"
expect_failure 'Unsupported OS' env PATH="$fixture_root/stubs:$PATH" bash install.sh
printf '#!/bin/sh\ncase "$1" in -s) echo Linux ;; *) echo unsupported ;; esac\n' > "$fixture_root/stubs/uname"
expect_failure 'Unsupported architecture' env PATH="$fixture_root/stubs:$PATH" bash install.sh
# /proc cannot accept a child directory, even when the test runs as root.
expect_failure 'Cannot create INSTALL_DIR' env INSTALL_DIR=/proc/conformline-install-test bash install.sh
mkdir "$fixture_root/readonly"
chmod 555 "$fixture_root/readonly"
if [ "$(id -u)" != 0 ]; then
 expect_failure 'Cannot write INSTALL_DIR' env INSTALL_DIR="$fixture_root/readonly" bash install.sh
fi
chmod 755 "$fixture_root/readonly"
# Restrict PATH to the installer's actual tools, omitting sha256sum.
mkdir "$fixture_root/fallback"
for tool in uname tr mkdir mktemp curl awk shasum cp chmod mv rm; do
 ln -s "$(command -v "$tool")" "$fixture_root/fallback/$tool"
done
PATH="$fixture_root/fallback" /bin/bash install.sh > "$fixture_root/fallback.log"
cmp "$fixture_root/original" "$INSTALL_DIR/conformline"
echo 'Installer checks passed: latest, pinned, verification failures, downloads, platform, destination, shasum.'
