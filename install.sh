#!/usr/bin/env bash
set -euo pipefail
fail() { echo "Fendkit: $*" >&2; exit 1; }
os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)
case "$os" in
 linux|darwin) ;;
 mingw*|msys*|cygwin*) os=windows ;;
 *) fail "Unsupported OS: $os. Download a supported release from GitHub." ;;
esac
case "$arch" in
 x86_64|amd64) arch=amd64 ;;
 arm64|aarch64) arch=arm64 ;;
 *) fail "Unsupported architecture: $arch. Download a supported release from GitHub." ;;
esac
asset="fendkit-$os-$arch"
binary=fendkit
if [ "$os" = windows ]; then asset="$asset.exe"; binary="$binary.exe"; fi
base=${FENDKIT_RELEASES_URL:-https://github.com/vincentsch/fendkit/releases}
case "${FENDKIT_VERSION:-latest}" in
 latest) route=latest/download ;;
 *) route="download/$FENDKIT_VERSION" ;;
esac
destination=${INSTALL_DIR:-"$HOME/.local/bin"}
mkdir -p "$destination" 2>/dev/null || fail "Cannot create INSTALL_DIR. Choose a writable directory."
[ -w "$destination" ] || fail "Cannot write INSTALL_DIR. Choose a writable directory."
tmp=$(mktemp -d)
staged=
cleanup() { rm -rf "$tmp"; if [ -n "$staged" ]; then rm -f "$staged"; fi; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
curl -fsSL "$base/$route/$asset" -o "$tmp/$asset" || fail "Binary download failed. Check the release tag and connection."
curl -fsSL "$base/$route/checksums.txt" -o "$tmp/checksums.txt" || fail "Checksum download failed. Check the release tag and connection."
expected=$(awk -v name="$asset" '$2 == name { print $1 }' "$tmp/checksums.txt")
[ -n "$expected" ] || fail "Missing checksum entry for $asset."
if command -v sha256sum >/dev/null 2>&1; then
 actual=$(sha256sum "$tmp/$asset" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
 actual=$(shasum -a 256 "$tmp/$asset" | awk '{print $1}')
else
 fail "Install sha256sum or shasum to verify this download."
fi
[ "$actual" = "$expected" ] || fail "Checksum mismatch for $asset. Existing installation was kept."
# Stage on the destination filesystem before replacing an existing executable.
staged=$(mktemp "$destination/.fendkit.XXXXXXXX") || fail "Cannot write INSTALL_DIR. Choose a writable directory."
cp "$tmp/$asset" "$staged"
chmod 755 "$staged"
mv -f "$staged" "$destination/$binary"
staged=
"$destination/$binary" --version
printf 'Installed to %s\n' "$destination/$binary"
case ":$PATH:" in
 *":$destination:"*) ;;
 *) printf 'Add this directory to PATH: export PATH="%s:$PATH"\n' "$destination" ;;
esac
echo 'Try: fendkit demo --offline'
