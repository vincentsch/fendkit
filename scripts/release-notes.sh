#!/usr/bin/env bash
set -euo pipefail
# Only a dated heading for the exact tag may supply publication notes.
tag=${1:?Usage: scripts/release-notes.sh vX.Y.Z}
awk -v tag="$tag" '
 /^## / {
  if (found) exit
  if ($2 == tag && $3 == "-" && $4 ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]$/ && NF == 4) { found=1; next }
 }
 found { print }
 END { if (!found) { print "No dated CHANGELOG.md section for " tag > "/dev/stderr"; exit 1 } }
' CHANGELOG.md
