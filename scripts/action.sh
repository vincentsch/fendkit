#!/usr/bin/env bash
set -euo pipefail
fail() { echo "Fendkit: $*" >&2; exit 1; }
output() { printf '%s=%s\n' "$1" "$2" >> "$GITHUB_OUTPUT"; }
summary() { printf '%s\n' "$*" >> "$GITHUB_STEP_SUMMARY"; }

install() {
 [ "${RUNNER_OS:-}" = Linux ] || fail 'Use an Ubuntu runner (runs-on: ubuntu-latest).'
 version=${INPUT_VERSION-latest}
 [[ "$version" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || fail 'version must be latest or a release tag such as v0.1.0.'
 destination=$(mktemp -d "$RUNNER_TEMP/fendkit-bin.XXXXXXXX")
 if [ "$version" = latest ]; then
  unset FENDKIT_VERSION
 else
  export FENDKIT_VERSION=$version
 fi
 INSTALL_DIR="$destination" bash "$GITHUB_ACTION_PATH/install.sh"
 printf '%s\n' "$destination" >> "$GITHUB_PATH"
}

run() {
 output scan-exit-code ''
 output check-exit-code ''
 output reports-ready false
 [ "${RUNNER_OS:-}" = Linux ] || fail 'Use an Ubuntu runner (runs-on: ubuntu-latest).'
 case "${INPUT_FAIL_ON-policy}" in policy|never) ;; *) fail 'fail-on must be policy or never.' ;; esac
 case "${INPUT_ATTACH_TO_RELEASE-false}" in true|false) ;; *) fail 'attach-to-release must be true or false.' ;; esac
 version=${INPUT_VERSION-latest}
 [[ "$version" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || fail 'version must be latest or a release tag such as v0.1.0.'
 project=${INPUT_WORKING_DIRECTORY:-.}
 [[ "$project" = /* ]] || project="$GITHUB_WORKSPACE/$project"
 project=$(cd -- "$project" && pwd -P) || fail 'working-directory must name an existing project directory.'
 [ -f "$project/cra.yml" ] || fail 'Run `fendkit init` locally and commit cra.yml'
 release_args=()
 if [ -n "${INPUT_RELEASE:-}" ]; then
  release=$INPUT_RELEASE
  [[ "$release" = /* ]] || release="$project/$release"
  # An existing literal path takes precedence over glob syntax in its name.
  if [ ! -e "$release" ]; then
   mapfile -t matches < <(compgen -G "$release" || true)
   case ${#matches[@]} in
    0) fail "release matched no files: $INPUT_RELEASE. Build or download the product release first." ;;
    1) release=${matches[0]}; [ -f "$release" ] || fail 'A release glob must match one file (use a literal path for a folder).' ;;
    *) printf 'Fendkit: release matched several paths; select one file:\n' >&2
       printf '  %s\n' "${matches[@]}" >&2; exit 1 ;;
   esac
  fi
  release=$(realpath -- "$release")
  release_args=(--release "$release")
 fi
 state=$(mktemp -d "$RUNNER_TEMP/fendkit-action.XXXXXXXX")
 mkdir "$state/artifacts"
 output state-dir "$state"
 output artifact-dir "$state/artifacts"
 output artifact-suffix "${state##*.}"
 printf '%s\n' "${INPUT_FAIL_ON-policy}" > "$state/fail-on"
 printf '%s\n' "${INPUT_ATTACH_TO_RELEASE-false}" > "$state/attach"
 scan=0
 fendkit scan --no-prompt --dir "$project" "${release_args[@]}" || scan=$?
 echo "Fendkit scan exit code: $scan"
 printf '%s\n' "$scan" > "$state/scan"
 output scan-exit-code "$scan"
 : > "$state/check"
 case "$scan" in
  0|11) ;;
  *) summary "Fendkit scan failed (exit $scan); no reports from this run"; return ;;
 esac
 check=0
 fendkit check --ci --no-prompt --dir "$project" || check=$?
 echo "Fendkit check exit code: $check"
 printf '%s\n' "$check" > "$state/check"
 output check-exit-code "$check"
 files=(inventory.json sbom.cdx.json vulnerabilities.json vulnerabilities.md)
 if [ -f "$project/cra/reports/vex.openvex.json" ]; then files+=(vex.openvex.json); fi
 case "$check" in
  0|10|11) files+=(status.md status.html) ;;
  *) summary "Fendkit check failed (exit $check); status reports omitted from this run" ;;
 esac
 for file in "${files[@]}"; do
  [ -f "$project/cra/reports/$file" ] || fail "Missing current report $file after scan/check; report collection failed."
  cp -- "$project/cra/reports/$file" "$state/artifacts/$file"
 done
 touch "$state/collected"
 output reports-ready true
}

attach() {
 state=$1
 [ -f "$state/collected" ] || fail 'No collected reports available for attachment.'
 [ "$(cat "$state/attach")" = true ] || return 0
 if [ "${GITHUB_EVENT_NAME:-}" != release ]; then
  echo 'Fendkit: release attachment skipped; this is not a release event.'
  return 0
 fi
 [ -f "$state/artifacts/sbom.cdx.json" ] || fail 'Current SBOM missing; cannot attach release evidence.'
 # Read the event tag as data; release names and branch refs are not release tags.
 tag=$(jq -er '.release.tag_name | select(type == "string" and length > 0)' "$GITHUB_EVENT_PATH") || fail 'Release event has no tag_name.'
 files=("$state/artifacts/sbom.cdx.json")
 if [ -f "$state/artifacts/vex.openvex.json" ]; then files+=("$state/artifacts/vex.openvex.json"); fi
 gh release upload "$tag" --repo "$GITHUB_REPOSITORY" --clobber "${files[@]}"
}

verdict() {
 state=$1
 scan=$(cat "$state/scan")
 check=$(cat "$state/check")
 echo "Fendkit verdict: scan=$scan check=${check:-not-run} fail-on=$(cat "$state/fail-on")"
 case "$scan" in 0|11) ;; *) fail "Scan failed (exit $scan)." ;; esac
 [ -f "$state/collected" ] || fail 'Report collection did not complete.'
 case "$check" in 0|10|11) ;; *) fail "Check failed (exit $check)." ;; esac
 if [ "$(cat "$state/fail-on")" = policy ] && { [ "$scan" != 0 ] || [ "$check" != 0 ]; }; then
  fail 'Policy failed or scan evidence is incomplete. Review the job summary and reports.'
 fi
}

case "${1:-}" in
 install) install ;;
 run) run ;;
 attach|verdict) [ "$#" = 2 ] || fail 'Supply the saved state directory.'; "$1" "$2" ;;
 *) fail 'Expected phase: install, run, attach or verdict.' ;;
esac
