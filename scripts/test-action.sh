#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source scripts/test-release-fixture.sh
start_release_fixture
export GITHUB_ACTION_PATH=$PWD RUNNER_OS=Linux
export RUNNER_TEMP="$fixture_root/runner" GITHUB_WORKSPACE="$fixture_root/maker with spaces"
mkdir -p "$RUNNER_TEMP" "$GITHUB_WORKSPACE" "$fixture_root/wrapper"
export GITHUB_PATH="$fixture_root/path" GITHUB_OUTPUT="$fixture_root/output"
export GITHUB_STEP_SUMMARY="$fixture_root/summary" GITHUB_EVENT_PATH="$fixture_root/event.json"
export GITHUB_EVENT_NAME=release GITHUB_REPOSITORY=example/maker
export CALL_LOG="$fixture_root/calls.jsonl" GH_LOG="$fixture_root/gh.jsonl"
export INPUT_VERSION=latest INPUT_WORKING_DIRECTORY=. INPUT_RELEASE=''
export INPUT_FAIL_ON=policy INPUT_ATTACH_TO_RELEASE=false
printf '{"release":{"tag_name":"product-v2.3.1"}}\n' > "$GITHUB_EVENT_PATH"
: > "$GITHUB_PATH"
expect() {
 local wanted=$1 code=0
 shift
 "$@" > "$fixture_root/last.log" 2>&1 || code=$?
 if [ "$code" != "$wanted" ]; then
  cat "$fixture_root/last.log"
  echo "Expected exit $wanted, got $code: $*" >&2
  exit 1
 fi
}
contains() { grep -F -- "$2" "$1" > /dev/null || { echo "Missing assertion: $2" >&2; cat "$1"; exit 1; }; }
value() { sed -n "s/^$1=//p" "$GITHUB_OUTPUT" | tail -1; }
reset_run() {
 : > "$GITHUB_OUTPUT"; : > "$GITHUB_STEP_SUMMARY"; : > "$CALL_LOG"; : > "$GH_LOG"
}
run_action() { expect 0 bash scripts/action.sh run; state=$(value state-dir); artifacts=$(value artifact-dir); }
# A preexisting version must not override latest. Only the loopback installer is used.
export CONFORMLINE_VERSION=nonexistent
expect 0 bash scripts/action.sh install
export REAL_BIN="$(tail -1 "$GITHUB_PATH")/conformline"
[ -x "$REAL_BIN" ]
export INPUT_VERSION=v0.1.0
expect 0 bash scripts/action.sh install
contains "$fixture_root/server.log" '/download/v0.1.0/'
contains "$fixture_root/server.log" '/latest/download/'
# The wrapper stays first even after the runner applies GITHUB_PATH.
export PATH="$fixture_root/wrapper:$(tail -1 "$GITHUB_PATH"):$PATH"
cat > "$fixture_root/wrapper/conformline" <<'WRAPPER'
#!/usr/bin/env python3
import json, os, subprocess, sys
args = sys.argv[1:]
with open(os.environ['CALL_LOG'], 'a') as f: f.write(json.dumps(args) + '\n')
if os.environ.get('CLI_MODE', 'real') == 'real':
    if args[0] == 'scan': args.append('--offline')
    sys.exit(subprocess.call([os.environ['REAL_BIN']] + args))
root = args[args.index('--dir') + 1]
reports = os.path.join(root, 'cra', 'reports')
os.makedirs(reports, exist_ok=True)
command = args[0]
code = int(os.environ['SCAN_CODE' if command == 'scan' else 'CHECK_CODE'])
if command == 'scan' and code in (0, 11):
    names = ['inventory.json', 'sbom.cdx.json', 'vulnerabilities.json', 'vulnerabilities.md']
    vex = os.path.join(reports, 'vex.openvex.json')
    if os.environ.get('VEX') == 'true': names.append('vex.openvex.json')
    elif os.path.exists(vex): os.unlink(vex)
elif command == 'check' and code in (0, 10, 11):
    names = ['status.md', 'status.html']
    with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as f: f.write('Current check summary\n')
else: names = []
for name in names:
    if name == os.environ.get('OMIT_REPORT'): continue
    with open(os.path.join(reports, name), 'w') as f: f.write('current ' + name)
sys.exit(code)
WRAPPER
cat > "$fixture_root/wrapper/gh" <<'WRAPPER'
#!/usr/bin/env python3
import json, os, sys
with open(os.environ['GH_LOG'], 'a') as f: f.write(json.dumps(sys.argv[1:]) + '\n')
sys.exit(int(os.environ.get('GH_CODE', '0')))
WRAPPER
chmod +x "$fixture_root/wrapper/"*
expect 11 "$REAL_BIN" demo --offline --out "$GITHUB_WORKSPACE/nested project"
export INPUT_WORKING_DIRECTORY='nested project/acme-booking'
export INPUT_RELEASE='../dist/*.zip' CLI_MODE=real
project="$GITHUB_WORKSPACE/$INPUT_WORKING_DIRECTORY"
for policy in policy never; do
 export INPUT_FAIL_ON=$policy
 reset_run; run_action
 [ "$(value scan-exit-code)" = 11 ]; [ "$(value check-exit-code)" = 11 ]
 [ -s "$GITHUB_STEP_SUMMARY" ]; [ -s "$artifacts/status.md" ]; [ -s "$artifacts/status.html" ]
 python3 - "$CALL_LOG" "$project" <<'PY'
import json, os, sys
scan, check = map(json.loads, open(sys.argv[1]))
assert scan[:2] == ['scan', '--no-prompt']
assert scan[scan.index('--dir')+1] == sys.argv[2]
assert scan[scan.index('--release')+1] == os.path.realpath(sys.argv[2] + '/../dist/acme-booking-2.3.1.zip')
assert check == ['check', '--ci', '--no-prompt', '--dir', sys.argv[2]]
PY
 if [ "$policy" = policy ]; then expect 1 bash scripts/action.sh verdict "$state"; else expect 0 bash scripts/action.sh verdict "$state"; fi
done
# A real operational check failure must not collect seeded status pages.
mkdir -p "$project/cra/incidents/inc-1"
printf 'version: [invalid\n' > "$project/cra/incidents/inc-1/incident.yml"
for policy in policy never; do
 export INPUT_FAIL_ON=$policy INPUT_ATTACH_TO_RELEASE=true
 printf old > "$project/cra/reports/status.md"; printf old > "$project/cra/reports/status.html"
 printf unrelated > "$project/cra/reports/private.txt"
 reset_run; run_action
 [ "$(value scan-exit-code)" = 11 ]; [ "$(value check-exit-code)" = 2 ]
 [ "$(find "$artifacts" -type f | wc -l)" = 4 ]
 [ ! -e "$artifacts/status.md" ]; [ ! -e "$artifacts/status.html" ]; [ ! -e "$artifacts/private.txt" ]
 contains "$project/cra/reports/status.md" old
 contains "$GITHUB_STEP_SUMMARY" 'Conformline check failed (exit 2); status reports omitted from this run'
 expect 0 bash scripts/action.sh attach "$state"; contains "$GH_LOG" sbom.cdx.json
 expect 1 bash scripts/action.sh verdict "$state"
done
rm -r "$project/cra/incidents/inc-1"
export CLI_MODE=stub INPUT_RELEASE='' INPUT_ATTACH_TO_RELEASE=false VEX=false
# All supported code combinations, including scan=11/check=10, retain both codes.
for policy in policy never; do
 export INPUT_FAIL_ON=$policy
 for scan in 0 11; do
  for check in 0 10 11; do
   export SCAN_CODE=$scan CHECK_CODE=$check
   reset_run; run_action
   [ "$(value scan-exit-code)" = "$scan" ]; [ "$(value check-exit-code)" = "$check" ]
   [ "$(value reports-ready)" = true ]; [ -f "$artifacts/status.md" ]; [ -f "$artifacts/status.html" ]
   [ "$(find "$artifacts" -type f | wc -l)" = 6 ]
   wanted=0
   if [ "$policy" = policy ] && { [ "$scan" != 0 ] || [ "$check" != 0 ]; }; then wanted=1; fi
   expect "$wanted" bash scripts/action.sh verdict "$state"
  done
 done
done
# Operational codes are never suppressed. Fatal scans leave old evidence untouched.
export INPUT_FAIL_ON=never INPUT_ATTACH_TO_RELEASE=true
for code in 1 2 5; do
 export SCAN_CODE=0 CHECK_CODE=0 VEX=false
 reset_run; run_action
 expect 0 bash scripts/action.sh verdict "$state"
 export SCAN_CODE=$code CHECK_CODE=0
 reset_run; run_action
 [ "$(value scan-exit-code)" = "$code" ]; [ -z "$(value check-exit-code)" ]
 [ "$(value reports-ready)" = false ]; [ -z "$(ls -A "$artifacts")" ]
 [ "$(wc -l < "$CALL_LOG")" = 1 ]; [ ! -s "$GH_LOG" ]
 [ "$(cat "$GITHUB_STEP_SUMMARY")" = "Conformline scan failed (exit $code); no reports from this run" ]
 contains "$project/cra/reports/status.md" 'current status.md'
 expect 1 bash scripts/action.sh verdict "$state"
 export SCAN_CODE=11 CHECK_CODE=$code VEX=true
 reset_run; run_action
 [ "$(value check-exit-code)" = "$code" ]
 [ "$(find "$artifacts" -type f | wc -l)" = 5 ]; [ ! -e "$artifacts/status.md" ]; [ ! -e "$artifacts/status.html" ]
 contains "$GITHUB_STEP_SUMMARY" "Conformline check failed (exit $code); status reports omitted from this run"
 expect 0 bash scripts/action.sh attach "$state"
 expect 1 bash scripts/action.sh verdict "$state"
done
# A VEX upload followed by an SBOM-only rerun never deletes remote assets.
export SCAN_CODE=11 CHECK_CODE=10 VEX=true
reset_run; run_action
expect 0 bash scripts/action.sh attach "$state"
export VEX=false
run_action
expect 0 bash scripts/action.sh attach "$state"
# gh log contains both calls; compare supplied file basenames and exact targeting.
python3 - "$GH_LOG" <<'PY'
import json, os, sys
first, second = map(json.loads, open(sys.argv[1]))
for args in (first, second):
    assert args[:6] == ['release', 'upload', 'product-v2.3.1', '--repo', 'example/maker', '--clobber']
assert [os.path.basename(x) for x in first[6:]] == ['sbom.cdx.json', 'vex.openvex.json']
assert [os.path.basename(x) for x in second[6:]] == ['sbom.cdx.json']
PY
export GITHUB_EVENT_NAME=pull_request
: > "$GH_LOG"
expect 0 bash scripts/action.sh attach "$state"
contains "$fixture_root/last.log" 'not a release event'
[ ! -s "$GH_LOG" ]
export GITHUB_EVENT_NAME=release GH_CODE=1
expect 1 bash scripts/action.sh attach "$state"
unset GH_CODE
# Literal folders, one-file globs, no matches, multiple matches and quoted shell text.
export INPUT_RELEASE='../dist/*.zip'
reset_run; run_action
cp "$GITHUB_WORKSPACE/nested project/dist/acme-booking-2.3.1.zip" "$GITHUB_WORKSPACE/nested project/dist/other.zip"
reset_run; expect 1 bash scripts/action.sh run
contains "$fixture_root/last.log" 'matched several'; contains "$fixture_root/last.log" other.zip
[ ! -s "$CALL_LOG" ]
export INPUT_RELEASE='../dist/missing*.zip'
reset_run; expect 1 bash scripts/action.sh run
contains "$fixture_root/last.log" 'matched no files'
export INPUT_RELEASE=.
reset_run; run_action
# An absolute project root and literal release also work independently of workspace.
export INPUT_WORKING_DIRECTORY="$project" INPUT_RELEASE="$GITHUB_WORKSPACE/nested project/dist/acme-booking-2.3.1.zip"
reset_run; run_action
export INPUT_WORKING_DIRECTORY='nested project/acme-booking'
export INPUT_RELEASE='$(touch should-never-exist)*'
reset_run; expect 1 bash scripts/action.sh run
[ ! -e should-never-exist ]
export INPUT_RELEASE=''
export INPUT_FAIL_ON=invalid
reset_run; expect 1 bash scripts/action.sh run; contains "$fixture_root/last.log" 'fail-on must be'
export INPUT_FAIL_ON=''
reset_run; expect 1 bash scripts/action.sh run; contains "$fixture_root/last.log" 'fail-on must be'
export INPUT_FAIL_ON=never INPUT_ATTACH_TO_RELEASE=yes
reset_run; expect 1 bash scripts/action.sh run; contains "$fixture_root/last.log" 'attach-to-release must be'
export INPUT_ATTACH_TO_RELEASE=false INPUT_VERSION='../bad'
reset_run; expect 1 bash scripts/action.sh install; contains "$fixture_root/last.log" 'version must be'
export INPUT_VERSION=latest RUNNER_OS=Windows
reset_run; expect 1 bash scripts/action.sh run; contains "$fixture_root/last.log" 'Ubuntu runner'
export RUNNER_OS=Linux INPUT_WORKING_DIRECTORY=.
reset_run; expect 1 bash scripts/action.sh run
contains "$fixture_root/last.log" 'Run `conformline init` locally and commit cra.yml'
[ ! -s "$CALL_LOG" ]; [ -z "$(value artifact-dir)" ]
export INPUT_WORKING_DIRECTORY='nested project/acme-booking'
# Missing required scan/status reports are collection errors, regardless of policy.
for missing in sbom.cdx.json status.html; do
 rm -f "$project/cra/reports/$missing"
 export OMIT_REPORT=$missing SCAN_CODE=0 CHECK_CODE=0
 reset_run; expect 1 bash scripts/action.sh run
 contains "$fixture_root/last.log" "Missing current report $missing"
 [ "$(value reports-ready)" = false ]
 expect 1 bash scripts/action.sh verdict "$(value state-dir)"
done
unset OMIT_REPORT
# Installer diagnostics survive the install phase and failed downloads.
export INPUT_VERSION=nonexistent
expect 1 bash scripts/action.sh install
contains "$fixture_root/last.log" 'Binary download failed'
# Verify orchestration independently of hosted storage, which local tests cannot run.
python3 - <<'PY'
from pathlib import Path
s = Path('action.yml').read_text()
assert s.index('scripts/action.sh" run') < s.index('uses: actions/upload-artifact@') < s.index('scripts/action.sh" attach') < s.index('scripts/action.sh" verdict')
assert 'path: ${{ steps.scan.outputs.artifact-dir }}/' in s
assert 'if-no-files-found: error' in s
assert 'GH_TOKEN: ${{ github.token }}' in s
assert "steps.scan.outputs.reports-ready == 'true'" in s
assert 'bash scripts/test-action.sh' in Path('.github/workflows/ci.yml').read_text()
PY
echo 'Action checks passed: real offline reports (11/11), real fatal check (11/2), policy matrix, operational errors, current-only collection, inputs, paths, attachments and reruns.'
