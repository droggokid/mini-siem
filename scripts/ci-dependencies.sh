#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export GOWORK=off GOFLAGS=-mod=readonly GOTOOLCHAIN=local
report_dir="$PWD/reports/dependencies"
mkdir -p "$report_dir"

# Include absent sums so creating a previously unnecessary go.sum also fails.
snapshot() {
  for file in go.mod go.sum eventkit/go.mod eventkit/go.sum; do
    if [[ -f "$file" ]]; then
      sha256sum "$file"
    else
      printf 'absent %s\n' "$file"
    fi
  done
}
snapshot > "$report_dir/before.txt"
finish() {
  result=$?
  snapshot > "$report_dir/after.txt"
  if ! diff -u "$report_dir/before.txt" "$report_dir/after.txt"; then
    echo 'Dependency files changed during verification.' >&2
    result=1
  fi
  exit "$result"
}
trap finish EXIT

for module in . eventkit; do
  (
    cd "$module"
    go mod edit -json | python3 -c '
import json, sys
module = json.load(sys.stdin)
assert not module.get("Replace"), "replace directives are forbidden in CI"
if module["Module"]["Path"] == "github.com/droggokid/mini-siem":
    versions = [r["Version"] for r in module["Require"]
                if r["Path"] == "github.com/droggokid/mini-siem/eventkit"]
    assert versions == ["v0.1.0"], "eventkit must be explicitly pinned to v0.1.0"
'
    go mod download
    go mod verify
    name=root
    [[ "$module" == . ]] || name=eventkit
    go list -m -f '{{.Path}} {{.Version}}' all > "$report_dir/$name-modules.txt"
  )
done

go list -m -json github.com/droggokid/mini-siem/eventkit > "$report_dir/eventkit-resolved.json"
python3 - "$report_dir/eventkit-resolved.json" "$(go env GOMODCACHE)" <<'PY'
import json, os, sys
with open(sys.argv[1]) as source:
    module = json.load(source)
assert module["Version"] == "v0.1.0", "unexpected resolved eventkit version"
assert not module.get("Replace") and not module.get("Main"), "eventkit was overridden"
assert module.get("Sum"), "published eventkit checksum is missing"
cache, directory = map(os.path.realpath, (sys.argv[2], module["Dir"]))
assert os.path.commonpath((cache, directory)) == cache, "eventkit is outside the module cache"
PY
