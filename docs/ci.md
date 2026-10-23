# Continuous integration

[CI on GitHub](https://github.com/droggokid/mini-siem/actions/workflows/ci.yml)
([workflow source](../.github/workflows/ci.yml)) runs on every push, pull requests
targeting `main`, and manual execution. All three Ubuntu 24.04 jobs must pass:

| Job | Blocking failures |
|---|---|
| Build, quality and tests | Module resolution/checksum failure, changed dependency files, replacement directives, overridden or incorrectly versioned `eventkit`, build failure, unformatted Go, vet errors, failed tests or races in either module. |
| Dependency security | Any HIGH/CRITICAL library vulnerability, including unfixed findings, or scanner/image/database/network failure. |
| Compose integration | Failed image build/start, unhealthy service, failed real-service assertions, failed diagnostic collection or incomplete cleanup. |

There is no `continue-on-error`, automatic test retry or deployment. The only
permission is `contents: read`; checkout does not persist credentials. The
`pull_request` trigger needs no repository secrets or privileged execution.

Go comes from root `go.mod` (currently 1.27.3). `GOTOOLCHAIN=local` prevents silent
switching after setup; `GOWORK=off` and `GOFLAGS=-mod=readonly` apply to host-side
builds/tests. The dependency helper downloads and verifies both modules, compares
dependency-file hashes including previously absent sums, rejects replacements and
asserts that root resolves published `eventkit v0.1.0` with a checksum and a
directory in the module cache. The library has no external requirements today.

The existing Dockerfiles download the same pinned dependency without copying a
local `eventkit` or workspace. The [CI Compose overlay](../compose.ci.yaml) uses a
random loopback API port and adds Event/Detection health checks. Compose 2.24.4+
is required for `!override`. A unique project provides fresh database/key volumes.
The helper refuses to reuse existing resources, builds all images, waits for all
three services to become healthy, then runs existing `TestDetectionIntegration`
with `MINI_SIEM_TEST_URL` and test caching disabled. It verifies login, submission,
detection, alert retrieval, admin listing, owner isolation and rejected requests.
Root tests also check direct internal-service authorization; internal services
remain unpublished in Compose.

An EXIT/signal trap collects restricted diagnostics and removes the project's
containers, networks, volumes and service image tags, preserving failure status.
It checks that no labeled containers/networks/volumes remain. An `always()` step
repeats teardown after interruption. Forced runner termination cannot guarantee
cleanup steps execute; GitHub-hosted runners are disposable.

## Results and artifacts

Open **Actions → CI → run → job → step** for command output. On the run summary,
download artifacts before their 14-day retention expires:

| Artifact | Contents |
|---|---|
| `checks-RUN_ID-ATTEMPT` | Module inventories, resolved `eventkit` metadata, before/after hashes, four JUnit XML reports for ordinary/race tests in both modules. |
| `security-RUN_ID-ATTEMPT` | Trivy version metadata and two vulnerability JSON reports for root and independent `eventkit`. |
| `integration-RUN_ID-ATTEMPT` | Compose integration JUnit, service status and startup logs. |

Uploads run after failed checks too. A scanner failure can occur before JSON
exists: inspect the failing step, never infer success from missing findings.
An empty independent `eventkit` scan is expected while it has no third-party
requirements. Only named report files are uploaded, never the whole workspace.

JUnit arbitrary output, failure details, skip messages and properties are removed
before upload because response bodies can contain JWTs. Names, timing, counts and
failure status remain; detailed assertions are in job logs. Sanitization failure
blocks upload and fails CI. Compose logs accept only exact startup messages;
status contains service/state/health/exit-code fields. No database, volume contents,
environment dump, raw HTTP response, signing key or raw service log is an artifact.
Tests use synthetic fixtures and temporary keys. Review new test logging and
subtest names so job logs and report metadata also stay free of sensitive values.

## Vulnerabilities and reviewed exceptions

Trivy 0.76.1 is pinned by image digest, gotestsum by v1.13.0, and Actions by commit.
The vulnerability database refreshes at scan time; new advisories may fail
unchanged code. Both direct/transitive requirements and published `eventkit` are
scanned. Container OS scanning, penetration testing and production readiness are
outside this dependency gate.

All HIGH/CRITICAL findings block pending review. Check the JSON advisory ID,
package, installed/fixed versions and upstream evidence; prefer a reviewed upgrade.
For a false positive or unavoidable exception, open an issue with applicability
and reachability evidence, impact, compensating controls, owner, reviewer and
expiry. Require maintainer approval. No exceptions currently exist and ignore
files are disabled. An approved exception requires a narrowly scoped, expiring
Trivy ignore entry plus explicit workflow wiring in a reviewed change. Never
blanket-ignore unfixed issues, lower thresholds or suppress scanner failures.
Confirmed violations of required authorization guarantees block release regardless
of scanner severity.

## Reproduce locally

Use Go 1.27.3, Bash, Python 3, Docker/Compose 2.24.4+, and a C compiler for race
instrumentation. Run from the repository root. If Go automatically downloads
toolchains, put the actual 1.27.3 installation's `bin` first on `PATH`:
`GOTOOLCHAIN=local go version` must report 1.27.3.

```sh
export GOWORK=off GOFLAGS=-mod=readonly GOTOOLCHAIN=local GIN_MODE=release
export PATH="$(go env GOPATH)/bin:$PATH"
bash scripts/ci-dependencies.sh
test -z "$(gofmt -l .)"
go build ./cmd/api ./cmd/event ./cmd/detection
go vet ./...
(cd eventkit && go vet ./...)
go install gotest.tools/gotestsum@v1.13.0
gotestsum --junitfile reports/root-tests.xml -- -count=1 -timeout=10m ./...
gotestsum --junitfile reports/root-race.xml -- -race -p=1 -count=1 -timeout=10m ./...
(cd eventkit && gotestsum --junitfile ../reports/eventkit-tests.xml -- -count=1 ./...)
(cd eventkit && gotestsum --junitfile ../reports/eventkit-race.xml -- -race -count=1 ./...)
bash scripts/ci-compose.sh
python3 scripts/ci-reports.py --self-test
python3 scripts/ci-reports.py
```

The Compose helper chooses a unique local project and cleans only its resources.
Root race tests serialize packages with `-p=1` so race-instrumented bcrypt work in
unit tests does not starve the integration services' existing startup deadline.
Do not set `COMPOSE_PROJECT_NAME` to your development project. Reports are in
ignored `reports/`, also excluded from Docker build contexts. `make test` remains
available for ordinary tests without reports.

Run both scans below, treating each nonzero exit as failure:

```sh
mkdir -p reports
TRIVY_IMAGE=aquasec/trivy:0.76.1@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c
docker pull "$TRIVY_IMAGE"
docker run --rm "$TRIVY_IMAGE" --version
docker run --rm -v "$PWD:/src:ro" -v "$PWD/reports:/reports" \
  "$TRIVY_IMAGE" fs --scanners vuln --pkg-types library --severity HIGH,CRITICAL \
  --exit-code 1 --format json --output /reports/trivy-root.json --ignorefile '' \
  --skip-dirs /src/.git --skip-dirs /src/eventkit --skip-dirs /src/reports /src
docker run --rm -v "$PWD/eventkit:/src:ro" -v "$PWD/reports:/reports" \
  "$TRIVY_IMAGE" fs --scanners vuln --pkg-types library --severity HIGH,CRITICAL \
  --exit-code 1 --format json --output /reports/trivy-eventkit.json --ignorefile '' /src
```

Validate workflow syntax with pinned
`go install github.com/rhysd/actionlint/cmd/actionlint@v1.7.7`, then
`actionlint .github/workflows/ci.yml`. Also run
`bash -n scripts/ci-dependencies.sh scripts/ci-compose.sh` and
`docker compose -f compose.yaml -f compose.ci.yaml config --quiet`.

## Demonstrate a failing authorization gate

This needs three real GitHub runs. Local checks are not workflow execution
evidence. You manage the branches, commits and pushes for the experiment:

1. Push the unchanged implementation. Wait for all three jobs and overall CI
   to pass. Save the run URL, revision ID and downloaded reports.
2. In a separate experimental revision, edit only
   `cmd/api/admin_events_test.go`, in `TestAdminEventsChecksRoleBeforeSigning`.
   Change its `w.Code != http.StatusForbidden` assertion to
   `w.Code != http.StatusOK`. The implementation still correctly returns 403;
   the harmless assertion fails without changing authorization behavior.
3. Push that experimental revision. Verify **Build, quality and tests** and
   overall CI are red. Inspect **Root tests** for that exact test failure.
   Race/library tests still run. Download `checks-RUN_ID-ATTEMPT`, keep
   `root-tests.xml` with the failure, and save the failing run URL/revision ID.
4. Restore `http.StatusForbidden`, push the restoration and verify every job and
   overall CI pass again. Keep its URL, revision ID and reports.
5. Record all three URLs, revisions, conclusions and artifact filenames in the
   assignment evidence. Leave no deliberately failing assertion in the final
   branch. Download evidence before artifact expiry.

Resolve any baseline dependency/advisory failures first; never weaken gates for
the demonstration. A passing local check or single job is not an overall pass.

## After pushing and branch protection

1. In **Settings → Actions → General**, enable Actions and allow the pinned
   official Actions. GitHub-hosted Ubuntu must be available; no secrets are needed.
2. Push the implementation, open the CI link above and verify all jobs/artifacts.
   Manual **Run workflow** is available once the workflow reaches the default
   branch; pushes run it on other branches too.
3. Perform the pass/fail/pass experiment above and retain the actual evidence.
4. In **Settings → Branches → Add branch protection rule** for `main` (or an
   equivalent ruleset), enable **Require a pull request before merging** and
   **Require status checks to pass before merging**. After the first run, select
   **Build, quality and tests**, **Dependency security**, and **Compose integration**.
   Require the branch to be up to date; restrict bypasses according to policy.

Branch protection makes CI mandatory for merging. Adding these files does not
execute GitHub workflows or change repository settings. See
[DD-012](design-decisions.md#dd-012--github-actions-ci-and-security-gates).
