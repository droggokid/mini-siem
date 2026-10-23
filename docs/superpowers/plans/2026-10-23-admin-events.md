# Admin event listing implementation plan

**Goal:** Complete FR-06 as specified in the implementation request and
`docs/initial-plan.md`, preserving NFR-02, NFR-03 and the access-control matrix.

**Architecture:** Reuse the API-to-Event HS256 delegation with a new exact action,
`events:list_all`, and its existing principal, issuer, Event audience and 30-second
expiry. API explicitly checks the authenticated role before privileged signing;
Event independently validates the action before calling `Store.ListAll()`.
Ordinary routes and detection job permissions remain owner-scoped.

**Scope:** API routes/proxy, Event route, shared action allowlist, focused tests,
existing real-service integration workflow, README, curl examples, collection and
design decisions. No dependencies, store changes, eventkit changes or experiments.
The original SSDLC plan stays intact. The existing `event/admin` branch is used.

- [x] Add failing API, Event and token tests: admin success, 401/403, rejection
  before forwarding, invalid request input, wrong key/audience/action/expiry,
  rejection of user/job authority, and no privilege on other operations.
- [x] Extend only the existing action allowlist and route/proxy behavior; run the
  focused tests and verify an empty array and all three owners.
- [x] Extend `TestDetectionIntegration` after its existing detection/alert checks:
  verify each owner's events, admin all-events, denial, and unchanged stored data.
- [x] Update all four requested documentation artifacts and validate collection JSON.
- [x] Run `go test ./...`, `go test -race ./...`, `make test`, and a fresh isolated
  Docker Compose stack with all three health checks and the same integration workflow.
- [x] Review the final diff against every authorization boundary and report actual
  verification results and limitations.

Review focus: no raw query forwarding, no GET body, exact action matching in both
directions, no job-key substitution, no ownership expansion for Admin on ordinary
events/alerts/detection, and no writes on rejected requests.

Verification so far: focused tests observed failing before implementation, then
passed. `go test ./...`, `go test -race ./...`, `go test ./... -count=1` and
`make test` passed. The initial sandboxed `make test` failed because `/tmp` was
read-only; rerunning with permission passed. Collection JSON and formatting/diff
checks passed. Independent review found no bugs or important test gaps.

Compose verification uses isolated project `mini-siem-fr06-verify` and port 18086
because two existing stacks are running. Check each service's health in this
project rather than using `make verify`, whose public health URL is fixed at 8080.

Compose results: `up --build -d --wait` passed, API/Event/Detection health endpoints
each returned `ok`, and `MINI_SIEM_TEST_URL=http://127.0.0.1:18086 go test -run
'^TestDetectionIntegration$' -count=1 -v .` passed against the fresh stack. Only
the temporary verification stack and its synthetic-data volumes are removed.
The collection was validated as JSON, but was not run in Apidog/Postman.
