# Detection and alerts implementation plan

> **For agentic workers:** Use superpowers:executing-plans to implement this plan task by task.

**Goal:** Implement FR-04 and FR-05 with synchronous owner-scoped detection and in-memory alerts.

**Architecture:** API signs Ed25519 job capabilities; Detection and Event verify with the public key. Existing API-to-Event HMAC permissions remain separate. Detection forwards API-issued event-read and alert-write capabilities with matching owner and job.

**Tech stack:** Existing Go, Gin, jwt/v5, standard library, Docker Compose; no new dependencies.

**Spec:** `docs/initial-plan.md` and the user's FR-04/FR-05 handoff. The user approved this design and review during implementation on 2026-10-23.

## Global constraints

- At least 5 `login.failed` events from one IP in any inclusive rolling 5-minute ingestion-time window; one alert per IP per run.
- No caller-selected ownership, admin-wide listing, eventkit, queues, persistence, or intentional vulnerabilities.
- Detection gets neither user JWT nor Event HMAC signing secret.
- Preserve existing event routes, input validation, and owner isolation.

## Review focus

- Equivalent textual IP addresses must group together.
- Unsorted events and historical windows must still detect.
- Mixing valid capabilities from different owners/jobs must fail before fetching or storing.
- Failed upstream calls must not expose credentials or trigger automatic retries.
- Oversized and malformed bodies must fail before mutation.

## Tasks

- [ ] 1. Add failing capability tests in `internal/auth/job_test.go`, then implement Ed25519 signing/verification in `job.go`: service, owner, action, expiry and job checks. Test tampering, algorithm confusion and missing claims.
- [ ] 2. Add rule tests in `cmd/detection/rule_test.go`, then implement pure `detect(events []event) []finding`: group canonical IPs, sort timestamps, compute maximum rolling count. Test threshold, inclusive boundary, mixed types/IPs, sorting and input immutability.
- [ ] 3. Add alert store and Event handler tests, then extend `cmd/event/internal/events` and Event handlers with owner-scoped alert listing and job-authorized reads/writes. Test malformed input, permission mismatches and concurrent snapshots/writes.
- [ ] 4. Add Detection and API tests, then wire synchronous detection, startup key configuration and routes. Keep ownership solely in verified claims. Add an integration test using real service handlers over HTTP while preserving Go internal-package boundaries.
- [ ] 5. Update Compose/Dockerfiles, README, curl examples, API collection and design decisions. Run `go test ./...`, `go test -race ./...`, `go vet ./...`, and an isolated Compose workflow with Alice/Bob/Admin and direct-service rejection checks.

## Execution record

Work in the user's clean `detection/detection-rule` branch so changes remain directly reviewable. Leave changes uncommitted for review. User authorization covers continued implementation without additional design gates.
