# Design decisions

This is the living record of choices made for Mini-SIEM. Update it when a
decision changes or its assumptions stop holding. Keep IDs stable; mark replaced
decisions as superseded and link their replacements instead of erasing history.

**Accepted** means the choice is agreed; it does not claim every planned feature
is implemented. **Deferred** means implementation or selection remains open.
The [initial SSDLC plan](initial-plan.md) preserves the original requirements;
this record explains later choices and explicitly identifies changes to it.

## DD-001 — HS256 for user JWTs

**Status:** Accepted; supersedes the initial plan's asymmetric signing-key wording.

**Decision:** API signs and verifies user JWTs with HS256. Use a randomly generated
secret of at least 32 bytes. API loads the existing file on startup or generates
32 random bytes with Go's `crypto/rand`, hex-encodes them, and saves the file with
permissions `0600`. The local default is ignored `.secrets/jwt-secret`; Compose
uses `/data/jwt-secret` in the persistent API-only users volume.
`JWT_SECRET_FILE` may override the default path; no `.env` file is
required. Pin validation to HS256 and require issuer, audience, subject, role,
and expiry; tokens last 15 minutes.

API creates missing parent directories with permissions `0700`. Existing valid
secret files are reused, including read-only files; invalid or unreadable files
stop startup and are never overwritten. No external generators are needed.

**Why:** API is the only service that issues and accepts these tokens. Ed25519
key generation, PEM parsing, and public/private key handling add setup without a
separate verifier that needs the public key.

**Tradeoff / revisit:** Any holder of the HMAC secret can mint tokens. Do not
share it with Event or Detection. Revisit asymmetric signing if separate services
must verify user JWTs without gaining signing authority. Replacing the secret
invalidates existing tokens. The initial plan's “private signing key” references
now mean API's symmetric signing secret for user JWTs; scoped inter-service
authorization remains a separate decision (DD-008).

## DD-002 — Squirrel for SQL construction

**Status:** Accepted.

**Decision:** Use the existing Squirrel query builder for users-table queries.

**Why:** The developer is familiar with Squirrel. This is a familiarity choice,
not a claim that a query builder supplies security automatically.

**Tradeoff / revisit:** It adds a dependency for a small query surface. User
values must still be bound as SQL parameters; concatenating untrusted values into
SQL remains unsafe. Revisit if the builder stops making the queries easy to read.
See [the users store](../cmd/api/internal/users/store.go).

## DD-003 — Gin for the public API

**Status:** Accepted.

**Decision:** Use Gin rather than Chi for API routing and JSON responses.

**Why:** The developer has experience with Gin and chose it for its wider usage.
Familiarity makes the API easier to develop and maintain.

**Tradeoff / revisit:** Gin brings framework conventions and dependencies. Keep
authorization and input validation explicit; revisit if those conventions hinder
the small API. See [API handlers](../cmd/api/handlers.go).

## DD-004 — curl examples and automated Go tests

**Status:** Accepted.

**Decision:** Document terminal requests with curl instead of maintaining a
Postman collection. Keep Go tests as the automated verification evidence.

**Why:** Commands can be copied, shared, versioned, and reproduced directly from
the repository without another GUI or account.

**Tradeoff / revisit:** Readers manage their own terminal variables and tokens;
examples do not replace regression tests. Revisit if a real workflow needs a
collection runner. See [curl examples](curl.md) and [API tests](../cmd/api/handlers_test.go).
`make verify` checks the three running services' health endpoints only.
`make test` runs the Go tests, including authentication checks.

## DD-005 — Three Go services with a small HTTP interface

**Status:** Accepted; business operations remain planned beyond login and identity.

**Decision:** Keep API, Event, and Detection as separate Go executables using
HTTP/JSON. Detection will consume the separately versioned `eventkit` module.

**Why:** The assignment needs a detection workflow that crosses service trust
boundaries and exercises a declared dependency. This makes those boundaries and
their security checks observable without adding a GUI.

**Tradeoff / revisit:** Three services add deployment and authorization work for
a small feature set. `eventkit` executes with Detection's privileges; a module
boundary is not process isolation. Revisit scope against assignment requirements.
See the [initial architecture and dependency plan](initial-plan.md#architecture-and-data-flow).

## DD-006 — SQLite users, bcrypt passwords, in-memory events

**Status:** Accepted; users storage exists, event and alert storage remains planned.

**Decision:** API alone owns a persistent SQLite users database, seeded with
Alice, Bob, and Admin. Store bcrypt hashes and preserve existing accounts on
initialization. Event will keep events and alerts in memory.

**Why:** SQLite avoids a separate database service for three local demo accounts.
Bcrypt satisfies the established password-hashing requirement. In-memory event
storage keeps the assignment's persistence scope limited to users.

**Tradeoff / revisit:** Demo credentials are fixed, and Event restarts will lose
events and alerts. Revisit credentials, durable event storage, and account
management before handling real users or data. See [users storage](../cmd/api/internal/users/store.go)
and the [initial scope](initial-plan.md).

## DD-007 — Local Docker Compose and API-only resources

**Status:** Accepted.

**Decision:** Run the three services with Compose. Publish only API at
`127.0.0.1:8080`; keep Event and Detection on the backend network. Mount the users
volume only in API, storing both the database and JWT secret there.
`make up` builds and starts the stack; API loads or generates the secret on startup.
`make verify` checks all three health endpoints; `make test` runs Go tests separately.
`docker compose down` preserves the database and secret;
`docker compose down --volumes` deletes both and invalidates existing tokens.

**Why:** This supports a repeatable local environment and keeps credentials and
the database outside services that do not need them.

**Tradeoff / revisit:** Network isolation does not authorize individual calls.
The local HTTP setup is insufficient for public hosting; revisit TLS and
deployment secret management before that scope changes. See [Compose](../compose.yaml).

## DD-008 — Scoped inter-service authorization

**Status:** Deferred mechanism; required behavior accepted, not implemented yet.

**Decision:** Select the mechanism when implementing service calls. It must bind
authority to the receiving service, owner or resource, action, validity period,
and job where relevant. Event must authorize every read and write independently.

**Why:** A service's network access does not grant permission to another user's
records. Detection needs authority only for the delegated owner and job.

**Tradeoff / revisit:** This remains required work before the event and detection
workflow is complete. User JWTs are accepted only at API; DD-001 does not authorize
sharing its HMAC secret with internal services. Verify direct-service,
cross-user, and cross-job denials when selecting the mechanism. See
[NFR-03 and the access model](initial-plan.md#non-functional-requirements).
