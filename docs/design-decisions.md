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

## DD-003 — Gin for HTTP handlers

**Status:** Accepted.

**Decision:** Use Gin rather than Chi for API routing and JSON responses. Event
follows the same router, middleware, and handler conventions.

**Why:** The developer has experience with Gin and chose it for its wider usage.
Familiarity makes the API easier to develop and maintain.

**Tradeoff / revisit:** Gin brings framework conventions and dependencies. Keep
authorization and input validation explicit; revisit if those conventions hinder
the small API. See [API handlers](../cmd/api/handlers.go).

## DD-004 — curl examples and automated Go tests

**Status:** Accepted.

**Decision:** Document terminal requests with curl and maintain a portable
Postman v2.1 collection plus local environment for Apidog/Postman users. Keep Go
tests as the automated verification evidence.

**Why:** Curl commands work without a GUI or account; the collection provides
the same requests in an API client and captures login tokens automatically.

**Tradeoff / revisit:** Readers manage their own terminal variables and tokens;
examples and collection assertions do not replace regression tests. Keep both
formats aligned as endpoints change. See [curl examples](curl.md), the
[collection](mini-siem.postman_collection.json), and [API tests](../cmd/api/handlers_test.go).
`make verify` checks the three running services' health endpoints only.
`make test` runs the Go tests, including authentication checks.

## DD-005 — Three Go services with a small HTTP interface

**Status:** Accepted; login, identity, and event submission/listing are implemented.
Detection, alerts, and admin operations remain planned.

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

**Status:** Accepted; users and in-memory event storage exist. Alert storage remains planned.

**Decision:** API alone owns a persistent SQLite users database, seeded with
Alice, Bob, and Admin. Store bcrypt hashes and preserve existing accounts on
initialization. Event keeps events in memory; alerts will also stay in memory.

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
Use a separate `event-auth` volume for API-to-Event authority, writable only by
API and mounted read-only by Event. Detection receives neither volume.
`make up` builds and starts the stack; API loads or generates both independent
secrets on startup. Event starts after API's healthcheck succeeds, so a fresh
deployment has a complete service-secret file before Event reads it.
`make verify` checks all three health endpoints; `make test` runs Go tests separately.
`docker compose down` preserves the database and both secrets;
`docker compose down --volumes` deletes them and invalidates existing tokens.

**Why:** This supports a repeatable local environment and keeps credentials and
the database outside services that do not need them.

**Tradeoff / revisit:** Network isolation does not authorize individual calls.
The local HTTP setup is insufficient for public hosting; revisit TLS and
deployment secret management before that scope changes. See [Compose](../compose.yaml).

## DD-008 — Scoped inter-service authorization

**Status:** Accepted and implemented for API → Event submission and owner listing.
Detection and job-scoped authority remain deferred.

**Decision:** Reuse the shared authentication package with a separate HS256
secret for API-to-Event delegation. API derives the owner from its verified user
identity and signs a new token for each internal request. The token has issuer
`mini-siem-api`, audience `mini-siem-event`, the owner's positive ID in `sub`,
action `events:add` or `events:list`, and an expiry 30 seconds after issuance.
API never forwards the user's JWT to Event.

Event independently pins HS256 and checks the signature, issuer, audience,
expiration, positive owner ID, and action required by its route. It uses the
verified subject as the sole owner for storage calls. Request JSON accepts only
`type` and `source_ip`; unknown fields, including ownership, are rejected. The
list operation accepts no caller-selected owner. Missing, forged, expired, or
insufficient authority fails before any store access. Neither service exposes
an admin event list yet.

API generates the separate service secret with the existing random-secret file
handling, using file mode `0600`, and rejects configurations that reuse its user
JWT secret. Compose stores it at `/run/event-auth/secret` in the dedicated volume
from DD-007. Event reads that file without permission to write it; unreadable or
invalid secrets stop startup. Neither Event nor Detection can read API's user
JWT secret or users database. Local runs default to `.secrets/event-secret`;
`EVENT_SECRET_FILE` overrides the path in each service.

**Why:** A service's network access does not grant permission to another user's
records. Detection needs authority only for the delegated owner and job.

**Tradeoff / revisit:** Either holder of the service HMAC secret can mint Event
authority; compromising Event therefore compromises its authorization boundary.
The separate secret prevents that compromise from minting public user JWTs.
Delegation tokens are bearer credentials and can be replayed for the same owner
and action until expiry; they are not bound to one request body and there is no
replay cache. HTTP on the local internal network provides no transport
confidentiality. Use TLS, stronger key isolation, and replay protection before
expanding beyond the assignment's local synthetic-data scope. Replacing the
service secret requires restarting both services; it invalidates outstanding
delegations, and restarting Event discards events.

API uses a bounded upstream timeout, returns HTTP 502 for backend failures and
HTTP 504 for timeouts, and does not retry event submissions: a timed-out request
may already have stored its event. Storage remains unbounded in memory and list
responses have no pagination; revisit retention and pagination before sustained
loads. Detection will need separate owner/action/job authority rather than this
API-only secret. See
[NFR-03 and the access model](initial-plan.md#non-functional-requirements).
