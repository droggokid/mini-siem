# Mini-SIEM

Mini-SIEM is a small security event monitor for Assignment I. Alice, Bob, and Admin submit events and inspect their own events and alerts. Admin can also view all users' events through a separate operation. A detection run checks the caller's events for at least five failed logins from the same IP within five minutes and saves alerts.

The planned system has three separate Go services: API authenticates users, Event stores events and alerts, and Detection finds patterns using the separately installed `eventkit` package. Users log in with seeded accounts stored in SQLite and receive short-lived JWTs. API alone accesses the users database and establishes scoped authority for inter-service calls. The detection run calls all three services.

The services will run locally with Docker Compose. The users database will persist in an API-only volume. Events and alerts will stay in memory and be lost when Event restarts. HTTP endpoints and automated tests provide the interface; curl examples will show how to use it.

## Project documents

- [Design decisions](docs/design-decisions.md), updated as implementation choices evolve
- [curl examples for all current endpoints](docs/curl.md)
- [Initial SSDLC plan](docs/initial-plan.md), including requirements, architecture, access control, threat model, and lifecycle gates
- [Component diagram](docs/diagrams/components.mmd), [data flow](docs/diagrams/data-flow.mmd), and [detection sequence](docs/diagrams/detection-sequence.mmd)

## Local development

Requirements: Go 1.27.3, Docker with Docker Compose, make, and curl.

API, Event, and Detection are separate executables. Each exposes
`GET /health`, returning HTTP 200 with the body `ok`.
API uses [Gin](https://github.com/gin-gonic/gin) for REST routing and JSON responses.

Only API publishes a host port, at `127.0.0.1:8080`.
Event and Detection are accessible through the internal Docker network.

### Build

From the repository root:

```sh
go build ./...
```

To build individual executable files:

```sh
go build -o bin/api ./cmd/api
go build -o bin/event ./cmd/event
go build -o bin/detection ./cmd/detection
```

### Run

From the repository root, build and start the services in the background:

```sh
make up
```

`make up` builds and starts the stack. API loads its JWT signing secret on startup
or, if missing, generates 32 random bytes with Go's `crypto/rand` and saves them
as hex with file permissions `0600`. No external secret-generation tools are needed.
Existing valid files are reused, including read-only files; unreadable or invalid
files stop startup and are never overwritten.

Compose stores the secret at `/data/jwt-secret` in the persistent API-only
`users-data` volume. Keep it between restarts and do not share it: anyone holding
the secret can mint tokens, including Admin tokens. Replacing or deleting it
invalidates existing tokens. Existing deployments switching from the host
`.secrets/jwt-secret` get a new secret in the volume and must log in again;
the host file is not automatically migrated.

```sh
make ps
make logs
```

`make logs` follows output; press Ctrl-C to stop following without stopping services.

API initializes SQLite on startup with these local demo accounts:

| Username | Password | Role |
|---|---|---|
| Alice | alice-password | user |
| Bob | bob-password | user |
| Admin | admin-password | admin |

These fixed credentials are only for the local assignment. SQLite stores bcrypt
hashes, and initialization preserves existing accounts and hashes.
Usernames are case-sensitive.

Compose mounts `users-data` at `/data` only in API. Event and Detection have no
database mount. The volume preserves both the database and signing secret through
container recreation and `docker compose down`; `docker compose down --volumes`
deletes both and invalidates existing tokens.

For a local API run without Docker:

```sh
go run ./cmd/api
```

API loads `.secrets/jwt-secret` relative to the working directory by default.
Set `JWT_SECRET_FILE` to override the path. API creates a missing parent directory
with permissions `0700` and generates a missing secret as described above.
Existing secrets must contain at least 32 bytes after trimming whitespace.
Git ignores `.secrets`, and Docker excludes it from build contexts. No environment
file, key pair, or PEM format is needed. Log in below to obtain an expiring JWT.
The database defaults to `users.db`
in the working directory. Set `USERS_DB_PATH` to override it; its parent directory
must exist and be writable.

The schema is in [`cmd/api/internal/users/schema.sql`](cmd/api/internal/users/schema.sql)
and embedded in the API binary. API applies it and seeds missing accounts on startup.
The generated `users.db` is ignored by Git and excluded from Docker build contexts.

### Log in and authenticate

Log in with one of the demo accounts:

```sh
curl --fail --silent --show-error http://127.0.0.1:8080/login \
  -H 'Content-Type: application/json' \
  --data '{"username":"Alice","password":"alice-password"}'
```

The JSON response contains `access_token`, `token_type` (`Bearer`), and
`expires_in` (`900` seconds). Tokens use HS256 and contain the user ID in `sub`,
the `role`, issuer `mini-siem`, audience `mini-siem-api`, and expiration `exp`.
Responses never include passwords, hashes, or signing secrets.

Copy `access_token` into the request below:

```sh
TOKEN='<access_token from login>'
curl --fail --silent --show-error http://127.0.0.1:8080/me \
  -H "Authorization: Bearer $TOKEN"
unset TOKEN
```

For Alice in a freshly seeded database, `/me` returns `{"id":1,"role":"user"}`.
Bob and Admin use the same flow with their own credentials. Wrong passwords and
unknown users both return HTTP 401 with the same error. `/me` returns HTTP 401
for missing or invalid bearer tokens, including expired tokens, invalid signatures,
wrong algorithms, issuer or audience, and missing required claims. Log in again
after a token expires; refresh tokens and revocation are outside this scope.
Login and authentication errors return JSON with an `error` message.

Login accepts one JSON object containing only `username` and `password`, with a
64 KiB body limit. Malformed input returns HTTP 400, oversized input returns
HTTP 413, and an unsupported content type returns HTTP 415. Authentication
responses are not cached, and credentials and tokens are not logged.
The local HTTP setup is for the assignment; use TLS before exposing it publicly.

### Verify

After `make up`, verify the running setup:

```sh
make verify
```

This checks all three health endpoints and stops after printing
`All three health checks passed.`

Run the Go tests, including authentication checks, with `make test`. For manual requests, see
[curl examples](docs/curl.md).

Check API from the host directly:

```sh
curl --fail --silent --show-error http://127.0.0.1:8080/health
```

Check Event and Detection from API's container over the backend network:

```sh
docker compose exec -T api wget -qO- http://event:8080/health
docker compose exec -T api wget -qO- http://detection:8080/health
```

Each command should print `ok` and exit successfully.

Inspect service status and published ports:

```sh
docker compose ps
```

Only API should show a published host port.

### Stop

```sh
make down
```
