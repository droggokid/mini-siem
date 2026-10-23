# Mini-SIEM

Mini-SIEM is a small security event monitor for Assignment I. Users submit events,
view their own events and alerts, and run detection. Five or more `login.failed`
events from the same IP within any rolling five-minute window produce a
`failed_login_burst` alert. Admin can also list every user's events; Admin's
ordinary event, alert and detection requests still use Admin's own records.

The project runs as three Go services over HTTP:

| Component | Responsibility |
|---|---|
| API | Authenticates users, reads the SQLite users database and delegates authorized requests. The only service exposed to the host. |
| Event | Stores events and alerts in memory and independently checks delegated permissions. |
| Detection | Reads the caller's events, applies the separately versioned [eventkit rule](eventkit/README.md) and sends alerts to Event. |

This is a local assignment demo with fixed accounts. Start it below, then use the
[Postman collection](docs/mini-siem.postman_collection.json) or
[curl walkthrough](docs/curl.md) to exercise the API, detection and access checks.

## Requirements

- To run the demo: Docker with Docker Compose, Make and curl.
- To build or test locally: Go **1.27.3**, as declared by both modules.
- For CI helpers: Compose **2.24.4+**, Bash and Python 3; a C compiler for race tests.

Run all commands below from the repository root unless a command changes directory.

## Quick start

Build and start all three services:

```sh
make up
```

`make up` runs `docker compose up --build -d`. On API startup, the application
automatically creates the users table and seeds any missing demo accounts:

| Username | Password | Role |
|---|---|---|
| Alice | alice-password | user |
| Bob | bob-password | user |
| Admin | admin-password | admin |

There is no separate seed command. Startup preserves existing accounts and stores
bcrypt password hashes. API also generates missing signing secrets and keys.
Compose keeps the users database and keys in project volumes; only API has the
database and private keys. Events and alerts disappear when Event restarts.

API is available at `http://127.0.0.1:8080`. Event and Detection are reachable only
inside the Compose network.

### Verify

Check all three health endpoints:

```sh
make verify
```

This prints `All three health checks passed.` on success. To check them individually:

```sh
curl --fail --silent --show-error http://127.0.0.1:8080/health
docker compose exec -T api wget -qO- http://event:8080/health
docker compose exec -T api wget -qO- http://detection:8080/health
```

Each returns `ok`. These checks confirm service availability; use the workflow
below to check application behavior.

### Stop and inspect

Inspect or stop the stack:

```sh
make ps
make logs
# Press Ctrl-C to stop following logs.
make down
```

`make down` preserves the users database and keys. Removing Compose volumes
deletes them and invalidates existing tokens.

## Test the running project

### Postman collection

The [collection](docs/mini-siem.postman_collection.json) contains executable
requests and response assertions for the public API. Import it together with the
[environment](docs/mini-siem.postman_environment.json), then:

1. Select the **Mini-SIEM local** environment. Leave `api_host` as
   `127.0.0.1:8080`, without a scheme or path.
2. With the services running, run the **API — run in order** folder from top to
   bottom. The login requests save Alice, Bob and Admin tokens automatically.
3. Complete the five Alice failed-login submissions within five minutes so the
   detection assertion has a qualifying burst. Review the response assertions;
   requests expecting HTTP 400, 401 or 403 pass when those rejections occur.

The workflow exercises:

| Scenario | Expected behavior |
|---|---|
| Health, login and identity | API responds; valid logins return tokens; identity requires authentication. |
| Event submission and listing | Valid events are stored; invalid IPs and client-supplied ownership are rejected. Users request their own event lists. |
| Alice's five failed logins | Detection scans at least five events and creates a `failed_login_burst` alert for `192.0.2.1`. |
| Bob and Admin detection and alerts | Neither analyzes Alice's events or receives Alice's alerts. |
| Admin event listing | `/admin/events` includes Alice, Bob and Admin events; Alice and Bob receive HTTP 403. |
| Missing tokens and unsupported queries | Protected requests without tokens return HTTP 401; owner selection and other unsupported queries return HTTP 400. |

Use a fresh Event process for predictable results: the collection expects Bob
and Admin to have no qualifying events or existing alerts. Restarting Event
discards **all** in-memory events and alerts. Repeated detection runs can create
additional alerts from the same historical events. User tokens expire after
15 minutes; rerun the logins when needed and keep captured tokens local.

For Apidog import settings and troubleshooting, see the
[collection instructions in curl.md](docs/curl.md).

### curl walkthrough

[docs/curl.md](docs/curl.md) provides the terminal version: log in, copy the
tokens, submit events, run detection, retrieve alerts and check user/admin access.
It includes expected status codes, input-validation failures and direct
internal-service authorization checks. Run its commands in the same terminal
so the token variables remain available.

## Automated tests

Run all tests in both Go modules:

```sh
make test
```

Run the ordinary tests, race tests and static analysis explicitly:

```sh
export GOWORK=off GOFLAGS=-mod=readonly
go test -count=1 ./...
go test -race -p=1 -count=1 ./...
go vet ./...
(cd eventkit && go test -count=1 ./...)
(cd eventkit && go test -race -count=1 ./...)
(cd eventkit && go vet ./...)
test -z "$(gofmt -l .)"
```

Tests cover authentication, input validation, events, alerts, detection, admin
permissions and inter-service authorization. The root integration test builds and
starts real service executables with temporary keys and a fresh database.

To test the actual Docker Compose system in a fresh, isolated environment:

```sh
go install gotest.tools/gotestsum@v1.13.0
export PATH="$(go env GOPATH)/bin:$PATH"
bash scripts/ci-compose.sh
python3 scripts/ci-reports.py
```

The helper builds all images, waits for three healthy services, sets
`MINI_SIEM_TEST_URL` to a random loopback API port and runs
`TestDetectionIntegration`. It checks login, submission, detection, alerts,
admin listing and rejected unauthorized requests, then removes its containers,
networks and volumes. It leaves the development stack alone.

## Build

Download and verify the existing pinned dependencies, then build each executable:

```sh
export GOWORK=off GOFLAGS=-mod=readonly
go mod download
go mod verify
(cd eventkit && go mod download && go mod verify)
go build -o bin/api ./cmd/api
go build -o bin/event ./cmd/event
go build -o bin/detection ./cmd/detection
```

To build the three Docker images without starting them:

```sh
docker compose build
```

### eventkit dependency

Detection resolves `github.com/droggokid/mini-siem/eventkit v0.1.0` from the
published `eventkit/v0.1.0` tag. Root `go.mod`/`go.sum` pin that dependency;
the local `eventkit/` module is tested independently. No local replacement or
workspace is required. The library uses only the standard library and has no
`go.sum`. See [the library documentation](eventkit/README.md).

Verify the published dependency and generate an inventory:

```sh
bash scripts/ci-dependencies.sh
```

New library releases need a new `eventkit/vX.Y.Z` tag and a reviewed update to
the root dependency and checksums. Never overwrite published tags.

## CI

[GitHub Actions CI](https://github.com/droggokid/mini-siem/actions/workflows/ci.yml)
runs on every push, pull requests to `main`, and manual execution. Required gates
cover dependency verification, builds, formatting, vet, ordinary/race tests,
HIGH/CRITICAL dependency vulnerabilities and healthy Compose integration.

See [CI documentation](docs/ci.md) for report downloads, exact local scanner
commands, the failing authorization-gate demonstration and branch protection.

## Project documents

- [Initial SSDLC plan](docs/initial-plan.md)
- [Design decisions](docs/design-decisions.md)
- [API requests](docs/curl.md)
- [Postman collection](docs/mini-siem.postman_collection.json) and [environment](docs/mini-siem.postman_environment.json)
- [Components](docs/diagrams/components.mmd), [data flow](docs/diagrams/data-flow.mmd) and [detection sequence](docs/diagrams/detection-sequence.mmd)
