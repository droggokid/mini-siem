# Mini-SIEM

Mini-SIEM is a small security event monitor for Assignment I. Alice, Bob, and Admin submit events and inspect their own events and alerts. Admin can also view all users' events through a separate operation. A detection run checks the caller's events for at least five failed logins from the same IP within five minutes and saves alerts.

The planned system has three separate Go services: API authenticates users, Event stores events and alerts, and Detection finds patterns using the separately installed `eventkit` package. Users log in with seeded accounts stored in SQLite and receive short-lived JWTs. API alone accesses the users database and establishes scoped authority for inter-service calls. The detection run calls all three services.

The services will run locally with Docker Compose. The users database will persist in an API-only volume. Events and alerts will stay in memory and be lost when Event restarts. HTTP endpoints and automated tests provide the interface; curl examples will show how to use it.

## Project documents

- [Initial SSDLC plan](docs/initial-plan.md), including requirements, architecture, access control, threat model, and lifecycle gates
- [Component diagram](docs/diagrams/components.mmd), [data flow](docs/diagrams/data-flow.mmd), and [detection sequence](docs/diagrams/detection-sequence.mmd)

## Local development

Requirements: Go 1.27.3, Docker with Docker Compose, and curl.

API, Event, and Detection are separate executables. Each exposes
`GET /health`, returning HTTP 200 with the body `ok`.

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

```sh
docker compose up --build
```

Leave this running and open another terminal for verification.

### Verify

Check API from the host:

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
docker compose down
```