# Mini-SIEM

Mini-SIEM is a small security event monitor for Assignment I. Alice, Bob, and Admin submit events and inspect their own events and alerts. Admin can also view all users' events through a separate operation. A detection run checks the caller's events for at least five failed logins from the same IP within five minutes and saves alerts.

The planned system has three separate Go services: API authenticates users, Event stores events and alerts, and Detection finds patterns using the separately installed `eventkit` package. Users log in with seeded accounts stored in SQLite and receive short-lived JWTs. API alone accesses the users database and establishes scoped authority for inter-service calls. The detection run calls all three services.

The services will run locally with Docker Compose. The users database will persist in an API-only volume. Events and alerts will stay in memory and be lost when Event restarts. HTTP endpoints and automated tests provide the interface; curl examples will show how to use it.

## Project documents

- [Initial SSDLC plan](docs/initial-plan.md), including requirements, architecture, access control, threat model, and lifecycle gates
- [Component diagram](docs/diagrams/components.mmd), [data flow](docs/diagrams/data-flow.mmd), and [detection sequence](docs/diagrams/detection-sequence.mmd)

## Status

The plan describes the intended system. The services, tests, Jenkins pipeline, final report, AI-use declaration, and exact build and run commands are still to be added. Use only synthetic data and local seeded accounts.
