# eventkit

Module: `github.com/droggokid/mini-siem/eventkit`

Version: `v0.1.0` (repository tag `eventkit/v0.1.0`)

Requires Go 1.27.3. Uses only the Go standard library.

Install from a Go module:

```sh
go get github.com/droggokid/mini-siem/eventkit@v0.1.0
```

Call `eventkit.Detect([]eventkit.Event{...})` to receive `[]eventkit.Finding`.
An event needs only `Type`, `SourceIP`, and `IngestedAt`. A finding contains
`SourceIP`, `DetectionType` (`failed_login_burst`), and `FailedLoginCount`.

The rule groups `login.failed` events by canonical IP address and returns one
finding per IP with at least five failures within any rolling five-minute
window, including timestamps exactly five minutes apart. Each finding reports
the largest count. Results are sorted by IP; input order is unchanged. Invalid
IPs and other event types are ignored. Historical events participate, and no
findings returns a nil slice.

Callers must authorize and validate their data and pass events for a single
owner. This module has no ownership, HTTP, authentication, storage, or service
dependencies. JSON field tags let callers retain the existing event/alert wire
format without adding serialization code to the rule.

Test independently from this directory:

```sh
GOWORK=off go test -count=1 ./...
GOWORK=off go test -race ./...
GOWORK=off go vet ./...
```

No `go.sum` is needed here because the module has no external dependencies.
The consuming service records the released module's checksums in its `go.sum`.
See the [repository README](../README.md#eventkit-dependency) for clean service
builds and release guidance. Never move or overwrite a published version tag.
