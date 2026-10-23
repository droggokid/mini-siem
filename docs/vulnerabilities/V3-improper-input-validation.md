# Input validation in Mini-SIEM

Input validation checks whether data has the expected size, structure and meaning
before the application uses it. Mini-SIEM validates public requests, internal
requests, service responses and startup configuration. Authentication establishes
who sent a request; it does not establish that its contents are valid.

## Where validation is used

| Location | What it checks |
| --- | --- |
| [API login](../../cmd/api/handlers.go) | JSON content type, a 64 KiB body limit, one valid JSON document, known fields, string types and nonempty credentials. |
| [API event/alert proxy](../../cmd/api/events.go) | Rejects query parameters, oversized bodies and GET bodies. Event performs the event-field validation before storage. |
| [API detection request](../../cmd/api/detections.go) | Accepts an empty body or one empty JSON object; rejects unknown parameters, null, wrong types, trailing JSON and oversized input. Nonempty bodies require JSON content type. |
| [Event submission](../../cmd/event/handlers.go) | Independently requires JSON, limits the body and accepts only `type` and `source_ip`. IDs, owners and timestamps are server-controlled. |
| [Event store](../../cmd/event/internal/events/store.go) | Requires a positive owner, nonblank event type and parseable source IP before appending an event. |
| [Event alert/list requests](../../cmd/event/alerts.go) | Shared `readRequest` rejects query parameters, GET bodies and oversized input, and checks POST content type. Alert writes require a non-null array containing known fields. |
| [Alert store](../../cmd/event/internal/events/alerts.go) | Validates every IP, detection type and minimum count; normalizes IPs, rejects duplicates and appends only after the whole batch passes. |
| [Detection](../../cmd/detection/handlers.go) | Validates its internal request, then checks Event's returned array, owner, timestamp and source IP. Checks generated alert size and the returned write count. |
| [API startup](../../cmd/api/main.go), [Detection startup](../../cmd/detection/main.go) | Validate configured service URLs. API also rejects reuse of signing material across trust domains. |
| [Signing-key initialization](../../cmd/api/job_key.go), [public-key loading](../../internal/auth/job_key.go) | Validate key encoding, exact key size and, in API, consistency with an existing public key. |
| [Shared authentication](../../internal/auth/middleware.go) | Rejects ambiguous bearer headers; token validators check signed claims and scopes. These authorization-related checks are covered in [V1](V1-missing-authorization.md). |
| [Detection rule](../../eventkit/rule.go) | Ignores invalid IPs and unrelated event types and groups equivalent IP addresses. This does not replace rejecting invalid events before storage. |

Comments at these boundaries explain why the checks are needed. No validation
logic was changed.

## Important code: with and without validation

The examples without checks below are illustrative only. They were not applied
or executed; their consequences are inferred from the current code.

### 1. Limit input before buffering it

Request handlers use:

```go
body, err := io.ReadAll(http.MaxBytesReader(c.Writer, c.Request.Body, 64*1024))
```

They check the read error and return HTTP 413 for `*http.MaxBytesError`, or HTTP
400 for other body-read failures. The limit is enforced while reading, rather
than trusting a caller-supplied length. See [Go's MaxBytesReader documentation](https://pkg.go.dev/net/http#MaxBytesReader).

Without the limit:

```go
body, err := io.ReadAll(c.Request.Body)
```

A caller could make the service buffer a much larger request. This increases
memory pressure and denial-of-service risk. A downstream limit does not recover
the memory already consumed in an upstream proxy.

### 2. Validate the complete JSON document and its allowed fields

Event submission declares the accepted shape and rejects invalid input:

```go
var input struct {
    Type     string `json:"type"`
    SourceIP string `json:"source_ip"`
}
decoder := json.NewDecoder(bytes.NewReader(body))
decoder.DisallowUnknownFields()
if !json.Valid(body) || decoder.Decode(&input) != nil {
    c.JSON(http.StatusBadRequest, gin.H{"error": "invalid event request"})
    return
}
```

`json.Valid` checks the complete body, so a second JSON value or trailing garbage
is rejected. Typed decoding checks field types, while `DisallowUnknownFields`
rejects unexpected fields. A single `Decode` reads the next JSON value, rather
than proving there is no additional input. See [Go's JSON decoder documentation](https://pkg.go.dev/encoding/json#Decoder).

Without the strictness, the weaker version would be:

```go
decoder := json.NewDecoder(bytes.NewReader(body))
if decoder.Decode(&input) != nil {
    c.JSON(http.StatusBadRequest, gin.H{"error": "invalid event request"})
    return
}
```

Unknown fields could be silently ignored, and a valid first object followed by
another JSON value could be accepted. Wrong field types would still fail.
Removing this check alone would **not** let `owner_id` override the verified
owner: the input struct has no owner field and storage uses the authenticated
identity. Rejecting unexpected fields keeps the API contract explicit.

Valid JSON also does not guarantee valid values. `null` is syntactically valid
JSON. Detection uses pointer decoding plus `input == nil` to reject it before
accessing capability fields; alert writes reject a nil array. Login requires
nonempty credentials, and event submission still passes through store checks.

### 3. Reject invalid source IPs before storing events

The central V3 check is in `Store.Add`, before the append:

```go
if _, err := netip.ParseAddr(sourceIP); err != nil {
    return Event{}, fmt.Errorf("invalid source IP: %w", err)
}
```

The illustrative removal is:

```diff
-if _, err := netip.ParseAddr(sourceIP); err != nil {
-    return Event{}, fmt.Errorf("invalid source IP: %w", err)
-}
```

With the other checks intact, an otherwise valid event such as
`{"type":"login.failed","source_ip":"999.999.999.999"}` would then reach
storage. The secure implementation returns HTTP 400 without storing it; a valid
documentation address such as `192.0.2.1` is accepted with HTTP 201.

This would corrupt the event dataset. Detection independently rejects invalid
source IPs returned by Event, so a job reading the corrupted data would fail
rather than produce normal results. The lower-level rule's behavior of ignoring
invalid IPs would not repair the stored data. This is a data-integrity and
availability problem; it does not by itself establish SQL injection or code
execution.

### 4. Validate the whole alert batch before committing it

`Store.AddAlerts` validates every finding:

```go
ip, err := netip.ParseAddr(input.SourceIP)
if err != nil || input.DetectionType != "failed_login_burst" || input.FailedLoginCount < 5 {
    return nil, errors.New("invalid alert")
}
```

It also rejects duplicate normalized IPs. The store appends the collected alerts
only after all items pass. Without the condition above, malformed addresses,
unexpected detection types or counts below the rule threshold could be accepted.
Moving the append inside the validation loop would create another problem: an
invalid later item could leave earlier items stored despite the request failing.

These checks establish that findings have an acceptable shape and range; they
do not independently recompute the detection result or prove an authorized
Detection service reported truthful counts.

## Why validation matters across services

**Every hop receives input.** API validates the public request, but Event and
Detection also validate the requests they receive. A signed capability grants
permission for an operation; it does not certify the JSON body. Each receiving
service protects its own contract before processing or storing data.

**Responses are also inputs.** Detection requires a non-null Event array and
checks the owner, ingestion timestamp and IP before invoking the rule. It also
checks that Event acknowledges the expected number of stored alerts. Without
these checks, a malformed service response could become misleading analysis or
an incorrect success report. API checks Detection response JSON syntax, but does
not perform the same detailed schema checks; its Event proxy checks status/read
errors and forwards the response body.

**Validation and authorization support each other.** Query parameters and GET
bodies are rejected instead of being treated as alternate ways to select owners.
Ownership still comes from verified authority. Merely accepting an ignored
parameter would not automatically change that ownership; trusting it downstream
would create the separate authorization failure described in V1.

**Configuration is another input boundary.** Service URL checks accept HTTP or
HTTPS base URLs with a host and no credentials, query, fragment or non-root path.
They check URL structure, not an allowlist of permitted hosts. Invalid or
mismatched key material stops startup rather than silently changing trust.

**The protections have limits.** A 64 KiB request limit does not cap total stored
events, request rate or all service-response sizes: several response paths use
unbounded `io.ReadAll`. Event types may be any nonblank string, and IP parsing
does not establish that an event happened or that an address is trustworthy.
Input validation does not replace [SQL parameter binding](V2-sql-injection.md),
authorization or transport protection.

## Existing checks and reproduction

The existing tests cover malformed/extra JSON, wrong types, unsupported content
types, body-size boundaries, invalid source IPs, rejected selectors, atomic
alert batches, malformed service responses and invalid configuration. Examples
include `TestLoginRejectsInvalidInput`, `TestValidateRequests`,
`TestAddRejectsInvalidInput`, `TestAlertsValidateAtomically`,
`TestDetectionScopeAndValidation` and `TestDetectionWorkflowAndUpstreamFailures`.

From the repository root:

```sh
go test -count=1 ./...
```

This includes the real three-service integration test, which starts isolated
local processes with temporary keys, a fresh user database and synthetic events
when `MINI_SIEM_TEST_URL` is unset. Test the separate local rule module from its
directory:

```sh
cd eventkit
go test -count=1 ./...
```

Actual verification on 2026-10-23: all seven root-module packages and the separate
local `eventkit` module passed. Output excerpts:

```text
ok  github.com/droggokid/mini-siem                7.821s
ok  github.com/droggokid/mini-siem/cmd/api        5.280s
ok  github.com/droggokid/mini-siem/cmd/detection  0.029s
ok  github.com/droggokid/mini-siem/cmd/event      0.024s
ok  github.com/droggokid/mini-siem/eventkit       0.004s
```

No vulnerable implementation was run and no Git operations were performed.
