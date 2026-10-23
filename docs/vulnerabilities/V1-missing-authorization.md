# Authorization in Mini-SIEM

Authentication answers **who is calling**; authorization answers **what that
caller may do and whose data they may access**. Mini-SIEM uses an admin-role check,
owner-based access and signed service permissions. Login and health endpoints
are public; the data operations require authenticated authority.

## Where authorization is used

| Location | What it enforces |
| --- | --- |
| [API routes](../../cmd/api/handlers.go) | Authenticates user JWTs and checks `role == "admin"` before granting cross-owner event access. Login takes the role from the account store, not the request. |
| [API event proxy](../../cmd/api/events.go) | Signs an exact Event action for the authenticated principal using a separate service key. |
| [API detection handler](../../cmd/api/detections.go) | Issues separate run, event-read and alert-write permissions for one owner and job. |
| [Event routes](../../cmd/event/handlers.go) | Verifies operation-specific authority before event reads/writes. Ordinary and job event reads filter by the verified owner; admin listing requires `events:list_all`. |
| [Event alert routes](../../cmd/event/alerts.go) | Requires alert-read authority for owner-filtered listing and signed job authority for writing alerts under that job's owner. |
| [Detection](../../cmd/detection/handlers.go) | Verifies run authority, checks read/write permissions belong to the same owner and job, and rejects cross-owner event data. |
| [Shared middleware](../../internal/auth/middleware.go), [Event tokens](../../internal/auth/event.go), [job tokens](../../internal/auth/job.go) | Validate signatures, intended service, action, expiry and principal; job requests also require the matching job ID. [User-token validation](../../internal/auth/token.go) establishes identity and role, rather than authorizing every operation. |
| [Event store](../../cmd/event/internal/events/store.go) and [alert store](../../cmd/event/internal/events/alerts.go) | Filter ordinary reads by owner. They trust the owner supplied by authorized handlers; `ListAll()` itself has no role check. |

Comments in these files identify the checks, delegation points and owner scope.

## Important code: with and without authorization

The “without” examples below are illustrative only. They are not applied changes
or observed vulnerability results.

### 1. API decides who may read every user's events

Current code in `cmd/api/handlers.go`:

```go
router.GET("/admin/events", tokens.Middleware(), func(c *gin.Context) {
    identity, _ := auth.FromContext(c.Request.Context())
    if identity.Role != "admin" {
        c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
        return
    }
}, events)
```

Without the role decision, while retaining authentication:

```go
router.GET("/admin/events", tokens.Middleware(), events)
```

Alice and Bob could still prove their identities, but would no longer be denied
the privileged operation. The proxy would sign `events:list_all` for them and
Event would accept that valid permission. The consequence would be vertical
privilege escalation: an ordinary user reading other users' events.
The secure version returns HTTP 403 to Alice/Bob and permits Admin.

### 2. Event limits ordinary reads to the verified owner

Current code in `cmd/event/handlers.go`:

```go
owned := store.ListByOwner(identity.ID)
```

Without owner isolation:

```go
owned := store.ListAll()
```

Even a valid ordinary `events:list` permission would then expose every owner's
events. This would be horizontal access-control failure. Authentication and a
valid operation token do not replace filtering the returned data. Admin's
ordinary `GET /events` also remains owner-scoped in the secure implementation.
Event and alert writes similarly derive ownership from verified authority,
rather than accepting a client-selected owner.

### 3. API delegates authority; Event checks it again

API's event proxy issues authority using:

```go
token, err := tokens.SignEvent(identity.ID, action)
```

`SignEvent` includes the exact action, authenticated principal, issuer
`mini-siem-api`, audience `mini-siem-event` and a 30-second expiry. It uses a
different key from public user JWTs. Event's admin route requires that authority;
this excerpt shows the relevant difference if its gate were removed:

```diff
-router.GET("/admin/events", tokens.EventMiddleware(auth.ListAllEvents), func(c *gin.Context) {
+router.GET("/admin/events", func(c *gin.Context) {
```

Without this middleware, a caller able to reach Event could invoke its unfiltered
admin listing directly without delegated authority, bypassing API's role check.
In the current implementation, missing, invalid or incorrectly scoped authority
returns HTTP 401 at Event.

Simply forwarding a public user JWT instead of signing Event authority would
also fail with HTTP 401: these credentials are deliberately not interchangeable.

### 4. Detection permissions belong to one owner and one job

API signs three permissions:

```go
run, runErr := auth.SignJob(jobKey, identity.ID, jobID, auth.DetectionService, auth.RunDetection)
read, readErr := auth.SignJob(jobKey, identity.ID, jobID, auth.EventService, auth.ListEvents)
write, writeErr := auth.SignJob(jobKey, identity.ID, jobID, auth.EventService, auth.AddAlerts)
```

Detection verifies the read and write signatures/scopes, then rejects mismatches:

```go
if readErr != nil || writeErr != nil || readScope != scope || writeScope != scope {
    c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid job permissions"})
    return
}
```

Without this decision, Detection could combine a run permission with valid
read/write permissions from different owners or jobs. Event would still validate
each capability independently, but Detection would lose the guarantee that the
whole workflow belongs to the initiating owner and job.

## Security consequences of the multi-service architecture

**Each service boundary needs its own check.** The flow is client → API →
Event, or client → API → Detection → Event. Event and Detection do not trust a
request just because it arrived over the backend network. API makes user-facing
policy decisions; downstream services validate the authority for their specific
operation. Removing API's role check cannot be repaired by Event checking a
correctly signed permission that API should never have issued.

**Separation limits access, but does not make services equally trusted.** Only
API accesses the users database and user-JWT key. Detection receives a job
verification public key, so it cannot mint new job permissions. Event and API
share the Event HMAC key: either holder can technically mint Event capabilities.
Compromising that key threatens Event authorization, even though it does not
provide the separate user-JWT or job-signing keys.

**Narrow delegation limits what a permission can do.** A list permission cannot
write events or alerts, and job permissions carry one owner/job. Short expiry
limits the lifetime of stolen tokens, but does not prevent replay before expiry.
A compromised Detection process could misuse permissions it already holds.

**Network isolation is another layer.** [Compose](../../compose.yaml) publishes
only API on localhost; Event and Detection stay on the internal backend network.
That reduces direct exposure but does not replace authorization. Local service
traffic uses HTTP, so tokens are not protected by TLS; this setup is intended
for the local assignment.

**More hops add failure points and verification work.** Keys, audiences, actions
and owner/job scope must agree across services. Invalid authority is rejected,
and API reports downstream rejection as a gateway failure rather than granting
access. Service outages can prevent otherwise authorized operations.

This update adds explanatory comments and documentation only. Security controls
remain active. The insecure examples describe consequences inferred from the
code; no vulnerable implementation was run and no Git operations were performed.
