# Mini-SIEM: initial SSDLC plan

This is the plan for Assignment I, written before feature implementation. Mini-SIEM will let users submit security events, inspect their own events and alerts, and request a detection run. Alice and Bob are ordinary users. Admin may also view all users' events through a separate operation. Only synthetic data and these three seeded accounts are in scope.

The system will have three Go services, two main resources (events and alerts), one SQLite database containing only users, and one fixed detection rule. The services will run locally with Docker Compose. The users database will persist in an API-only volume. Events and alerts will stay in memory and be lost when Event restarts. HTTP endpoints, automated tests, and curl examples will provide the interface. A GUI, registration, public hosting, and real-time processing are outside the scope.

## Requirements and operations

### Functional requirements

| ID | Operation and expected result | Verification |
|---|---|---|
| FR-01 | Log in as Alice, Bob, or Admin with a seeded username and password and receive a short-lived JWT. | Correct credentials return a JWT; wrong passwords and unknown users fail. |
| FR-02 | Submit an event under the authenticated owner. | Stored ownership comes from the caller, not the payload. |
| FR-03 | List the caller's events. | Alice's list excludes Bob's events. |
| FR-04 | Run detection on the caller's events and save alerts for at least five failed logins from the same IP within a five-minute window. | Test the count and time boundaries and confirm that all three services participate. |
| FR-05 | List the caller's alerts. | Alice's list excludes Bob's alerts. |
| FR-06 | Let Admin list all users' events through a separate admin operation. | Admin succeeds; Alice, Bob, and Detection are denied. |

### Non-functional requirements

| ID | Requirement | Verification |
|---|---|---|
| NFR-01 | Protected API operations require a JWT with a valid signature, expected algorithm, issuer, audience, expiry, and required claims. | Missing, altered, expired, or wrongly targeted JWTs are rejected, including tokens without required claims. |
| NFR-02 | Ordinary operations are limited to the caller's records; only the admin event list may cross owners. | Cross-user access fails; Admin cannot read others' alerts or run detection on their events. |
| NFR-03 | Event and Detection enforce inter-service authorization scoped to the receiving service, owner or resource, action, validity period, and job where relevant. | User JWTs at internal services, unauthorized direct-service calls, and missing, expired, or mismatched authority fail. |
| NFR-04 | Reject malformed input, including invalid source IP addresses, and limit JSON request bodies to 64 KiB. | Invalid or oversized input is rejected without storing records; valid source IPs and boundary-sized requests succeed. |
| NFR-05 | Functional and security checks run automatically. | Test valid workflows, forbidden operations, and the fixes for all four planted flaws. |
| NFR-06 | Three separate services run locally through Docker Compose and communicate over HTTP/JSON. Only API mounts the users database volume. | Start a fresh environment with a newly seeded database, complete detection, and check database access is limited to API. |
| NFR-07 | Builds are reproducible and use approved, declared dependencies. | Build in a clean environment using the pinned toolchain, dependency versions, and artifact checks. |
| NFR-08 | Jenkins runs on every push and pull request, saves results, and fails when a release gate fails. | Check both triggers, archived results, and a deliberately failing gate. |
| NFR-09 | Store salted password hashes using an established library. Keep passwords, hashes, and private keys out of responses, and credentials and tokens out of logs. | Check stored values and logs; confirm login verifies password hashes and errors reveal no secrets. |

## Architecture and data flow

[Component diagram](diagrams/components.mmd) · [Data flow with trust boundaries](diagrams/data-flow.mmd) · [Detection sequence](diagrams/detection-sequence.mmd)

| Component | Responsibility | Authority |
|---|---|---|
| API | Check credentials against SQLite, handle public requests, issue user JWTs, and establish scoped authority for inter-service calls. | Alone accesses the users database and holds the private signing key. |
| Event | Store events and alerts in memory. | Checks every read and write, including admin event lists. |
| Detection | Analyze one user's events using the separate `eventkit` dependency. | Acts only for the delegated owner and job; cannot expand its authority or access storage directly. |

A client sends a username and password to API's login endpoint. API reads the seeded user's ID, username, password hash, and role from SQLite using parameterized queries, then verifies the password hash. Successful login returns a short-lived JWT naming the user, role, issuer, API audience, and expiry. The client sends this token as a bearer token with later requests. Wrong passwords and unknown users receive the same login error.

API signs user JWTs and verifies their signature, expected algorithm, issuer, audience, expiry, and required claims. User JWTs are accepted only by API. Only API holds the private signing key.

API delegates only the authority needed for each operation. Event and Detection verify the requesting user, receiving service, owner or resource scope, action, validity period, and job where relevant. Detection may read only that owner's events and write alerts for the authorized job; it may not submit events, list alerts, or use the admin operation. Event independently authorizes every read and write. Ownership comes from verified authority, never from JSON. The inter-service authorization mechanism will be selected during implementation.

SQLite runs inside API and stores only users. Event and Detection cannot access its file or volume. Tests start with a fresh database seeded with Alice, Bob, and Admin. Account management, refresh tokens, and token revocation are outside the scope; issued user JWTs remain valid until expiry, after which the user logs in again.

For the admin event list, API checks the user's role and delegates authority limited to listing all events. Event verifies this authority before returning records across owners. Ordinary operations always name a single owner, including when Admin uses them. Admin event-list authority cannot authorize alert access, writes, or detection jobs.

The helper `eventkit` will be our own small Go module in a separate directory or repository, with its own `go.mod`, declared and installed as a versioned dependency of Detection. Its code will not be copied into the service. Acceptance requires a clean build to resolve the declared module and a detection test to exercise its rule implementation.

The boundaries are **TB1** client → API, **TB2** API → Event, **TB3** API → Detection, **TB4** Detection → Event, and **TB5** Detection → `eventkit`. An internal call does not imply permission. TB5 marks dependency trust, not process isolation: `eventkit` executes with Detection's process privileges.

## Assets and access control

| Asset | Owner or custodian | Required protection |
|---|---|---|
| Events | Submitting user; stored by Event | The owner, Detection for that owner's job, and the separate admin event-list operation may read them. Only the owner may submit them. |
| Alerts | User whose events were analysed; stored by Event | Only the owner may list them. Only Detection may write them for an authorized job. |
| Users database and password hashes | API | Store seeded user IDs, usernames, password hashes, and roles. Persist the file in an API-only volume and keep hashes private. |
| Private signing key | API | Keep it private and prevent other services from signing user JWTs. |
| User JWTs | Issued by API; held by clients | Accept only at API, verify required claims, and keep complete tokens out of logs. |
| Delegated authority | Established by API; checked by Event and Detection | Prevent forgery and use outside the stated service, scope, action, validity period, and job. |
| `eventkit` artifact and build inputs | Project maintainers | Pin versions and reject undeclared, unapproved, or malformed artifacts. |

| Action | Alice | Bob | Admin | Detection |
|---|---|---|---|---|
| Submit event | Own | Own | Own | Denied |
| List events | Own | Own | Own | Delegated owner/job only |
| List alerts | Own | Own | Own | Denied |
| Run detection | Own | Own | Own | Delegated job only |
| Write alerts | Denied | Denied | Denied | Delegated owner/job only |
| List all users' events | Denied | Denied | Allowed | Denied |
| Access users database or sign JWTs | Denied | Denied | Denied | Denied; API only |

Admin's extra permission is limited to listing all events. Alerts and detection jobs stay limited to the caller's own records. Missing, altered, expired, or mismatched authority fails before any protected data is returned or any side effect occurs.

## STRIDE threats and controls

| Threat | Example | Planned control and evidence |
|---|---|---|
| Spoofing | Client claims to be Alice (TB1). | Verify the password hash at login and validate JWTs; failed-login and invalid-token tests. |
| Tampering | Caller changes a JWT role, delegated owner, or action (TB1–TB4). | Validate JWTs and delegated authority; tamper and wrong-service tests. |
| Repudiation | Detection run has no accountable requester (TB3). | Log user and job ID; inspect job logs. |
| Information disclosure | Alice's job reads Bob's events (TB4), or another service accesses password hashes. | Event checks owner on every read; restrict the database volume to API; cross-user and database-access checks. |
| Denial of service | Oversized input (TB1–TB3). | Limit JSON request bodies to 64 KiB; boundary and rejection tests. |
| Elevation of privilege | Alice requests the admin event list (TB1–TB2). | API checks the role; Event checks the admin event-list authority; role and direct-service tests. |

The design applies **least privilege** through job-scoped authority, **complete mediation** through Event's checks on every operation, and **fail-safe defaults** through rejection of missing or invalid authority. Direct-service, cross-job, and malformed-input tests will verify these decisions.

## Lifecycle gates

| Phase | Asset → threat → control and activity | Evidence → gate |
|---|---|---|
| Requirements | Private records → unauthorized access → define functional and non-functional requirements, asset register, boundaries, access matrix, and STRIDE controls. | Review scope, permissions, and controls before implementation. |
| Implementation and build | Credentials, JWTs, and dependency → exposure, forgery, or substitution → hash passwords, restrict database access, protect signing key, use reproducible builds, verify declared `eventkit` artifact. | Failed builds, analysis gates, or artifact checks block progress. |
| Testing | Credentials, events, and alerts → unauthorized access or malformed input → login, JWT validation, functional, and negative authorization tests with a fresh seeded database. | Failed tests or acceptance of malformed artifacts block release. |
| Release and operation | Credentials and records → exposure or loss → assess TLS, secret management, durable storage, and audit logs. | Record production gaps in the final report. |

Builds will pin the Go toolchain, dependency versions, and container images. The repository will retain `go.mod` and `go.sum` where dependencies require it. Local runs and Jenkins will use the same documented build procedure from a clean checkout, including verification of the approved `eventkit` artifact.

Jenkins will run on every push and pull request. It will build the services, run static and dependency analysis, start a fresh Docker Compose test environment, run functional and authorization tests, and archive test and analysis results.

The pipeline will fail on build or analysis errors, undeclared or unapproved dependencies, malformed artifacts, failed functional or security tests, and confirmed high or critical dependency vulnerabilities. Any confirmed violation of the required security guarantees will also block release, regardless of severity. Confirmed violations must be fixed before release.

## Planned vulnerability evidence

The three selected course-catalog vulnerabilities are CWE-20, CWE-89, and CWE-862. The fourth experiment targets cross-service composition.

| Experiment | Vulnerable behavior and observable exploit | Fix and regression evidence |
|---|---|---|
| V1 — CWE-862: Missing Authorization | Bob calls the restricted admin event-list operation. API omits its role check and delegates admin event-list authority, exposing Alice's events through the normal API path. | API requires the privileged role before delegating that authority; Event requires the specific admin event-list action. Bob is denied and Admin succeeds. |
| V2 — CWE-89: SQL Injection | API concatenates a login username into its SQLite lookup. A crafted username changes the query to return a privileged identity with a valid password hash chosen by the attacker. Password verification still runs, but the attacker receives privileged authority. | Use parameterized queries. The exploit cannot replace the returned identity or obtain a privileged JWT; ordinary seeded-account login still works. |
| V3 — CWE-20: Improper Input Validation | Event accepts an event submitted through API with source IP `999.999.999.999`, storing invalid data for detection. | Validate source IP addresses before storage. Reject the invalid address without a write; a valid source IP is accepted. |
| V4 — cross-service confused deputy | Bob's authenticated analysis request supplies Alice's owner ID. In the vulnerable variant, Detection forwards that target and Event trusts Detection's service authority instead of enforcing the delegated owner. Bob receives an alert derived from Alice's events, although direct requests for Alice's events remain denied. | Derive ownership from verified delegated authority and reject caller-selected ownership. Detection checks the owner and job scope, and Event enforces that owner on every read and write. Bob's request cannot produce Alice-derived results; his legitimate job still works. |

V1 removes the ordinary user's role check on a privileged operation. V4 keeps ordinary API authorization intact and exposes a mismatch between a processing request and the authority enforced by another service. V4 uses a valid Bob identity, not a forged JWT. Each experiment starts from the secure baseline and changes only the behavior needed to expose its own flaw.

All four flaws are required. Each will have an isolated vulnerable commit or branch, an exploit trace, a fix, and a regression test. The final version must pass all regression tests and deny the unauthorized operations.

The optional supply-chain experiment is deferred. If attempted, a malicious `eventkit` version must enter through the dependency install path; digest checks alone cannot contain an approved malicious package running inside Detection.

## Submission evidence

- Commit this settled lifecycle plan and its diagrams before feature implementation; preserve the full Git history and link the initial-plan commit in the report.
- Provide exact README commands to build, seed, run, and test the three services and install the declared `eventkit` dependency.
- Include the Jenkinsfile, functional and authorization tests, archived analysis and test results, and evidence of a deliberately failing release gate.
- Write the 2,000–2,500-word report, excluding diagrams, tables, references, code excerpts, and appendices. Link design principles and all four experiments to code, commits, tests, logs, and gate results; discuss production-release gaps.
- Submit the source repository, required artifacts, report, and AI-use declaration. The optional supply-chain experiment remains outside the MVP.
