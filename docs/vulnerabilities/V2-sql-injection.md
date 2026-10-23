# SQL injection prevention in Mini-SIEM

SQL injection happens when untrusted input becomes part of a SQL statement's
syntax. Mini-SIEM prevents this by keeping query structure fixed and passing
values separately as parameters. A username containing quotes or SQL keywords
is treated as a username, not an instruction to the database.

## Where the protection is used

| Location | What it does |
| --- | --- |
| [API login handler](../../cmd/api/handlers.go) | Validates the JSON request and calls `store.Authenticate`. It does not build SQL. Database failures produce a generic response rather than exposing SQL details. |
| [User store](../../cmd/api/internal/users/store.go): `Open` | Configures Squirrel with dollar-style placeholders and the SQLite connection. |
| User store: `Authenticate` | Binds the untrusted login username through `sq.Eq`; checks the password using bcrypt after retrieving the row. |
| User store: `LookupByUsername` | Uses the same parameter binding for username lookups. This helper is not itself a public HTTP endpoint. |
| User store: `initialize` | Executes a fixed, embedded schema and inserts seeded accounts through bound `Values`. The table, column names and conflict clause are fixed source text. |
| [Schema](../../cmd/api/internal/users/schema.sql) | Defines unique usernames and allowed roles. These constraints protect data integrity; they do not replace parameter binding. |

Comments at the SQL construction points explain which parts are fixed SQL and
which parts are bound data.

## Important code: safe and unsafe versions

The unsafe examples below are illustrative only. They have not been applied or
executed, and their consequences are source-based explanations rather than
observed exploit results.

### 1. Bind the username instead of concatenating it

Both lookup methods use this query in `cmd/api/internal/users/store.go`:

```go
err := s.psql.Select("id", "username", "password_hash", "role").
    From("users").
    Where(sq.Eq{"username": username}).
    QueryRowContext(ctx).
    Scan(&row.ID, &row.Username, &row.PasswordHash, &row.Role)
```

The builder is configured with:

```go
psql: sq.StatementBuilder.PlaceholderFormat(sq.Dollar).RunWith(db),
```

Conceptually, SQL and the supplied value remain separate:

```text
SQL:  SELECT id, username, password_hash, role FROM users WHERE username = $1
args: ["' OR 1=1 --"]
```

The database searches for that literal username. The quote, `OR` and comment
marker cannot change the query's meaning. Squirrel generates SQL plus separate
arguments and replaces placeholders according to the configured format; it does
not need to insert an escaped username into the SQL string.
See [Squirrel's parameter and placeholder examples](https://github.com/Masterminds/squirrel/blob/master/README.md).

Without parameter binding, the dangerous replacement would be:

```go
err := s.psql.Select("id", "username", "password_hash", "role").
    From("users").
    Where("username = '" + username + "'").
    QueryRowContext(ctx).
    Scan(&row.ID, &row.Username, &row.PasswordHash, &row.Role)
```

With the same input, the unsafe query would contain:

```sql
SELECT id, username, password_hash, role
FROM users WHERE username = '' OR 1=1 --'
```

The input now changes the selection condition. Using Squirrel does not prevent
injection if a developer concatenates input into its raw SQL clauses. Likewise,
`fmt.Sprintf` is formatting, not parameter binding. Table and column identifiers
must stay fixed or be selected from a trusted allowlist; value parameters do not
make arbitrary SQL fragments safe.

### 2. Keep passwords out of query construction

Current password verification happens after the username query:

```go
if err = bcrypt.CompareHashAndPassword(row.PasswordHash, []byte(password)); err != nil {
    return User{}, ErrAuthentication
}
```

The submitted password is never concatenated into SQL, and the database stores
bcrypt hashes rather than plaintext passwords. Bcrypt protects stored passwords;
parameter binding prevents SQL injection. These are different controls.

Changing only the username condition does **not** automatically bypass this
password check: the submitted password still has to match the returned hash.
However, an injectable SELECT may also allow an attacker to substitute returned
identity, role or hash values, for example through a compatible UNION query.
Checking an attacker-supplied hash would no longer establish the real account's
identity. The correct defense is preserving the parameterized lookup, not relying
on bcrypt to compensate for an injectable query.

### 3. Bind inserted values; keep raw schema SQL static

Account initialization uses:

```go
if _, err = psql.Insert("users").
    Columns("username", "password_hash", "role").
    Values(seed.username, hash, seed.role).
    Suffix("ON CONFLICT(username) DO NOTHING").Exec(); err != nil {
    return fmt.Errorf("seed users: %w", err)
}
```

`Values` passes the account data as parameters. The raw `Suffix` is safe here
because it is a fixed string. Concatenating external values into an INSERT or
its suffix would lose this protection. These seed values are currently local
constants, not user-controlled registration data.

The other raw SQL call is `tx.Exec(schema)`. Its SQL comes from the embedded
`schema.sql` file, not from a request. Raw SQL is not inherently vulnerable;
mixing untrusted values into its syntax is the problem.

## Security consequences of the multi-service architecture

**API owns the SQL trust boundary.** Client input reaches the users database
through API. [Compose](../../compose.yaml) mounts the SQLite users database only
in API. Event stores events and alerts in memory; Detection processes events
without a database. Neither service has SQL query paths. Separating services
reduces how many components can directly access the account database, but does
not protect an unsafe query inside API.

**A database identity error can cross service boundaries.** API signs a user JWT
using the authenticated row's ID and role. If an injectable query made API accept
a fabricated privileged identity, API could then issue valid privileged Event
authority. Event would see a correctly signed permission; it cannot determine
whether API's earlier account lookup was trustworthy. SQL injection can therefore
undermine the authorization chain even when downstream token checks work.

**The other controls still have separate jobs.** JSON validation rejects malformed
requests, but an injection string is still a valid JSON string. Generic login
errors reduce information disclosure; they do not fix an injectable query.
Owner checks and role checks control access after authentication. Database
constraints protect integrity. None replaces parameter binding at the SQL boundary.

**The impact depends on the injectable operation.** A manipulated SELECT can
affect returned identities and data. Unauthorized writes or schema damage depend
on the query and driver behavior; this document does not claim that multiple
statements or a destructive payload were executed. Protecting the SQLite file,
API process and signing keys remains necessary even with safe queries.

## Existing checks

[Store tests](../../cmd/api/internal/users/store_test.go) include
`TestLookupByUsernameNotFound` and `TestAuthenticateRejectsInvalidCredentials`.
They check injection-like usernames are rejected without returning an identity;
the lookup test also verifies Admin can still be retrieved afterward.
[API tests](../../cmd/api/handlers_test.go) include `TestLoginRejectsCredentials`
and `TestLoginHidesStorageErrors`, covering HTTP 401 for an injection-like
username and generic storage-error responses.

Reproduce these checks from the repository root:

```sh
go test -count=1 -v ./cmd/api/internal/users -run '^Test(LookupByUsernameNotFound|Authenticate|AuthenticateRejectsInvalidCredentials)$'
go test -count=1 -v ./cmd/api -run '^Test(LoginRejectsCredentials|LoginHidesStorageErrors)$'
```

Both commands passed on 2026-10-23. Relevant output excerpts:

```text
--- PASS: TestLookupByUsernameNotFound (0.21s)
--- PASS: TestAuthenticate (0.41s)
--- PASS: TestAuthenticateRejectsInvalidCredentials (0.42s)
ok  github.com/droggokid/mini-siem/cmd/api/internal/users  1.043s
--- PASS: TestLoginRejectsCredentials (0.27s)
--- PASS: TestLoginHidesStorageErrors (0.22s)
ok  github.com/droggokid/mini-siem/cmd/api  0.498s
```

This update adds explanatory comments and documentation only. Parameter binding
remains active; no vulnerable variant was run and no Git operations were performed.
