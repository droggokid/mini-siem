# curl examples

For Apidog or Postman, import [the collection](mini-siem.postman_collection.json)
and [local environment](mini-siem.postman_environment.json) together, then select
the `Mini-SIEM local` environment. In Apidog's
[Postman import](https://docs.apidog.com/import-from-postman-635043m0), choose
**Keep full URLs** (disable **Remove base URLs**). Each request starts with literal
`http://` and uses `{{api_host}}`, whose value must not include a scheme or path.
If an earlier import produced a malformed endpoint URL, re-import both updated
files and replace the affected endpoints, checking the import preview for
`http://{{api_host}}/health`. The collection contains only public API requests;
delete any previously imported `Internal` folder in Apidog or Postman.
Run the `API — run in order` folder after `make up`; the login requests save
Alice, Bob, and Admin tokens automatically. Run logins again after tokens expire.
Exported files contain no live tokens; keep captured tokens local when sharing.

Run `make up` from the repository root to start the services. API loads or generates
its user-JWT secret and a separate API-to-Event secret on startup. `make verify`
checks all three health endpoints; see the
[README](../README.md#verify). For manual checks, run the API commands below
in the same terminal:

```sh
API_URL='http://127.0.0.1:8080'
```

## API: GET /health

```sh
curl --fail --silent --show-error "$API_URL/health"
```

Returns HTTP 200 and `ok`.

## API: POST /login

Choose one of the seeded demo accounts:

```sh
# Alice
curl --fail --silent --show-error "$API_URL/login" \
  -H 'Content-Type: application/json' \
  --data '{"username":"Alice","password":"alice-password"}'
```

```sh
# Bob
curl --fail --silent --show-error "$API_URL/login" \
  -H 'Content-Type: application/json' \
  --data '{"username":"Bob","password":"bob-password"}'
```

```sh
# Admin
curl --fail --silent --show-error "$API_URL/login" \
  -H 'Content-Type: application/json' \
  --data '{"username":"Admin","password":"admin-password"}'
```

Returns HTTP 200 with `access_token`, `token_type`, and `expires_in`.
Copy an `access_token` into `TOKEN` below. Tokens expire after 15 minutes.

## API: GET /me

```sh
TOKEN='<paste access_token from a successful login>'
curl --fail --silent --show-error "$API_URL/me" \
  -H "Authorization: Bearer $TOKEN"
unset TOKEN
```

Returns HTTP 200 with the authenticated user's `id` and `role`.
Without a token, the endpoint returns HTTP 401:

```sh
curl --silent --show-error --include "$API_URL/me"
```

## API: POST /events

Use the access token returned by Alice's login:

```sh
ALICE_TOKEN='<paste Alice access_token>'
curl --fail --silent --show-error "$API_URL/events" \
  -H "Authorization: Bearer $ALICE_TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{"type":"login.failed","source_ip":"192.0.2.1"}'
```

Returns HTTP 201 with `id`, `owner_id`, `type`, `source_ip`, and `ingested_at`.
The owner is Alice's verified user ID. Event generates the event ID and UTC
ingestion timestamp. Only a nonblank type and valid IPv4 or IPv6 source IP are
accepted from the client.

An invalid IP returns HTTP 400 without storing an event:

```sh
curl --silent --show-error --include "$API_URL/events" \
  -H "Authorization: Bearer $ALICE_TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{"type":"login.failed","source_ip":"999.999.999.999"}'
```

Client-supplied ownership also returns HTTP 400 without storing an event:

```sh
curl --silent --show-error --include "$API_URL/events" \
  -H "Authorization: Bearer $ALICE_TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{"type":"login.failed","source_ip":"192.0.2.1","owner_id":2}'
```

Malformed JSON, missing fields, and unknown fields return HTTP 400. Requests
larger than 64 KiB return HTTP 413; unsupported POST content types return HTTP
415. Missing or invalid authentication returns HTTP 401.

## API: GET /events

```sh
curl --fail --silent --show-error "$API_URL/events" \
  -H "Authorization: Bearer $ALICE_TOKEN"
```

Returns HTTP 200 with an array containing only Alice's events. Log in as Bob
using the earlier login example and copy his access token:

```sh
BOB_TOKEN='<paste Bob access_token>'
curl --fail --silent --show-error "$API_URL/events" \
  -H "Authorization: Bearer $BOB_TOKEN"
```

Bob sees only his own events, or `[]` if he has submitted none. He does not see
Alice's event. A GET body or owner query parameter is rejected with HTTP 400:

```sh
curl --silent --show-error --include "$API_URL/events?owner_id=1" \
  -H "Authorization: Bearer $BOB_TOKEN"
unset ALICE_TOKEN BOB_TOKEN
```

Event independently validates API's short-lived owner/action/service-scoped
authority; the user token is accepted only by API. Backend failures return HTTP
502 and timeouts return HTTP 504. A timed-out submission may already be stored;
do not retry it blindly. All stored events disappear when Event restarts.

## Event and Detection: GET /health

These services have no published host ports. Run these commands from a container
on Compose's backend network with curl installed; their hostnames resolve there.

```sh
curl --fail --silent --show-error http://event:8080/health
curl --fail --silent --show-error http://detection:8080/health
```

Each returns HTTP 200 and `ok`. The API image includes `wget` rather than curl;
the [README verification commands](../README.md#verify) work from that container.

## Event: unauthorized direct access

From a container on the backend network with curl installed:

```sh
curl --silent --show-error --include http://event:8080/events
```

Returns HTTP 401. Adding a public user JWT also returns HTTP 401: Event requires
separate delegated authority for the intended owner and action. Network access
alone grants no event access. The same missing-authority check can be run with
API's installed `wget` (an HTTP 401 produces a nonzero exit):

```sh
docker compose exec -T api wget -S -O- http://event:8080/events
```
