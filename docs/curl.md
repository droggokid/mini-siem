# curl examples

Run `make up` from the repository root to start the services. API loads or generates
its JWT secret on startup. `make verify` checks all three health endpoints; see the
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

## Event and Detection: GET /health

These services have no published host ports. Run these commands from a container
on Compose's backend network with curl installed; their hostnames resolve there.

```sh
curl --fail --silent --show-error http://event:8080/health
curl --fail --silent --show-error http://detection:8080/health
```

Each returns HTTP 200 and `ok`. The API image includes `wget` rather than curl;
the [README verification commands](../README.md#verify) work from that container.
