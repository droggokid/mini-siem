.PHONY: help up down logs ps test verify

help:
	@printf '%s\n' 'make up      Build and start Docker services; API creates a missing JWT secret' 'make verify  Check all three running services health endpoints' 'make test    Run Go tests only' 'make logs    Follow service logs' 'make ps      Show service status' 'make down    Stop services; keep the users database and JWT secret'

up:
	docker compose up --build -d

down:
	docker compose down

logs:
	docker compose logs -f

ps:
	docker compose ps

test:
	cd eventkit && go test ./...
	go test ./...

verify:
	@test "$$(curl --fail --silent --show-error --max-time 5 --retry 10 --retry-connrefused --retry-delay 1 http://127.0.0.1:8080/health)" = ok
	@test "$$(docker compose exec -T api wget -qO- http://event:8080/health)" = ok
	@test "$$(docker compose exec -T api wget -qO- http://detection:8080/health)" = ok
	@printf 'All three health checks passed.\n'
