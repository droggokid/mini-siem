#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export GOWORK=off GOFLAGS=-mod=readonly GOTOOLCHAIN=local GIN_MODE=release
export COMPOSE_FILE=compose.yaml:compose.ci.yaml
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-mini-siem-ci-$(date +%s)-$$}"
mkdir -p reports

finish() {
  result=$?
  trap - EXIT
  set +e
  docker compose ps --all --format '{{.Service}} {{.State}} {{.Health}} {{.ExitCode}}' > reports/compose-status.log
  [[ $? == 0 ]] || result=1
  # Allow only known startup messages; never archive arbitrary service output.
  for service in api event detection; do
    docker compose logs --no-color --no-log-prefix "$service" |
      awk -v service="$service" '/^[0-9]{4}\/[0-9]{2}\/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} listening on :8080$/ { print service, $0 }' \
      > "reports/compose-$service.log"
    [[ $? == 0 ]] || result=1
  done
  docker compose down --volumes --remove-orphans --rmi local --timeout 10
  [[ $? == 0 ]] || result=1
  for resource in container network volume; do
    listing_flags=(-q)
    [[ "$resource" != container ]] || listing_flags+=(-a)
    remaining=$(docker "$resource" ls "${listing_flags[@]}" --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME")
    if [[ $? != 0 || -n "$remaining" ]]; then
      echo "Compose cleanup left $resource resources or could not verify removal." >&2
      result=1
    fi
  done
  exit "$result"
}
# Refuse to reuse a project, including orphaned volumes from an interrupted run.
for resource in container network volume; do
  listing_flags=(-q)
  [[ "$resource" != container ]] || listing_flags+=(-a)
  existing=$(docker "$resource" ls "${listing_flags[@]}" --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME")
  if [[ -n "$existing" ]]; then
    echo 'Choose a new COMPOSE_PROJECT_NAME; this project already has resources.' >&2
    exit 1
  fi
done
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

docker compose build
docker compose up -d --wait --wait-timeout 120
for service in api event detection; do
  container=$(docker compose ps -q "$service")
  [[ -n "$container" ]]
  [[ $(docker inspect --format '{{.State.Health.Status}}' "$container") == healthy ]]
done
address=$(docker compose port api 8080)
[[ "$address" =~ ^127\.0\.0\.1:[0-9]+$ ]]
export MINI_SIEM_TEST_URL="http://$address"
gotestsum --junitfile reports/compose-integration.xml -- -count=1 -timeout=5m -run '^TestDetectionIntegration$' .
# Also catch a service that exited or became unhealthy during the test.
for service in api event detection; do
  container=$(docker compose ps -q "$service")
  [[ -n "$container" ]]
  [[ $(docker inspect --format '{{.State.Health.Status}}' "$container") == healthy ]]
done
