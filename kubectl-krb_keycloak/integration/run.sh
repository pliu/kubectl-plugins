#!/bin/sh
set -eu

integration_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_name="kubectl-krb-keycloak-e2e-$$"

compose() {
	docker compose --project-name "$project_name" --file "$integration_dir/docker-compose.yml" "$@"
}

cleanup() {
	compose down --volumes --remove-orphans --rmi local >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

compose up --build --abort-on-container-exit --exit-code-from test
