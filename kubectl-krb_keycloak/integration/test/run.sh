#!/bin/sh
set -eu

issuer=http://keycloak.test:8080/realms/kubectl-krb-keycloak-e2e
discovery=$issuer/.well-known/openid-configuration

run_plugin() {
	kubectl-krb_keycloak \
		--issuer-url="$issuer" \
		--client-id=kubectl-e2e \
		--redirect-uri=http://localhost:8000 \
		--scope='openid profile email' \
		--cache-dir=/tmp/token-cache \
		--krb5-conf=/etc/krb5.conf \
		--keytab=/kerberos/alice.keytab \
		--principal=alice \
		--realm=EXAMPLE.TEST
}

# Start the mock API server in the background; sets mock_pid.
# Usage: start_mock <record-path>
start_mock() {
	record_path=$1
	python3 /usr/local/bin/mock-apiserver.py \
		--listen 127.0.0.1:6443 \
		--cert "$workdir/tls.crt" \
		--key "$workdir/tls.key" \
		--record "$record_path" &
	mock_pid=$!

	# Wait until the mock server is listening (TCP accept), without consuming an HTTP request.
	attempt=0
	until python3 - <<'PY' 2>/dev/null
import socket, sys
with socket.create_connection(("127.0.0.1", 6443), timeout=1) as s:
    sys.exit(0)
PY
	do
		attempt=$((attempt + 1))
		if test "$attempt" -ge 30; then
			echo "mock API server did not become ready" >&2
			exit 1
		fi
		# Fail fast if the mock process already exited.
		if ! kill -0 "$mock_pid" 2>/dev/null; then
			wait "$mock_pid" || true
			echo "mock API server exited before accepting connections" >&2
			exit 1
		fi
		sleep 0.2
	done
}

# Assert the mock recorded a successful Bearer JWT request with the /developers group.
assert_mock_record() {
	record_path=$1
	test -f "$record_path"
	test "$(jq -r '.ok' "$record_path")" = true
	test "$(jq -r '.authorization | startswith("Bearer ")' "$record_path")" = true
	test "$(jq -r '.jwt.payload.groups | index("/developers") != null' "$record_path")" = true
	test "$(jq -r '.token | split(".") | length' "$record_path")" -eq 3
}

attempt=0
until curl --fail --silent "$discovery" >/dev/null; do
	attempt=$((attempt + 1))
	if test "$attempt" -ge 90; then
		echo "Keycloak did not become ready within 90 seconds" >&2
		exit 1
	fi
	sleep 1
done

# --- Phase 1: direct plugin ExecCredential exchange (existing coverage) ---

request='{"apiVersion":"client.authentication.k8s.io/v1","kind":"ExecCredential","spec":{"interactive":false}}'
output=$(
	printf '%s\n' "$request" | run_plugin
)

test "$(printf '%s' "$output" | jq -r '.apiVersion')" = 'client.authentication.k8s.io/v1'
test "$(printf '%s' "$output" | jq -r '.kind')" = 'ExecCredential'
test "$(printf '%s' "$output" | jq -r '.status.token | split(".") | length')" -eq 3
test "$(printf '%s' "$output" | jq -r '.status.expirationTimestamp | length > 0')" = true

token=$(printf '%s' "$output" | jq -r '.status.token')
has_developers_group=$(
	printf '%s' "$token" | jq -Rr '
		def decode:
			gsub("-"; "+") | gsub("_"; "/") | @base64d | fromjson;
		split(".")[1] | decode | .groups | index("/developers") != null
	'
)
test "$has_developers_group" = true

printf 'received JWT: %s\n' "$token"
printf 'decoded JWT header and payload:\n'
printf '%s' "$token" | jq -R '
	def decode:
		gsub("-"; "+") | gsub("_"; "/") | @base64d | fromjson;
	split(".") | {header: (.[0] | decode), payload: (.[1] | decode)}
'
echo "phase 1 passed: Kerberos, LDAP groups, SPNEGO, Keycloak, PKCE, and ExecCredential"

# Shared TLS material and mock lifecycle for phases that hit a mock API server.
workdir=$(mktemp -d)
mock_pid=""

cleanup() {
	if test -n "$mock_pid" && kill -0 "$mock_pid" 2>/dev/null; then
		kill "$mock_pid" 2>/dev/null || true
		wait "$mock_pid" 2>/dev/null || true
	fi
	rm -rf "$workdir"
}
trap cleanup EXIT

openssl req -x509 -newkey rsa:2048 \
	-keyout "$workdir/tls.key" \
	-out "$workdir/tls.crt" \
	-days 1 -nodes \
	-subj '/CN=127.0.0.1' \
	>/dev/null 2>&1

# --- Phase 2: real kubectl + exec plugin -> mock Kubernetes API server ---

record="$workdir/request.json"
start_mock "$record"

kubeconfig="$workdir/kubeconfig"
cat >"$kubeconfig" <<EOF
apiVersion: v1
kind: Config
clusters:
  - name: mock
    cluster:
      server: https://127.0.0.1:6443
      insecure-skip-tls-verify: true
users:
  - name: alice-keycloak
    user:
      exec:
        apiVersion: client.authentication.k8s.io/v1
        command: kubectl-krb_keycloak
        interactiveMode: Never
        provideClusterInfo: false
        args:
          - --issuer-url=$issuer
          - --client-id=kubectl-e2e
          - --redirect-uri=http://localhost:8000
          - --scope=openid profile email
          - --cache-dir=/tmp/token-cache
          - --krb5-conf=/etc/krb5.conf
          - --keytab=/kerberos/alice.keytab
          - --principal=alice
          - --realm=EXAMPLE.TEST
contexts:
  - name: mock
    context:
      cluster: mock
      user: alice-keycloak
current-context: mock
EOF

echo "invoking kubectl with kubeconfig exec plugin against mock API server"
kubectl_output=$(
	kubectl --kubeconfig="$kubeconfig" get --raw /api
)
printf 'kubectl raw /api response: %s\n' "$kubectl_output"
test "$(printf '%s' "$kubectl_output" | jq -r '.kind')" = 'APIVersions'

# Mock process exits after the authenticated request; wait for its verification status.
wait "$mock_pid"
mock_status=$?
mock_pid=""
test "$mock_status" -eq 0

assert_mock_record "$record"

echo "=== recorded request from mock API server (kubectl) ==="
jq '.' "$record"

echo "phase 2 passed: kubectl invoked the plugin and sent the JWT Bearer token to the mock API server"

# --- Phase 3: standalone plugin (no kubectl) -> JWT -> curl mock API server ---
#
# Demonstrates that kubectl-krb_keycloak can be invoked outside kubectl: pipe an
# ExecCredential request, extract status.token, and use it as a Bearer token when
# curling the Kubernetes API directly.

record_curl="$workdir/request-curl.json"
start_mock "$record_curl"

echo "invoking plugin standalone (no kubectl) and curling the mock API with the JWT"
standalone_output=$(
	printf '%s\n' "$request" | run_plugin
)
standalone_token=$(printf '%s' "$standalone_output" | jq -r '.status.token')
test "$(printf '%s' "$standalone_token" | jq -Rr 'split(".") | length')" -eq 3

curl_output=$(
	curl --fail --silent --insecure \
		-H "Authorization: Bearer ${standalone_token}" \
		https://127.0.0.1:6443/api
)
printf 'curl /api response: %s\n' "$curl_output"
test "$(printf '%s' "$curl_output" | jq -r '.kind')" = 'APIVersions'

wait "$mock_pid"
mock_status=$?
mock_pid=""
test "$mock_status" -eq 0

assert_mock_record "$record_curl"
# Confirm the mock saw the same JWT the standalone plugin returned.
test "$(jq -r '.token' "$record_curl")" = "$standalone_token"

echo "=== recorded request from mock API server (standalone curl) ==="
jq '.' "$record_curl"

echo "phase 3 passed: standalone plugin JWT used with curl against the mock API server"
echo "end-to-end Kerberos, LDAP groups, SPNEGO, Keycloak, PKCE, ExecCredential, kubectl, and standalone curl flows passed"
