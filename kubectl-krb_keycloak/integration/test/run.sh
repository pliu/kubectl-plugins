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

attempt=0
until curl --fail --silent "$discovery" >/dev/null; do
	attempt=$((attempt + 1))
	if test "$attempt" -ge 90; then
		echo "Keycloak did not become ready within 90 seconds" >&2
		exit 1
	fi
	sleep 1
done

# --- Phase 1: standalone plugin invocation (existing coverage) ---

output=$(
	run_plugin
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

# --- Phase 2: real kubectl + exec plugin -> mock Kubernetes API server ---

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

record="$workdir/request.json"
python3 /usr/local/bin/mock-apiserver.py \
	--listen 127.0.0.1:6443 \
	--cert "$workdir/tls.crt" \
	--key "$workdir/tls.key" \
	--record "$record" &
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

test -f "$record"
test "$(jq -r '.ok' "$record")" = true
test "$(jq -r '.authorization | startswith("Bearer ")' "$record")" = true
test "$(jq -r '.jwt.payload.groups | index("/developers") != null' "$record")" = true
test "$(jq -r '.token | split(".") | length' "$record")" -eq 3

echo "=== recorded request from mock API server ==="
jq '.' "$record"

echo "phase 2 passed: kubectl invoked the plugin and sent the JWT Bearer token to the mock API server"
echo "end-to-end Kerberos, LDAP groups, SPNEGO, Keycloak, PKCE, ExecCredential, and kubectl flow passed"
