#!/bin/sh
set -eu

issuer=http://keycloak.test:8080/realms/kubectl-krb-keycloak-e2e
discovery=$issuer/.well-known/openid-configuration

attempt=0
until curl --fail --silent "$discovery" >/dev/null; do
	attempt=$((attempt + 1))
	if test "$attempt" -ge 90; then
		echo "Keycloak did not become ready within 90 seconds" >&2
		exit 1
	fi
	sleep 1
done

request='{"apiVersion":"client.authentication.k8s.io/v1","kind":"ExecCredential","spec":{"interactive":false}}'
output=$(
	printf '%s\n' "$request" |
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
echo "end-to-end Kerberos, LDAP groups, SPNEGO, Keycloak, PKCE, and ExecCredential flow passed"
