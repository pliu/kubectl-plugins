# `kubectl-krb_keycloak`

`kubectl-krb_keycloak` is a non-interactive Kubernetes exec credential plugin. It uses a Kerberos
ticket cache or keytab to authenticate to Keycloak with SPNEGO, completes the OIDC authorization
code flow with PKCE, and returns the resulting ID token to `kubectl`.

The plugin never opens a browser, prompts for credentials, or listens on the configured redirect
URI. It caches only the short-lived ID token; access and refresh tokens are not stored.

## Requirements

- A Keycloak realm with Kerberos user federation and SPNEGO enabled in its browser authentication
  flow.
- A public OIDC client configured for the standard authorization code flow.
- A file-based Kerberos credential cache containing a valid TGT, or a keytab and reachable KDC.
- A Kubernetes API server configured with the same Keycloak realm URL as its OIDC issuer.
- `kubectl` with `client.authentication.k8s.io/v1` ExecCredential support (Kubernetes 1.24 or
  newer is recommended).

## Build and install

The plugin is an independent Go module so its dependencies and version can evolve without changing
other plugins in this repository.

```sh
cd kubectl-krb_keycloak
make test
make build
install -m 0755 kubectl-krb_keycloak "$HOME/.local/bin/kubectl-krb_keycloak"
```

An opt-in end-to-end test starts an ephemeral MIT Kerberos KDC, OpenLDAP directory, and Keycloak
realm, builds the Linux plugin, authenticates with a generated keytab, and validates the resulting
ExecCredential and its LDAP-derived group membership. It then:

1. Configures a real `kubectl` with the plugin as an exec credential provider and issues a request
   against a mock Kubernetes API server.
2. Invokes the plugin **standalone** (no `kubectl`), extracts the JWT from the ExecCredential
   response, and `curl`s the same mock API with `Authorization: Bearer <token>`.

Both paths check that the mock received the Bearer JWT (printing request headers, body, and the
decoded token):

```sh
make integration-test
```

The integration test requires Docker with the Compose plugin. It downloads versioned Debian, Go,
Keycloak, and kubectl binaries on the first run and removes its containers, network, and credential
volume when it finishes. It does not require locally installed Kerberos, LDAP, Keycloak, or kubectl.

## Standalone use (JWT for curl)

The plugin does not require `kubectl`. When `KUBERNETES_EXEC_INFO` is unset, pipe a minimal
`ExecCredential` request on stdin. Successful runs print only ExecCredential JSON on stdout; extract
`status.token` and pass it as a Bearer token to the Kubernetes API:

```sh
request='{"apiVersion":"client.authentication.k8s.io/v1","kind":"ExecCredential","spec":{"interactive":false}}'
token=$(
  printf '%s\n' "$request" | kubectl-krb_keycloak \
    --issuer-url=https://sso.example.com/realms/prod \
    --client-id=kubectl \
    --redirect-uri=http://localhost:8000 \
    --keytab=/secure/path/kubectl.keytab \
    --principal=alice \
    --realm=EXAMPLE.COM \
  | jq -r '.status.token'
)
curl --cacert /path/to/kubernetes-ca.pem \
  -H "Authorization: Bearer ${token}" \
  https://kubernetes.example.com/api
```

The same flags and environment variables apply as in the kubeconfig exec stanza. The ID token cache
is shared with kubectl-driven runs when `--cache-dir` matches.

`make cross-build` creates static `linux/amd64`, `darwin/arm64`, and `windows/amd64` binaries under
`dist/`. The repository intentionally does not define hosted build or release workflows.

## Keycloak client configuration

Create or update a client in the target realm with these settings:

- Client authentication: **Off** (public client; no client secret).
- Standard flow: **Enabled**.
- Valid redirect URI: `http://localhost:8000` exactly, or the exact value passed with
  `--redirect-uri`. Nothing will bind this address.
- PKCE code challenge method: **S256**.
- Client scopes: include `openid`; add `profile` and `email` as required by the cluster's claim
  mappings.
- Browser flow: ensure the Kerberos authenticator is enabled and can complete without displaying a
  login form for users with a valid ticket. Configure the realm's Kerberos user federation provider
  and service principal/keytab for the Keycloak hostname.
- GSS delegation credentials are not consumed by this plugin. If the realm's browser flow enables
  delegation for another Keycloak feature, review that forwarding separately with the Kerberos
  administrator.

The issuer is the realm base URL, such as `https://sso.example.com/realms/prod`. Older Keycloak
deployments may include `/auth` in that base path; the plugin treats the supplied issuer as opaque
and appends the standard authorization and token endpoint paths.

## Kerberos credentials

### File ccache

By default the plugin reads `KRB5CCNAME`, then falls back to the platform temporary directory's
`krb5cc_<uid>` file. Both plain paths and `FILE:` names are accepted.

```sh
kinit alice@EXAMPLE.COM
export KRB5CCNAME=FILE:/tmp/krb5cc_alice
kinit -c "$KRB5CCNAME" alice@EXAMPLE.COM
```

`gokrb5` cannot read macOS `API:`/`KCM:`, Linux `KEYRING:`/`KCM:`, or Windows LSA caches. Use a
`FILE:` cache created with an MIT Kerberos `kinit -c` command, or use keytab mode. A non-file cache
name fails immediately with a message explaining the limitation.

### Keytab

Keytab mode obtains a TGT directly and does not require `kinit` or a ccache:

```yaml
args:
  - --keytab=/secure/path/kubectl.keytab
  - --principal=svc-kubectl
  - --realm=EXAMPLE.COM
```

The principal flag must omit `@REALM`; pass the realm separately. Protect the keytab using operating
system file permissions. Keytab login is deferred until a network authentication is required, so a
valid ID token cache hit does not contact the KDC.

## Kubeconfig

```yaml
apiVersion: v1
kind: Config
clusters:
  - name: production
    cluster:
      server: https://kubernetes.example.com
      certificate-authority: /path/to/kubernetes-ca.pem
users:
  - name: alice-keycloak
    user:
      exec:
        apiVersion: client.authentication.k8s.io/v1
        command: /home/alice/.local/bin/kubectl-krb_keycloak
        interactiveMode: Never
        provideClusterInfo: false
        args:
          - --issuer-url=https://sso.example.com/realms/prod
          - --client-id=kubectl
          - --redirect-uri=http://localhost:8000
        env:
          - name: KRB5_CONFIG
            value: /etc/krb5.conf
          - name: KRB5CCNAME
            value: FILE:/tmp/krb5cc_alice
contexts:
  - name: production
    context:
      cluster: production
      user: alice-keycloak
current-context: production
```

The plugin accepts both `interactive: true` and `interactive: false` in the incoming ExecCredential
request but remains non-interactive in either case.

## Configuration

Flags take precedence over environment variables, which take precedence over defaults.

| Flag | Environment variable | Default |
|---|---|---|
| `--issuer-url` | `KUBECTL_KRB_KEYCLOAK_ISSUER_URL` | required |
| `--client-id` | `KUBECTL_KRB_KEYCLOAK_CLIENT_ID` | required |
| `--redirect-uri` | `KUBECTL_KRB_KEYCLOAK_REDIRECT_URI` | `http://localhost:8000` |
| `--scope` | `KUBECTL_KRB_KEYCLOAK_SCOPE` | `openid profile email` |
| `--cache-dir` | `KUBECTL_KRB_KEYCLOAK_CACHE_DIR` | `~/.kube/cache/krb-keycloak` |
| `--expiry-skew` | `KUBECTL_KRB_KEYCLOAK_EXPIRY_SKEW` | `60s` |
| `--krb5-conf` | `KRB5_CONFIG` | `/etc/krb5.conf` |
| `--ccache` | `KRB5CCNAME` | temporary `krb5cc_<uid>` file |
| `--keytab` | `KUBECTL_KRB_KEYCLOAK_KEYTAB` | unset |
| `--realm` | `KUBECTL_KRB_KEYCLOAK_REALM` | unset |
| `--principal` | `KUBECTL_KRB_KEYCLOAK_PRINCIPAL` | unset |
| `--ca-file` | `KUBECTL_KRB_KEYCLOAK_CA_FILE` | system trust roots only |
| `--insecure-skip-tls-verify` | none | `false` |

`--insecure-skip-tls-verify` is deliberately flag-only so the unsafe setting remains visible in the
kubeconfig. It prints a warning on stderr whenever used. Prefer `--ca-file` for an internal CA.

## Cache and token handling

Cache filenames are SHA-256 hashes of the issuer, client ID, scope, and Kerberos principal. Cache
directories are mode `0700`; entries are atomically written with mode `0600`. A token becomes stale
at `exp - expiry-skew`, while the ExecCredential response reports the token's unmodified `exp`.

The plugin parses the JWT structure and `exp` claim but does not verify the signature locally. The
token comes directly from the configured issuer over TLS, and the Kubernetes API server remains the
verifier of record against the issuer's JWKS.

## Troubleshooting

- **No valid Kerberos ticket / TGT:** run `kinit`, confirm `KRB5CCNAME` points to a file cache, and
  inspect it with `klist -c`. In keytab mode, confirm the principal, realm, keytab permissions, KDC,
  DNS, and clock synchronization.
- **SPNEGO rejected:** verify Keycloak's Kerberos federation provider, the `HTTP/<keycloak-host>`
  service principal, Keycloak keytab, and browser authentication flow.
- **Interactive login page returned:** the browser flow did not complete through Kerberos. Check
  authenticator ordering/requirements and that the user maps into the realm.
- **Token exchange rejected:** confirm the client is public, standard flow is enabled, PKCE is
  `S256`, and the redirect URI matches exactly.
- **Missing `id_token`:** ensure `openid` is both requested and allowed for the client.
- **TLS unknown authority:** pass the private CA bundle with `--ca-file`. Avoid disabling
  verification except for isolated diagnostics.

Errors and warnings are written to stderr. Successful stdout contains only the ExecCredential JSON,
so tokens, cookies, and Kerberos authorization headers are never included in diagnostic messages.
