# Design: `kubectl-krb-keycloak` — Kerberos/SPNEGO → Keycloak OIDC exec credential plugin

Status: **Proposed** (this document is the first commit; implementation follows once the design is agreed).

## 1. Overview

### Problem

Clusters that authenticate users via OIDC (Keycloak as the IdP) normally require an interactive
browser login to obtain an `id_token`. In environments that already run Kerberos (Active Directory
or MIT KDC) with Keycloak's Kerberos user federation enabled, that interactive step is redundant:
the user's workstation already holds a TGT, and Keycloak can authenticate the browser flow silently
via SPNEGO (`WWW-Authenticate: Negotiate`). There is no off-the-shelf kubectl credential plugin that
drives this flow headlessly.

### Proposed solution

A Go binary implementing the Kubernetes
[`client.authentication.k8s.io/v1` ExecCredential](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#client-go-credential-plugins)
contract. On invocation it:

1. Returns a cached `id_token` from disk if it is still valid (the common case — zero network calls).
2. Otherwise, drives Keycloak's **authorization-code flow with PKCE** using an HTTP client that
   completes the SPNEGO handshake with the user's ambient Kerberos ticket (from the ccache, or a
   keytab for service accounts), captures the authorization `code` from the redirect `Location`
   header without ever opening a browser or listening on a socket, exchanges it for tokens, and
   returns the **`id_token`** (never the access token) as `status.token`.

The plugin is strictly non-interactive: it never prompts and never opens a browser. Any condition
that would require interaction is a hard failure with an actionable message on stderr.

Key insight driving the design: Keycloak only performs SPNEGO on the *browser* (authorization)
endpoint, not on the direct-grant token endpoint — so the plugin must emulate a minimal browser:
follow the auth endpoint's redirects within the Keycloak host (with a cookie jar), answer the
`Negotiate` challenge, and stop as soon as a redirect targets the configured `redirect_uri`,
harvesting `code` from its query string.

### Repository scope

This repository (`kubectl-plugins`) will grow to hold multiple kubectl plugins. The layout below
reserves shared space (`internal/` packages usable across plugins, one `cmd/` entry per plugin, a
shared build/release pipeline) so later plugins slot in without restructuring.

## 2. Architecture

### 2.1 Components

```
                    ┌────────────────────────────────────────────────┐
 kubectl/client-go  │  cmd/kubectl-krb_keycloak (main)               │
 ── stdin/env ────▶ │   flag/env config → wire deps → run            │
 ◀── stdout ─────── │                                                │
                    │  internal/execcred     ExecCredential I/O      │
                    │  internal/tokencache   disk cache (0600)       │
                    │  internal/jwt          exp-claim parsing       │
                    │  internal/keycloak     auth-code + PKCE flow   │
                    │  internal/krb          gokrb5 SPNEGO client    │
                    └────────────────────────────────────────────────┘
                                    │ HTTPS (SPNEGO)        │ HTTPS
                                    ▼                       ▼
                          Keycloak /auth endpoint   Keycloak /token endpoint
                                    │
                              Kerberos KDC (via gokrb5, ambient ccache/keytab)
```

| Package | Responsibility | Key interfaces |
|---|---|---|
| `internal/execcred` | Parse the `ExecCredential` request from stdin / `KUBERNETES_EXEC_INFO`; enforce `apiVersion`; write the response (`status.token`, `status.expirationTimestamp`) to stdout. Uses the official types from `k8s.io/client-go/pkg/apis/clientauthentication/v1`. | — |
| `internal/tokencache` | Load/store the cached `id_token` keyed by SHA-256 of `issuer\|client_id\|scope\|principal`; validity check `now < exp − skew`; atomic writes (temp file + rename), file mode `0600`, dir `0700`. | `Clock` (injectable `func() time.Time`) for tests |
| `internal/jwt` | Parse a compact JWT *without signature verification*: structural validation (three base64url segments, JSON payload) and extraction of `exp` (and `sub`/`preferred_username` for diagnostics only). | — |
| `internal/keycloak` | Build the authorization request (`response_type=code`, `client_id`, `redirect_uri`, `scope`, random `state`, PKCE S256 `code_challenge`); walk the redirect chain; verify `state`; extract `code`; exchange it at the token endpoint with `code_verifier`; surface Keycloak error payloads verbatim in errors. | `Doer` (`Do(*http.Request) (*http.Response, error)`) — the SPNEGO client is injected behind this, so the whole flow is testable against `httptest` servers |
| `internal/krb` | Construct the gokrb5 client from ccache (`--ccache` / `KRB5CCNAME` / OS default) or keytab (`--keytab` + `--realm`); load `krb5.conf` (`--krb5-conf` / `KRB5_CONFIG` / `/etc/krb5.conf`); wrap it in a `spnego.Client` that satisfies `Doer`; report the authenticated principal (feeds the cache key). | `CredentialSource` abstraction so the Keycloak flow never touches gokrb5 types directly |
| `cmd/kubectl-krb_keycloak` | Flag/env parsing, dependency wiring, exit codes. Thin — no logic worth unit-testing beyond config resolution. | — |

### 2.2 Data flow (cache miss)

1. `main` reads config (flags → env fallbacks), reads/validates the `ExecCredential` request from
   stdin. `spec.interactive` is noted but never acted on — this plugin never needs interaction, so
   both `true` and `false` are acceptable; it simply never reads further from stdin.
2. `tokencache.Get(key)` — miss or expired (past `exp − skew`, default skew 60 s).
3. `krb` loads the ccache and builds the SPNEGO client. Failure here (no ccache, expired TGT)
   produces the "no valid Kerberos ticket — run `kinit`" error class.
4. `keycloak` GETs `{issuer}/protocol/openid-connect/auth?...` with redirects disabled
   (`CheckRedirect` returns `http.ErrUseLastResponse`) and a cookie jar (Keycloak's
   `AUTH_SESSION_ID` / `KC_RESTART` cookies are required across the hop). The SPNEGO transport
   answers the `401 Negotiate` challenge with the ambient ticket. Loop over redirects **manually**,
   bounded (max ~10 hops):
   - redirect target is on the issuer host → follow it (Keycloak may bounce through
     `login-actions` URLs);
   - redirect target matches the configured `redirect_uri` prefix → stop; parse `code` and `state`
     from the query (or `error`/`error_description` → the "SPNEGO rejected by Keycloak" error class);
   - anything else (200 with an HTML login form, redirect elsewhere) → the "Keycloak wants
     interaction" error class: exit non-zero, tell the user Kerberos federation/SPNEGO is likely
     not enabled for this realm or client.
   The `redirect_uri` is **never listened on** — no local server, no port conflicts; it exists only
   as a registered URI whose appearance in a `Location` header terminates the walk.
5. `keycloak` POSTs `{issuer}/protocol/openid-connect/token` with
   `grant_type=authorization_code`, `code`, `redirect_uri`, `client_id`, `code_verifier`
   (public client — no secret). The response **must** contain `id_token`; if only `access_token`
   is present, fail with a message reminding the user the `openid` scope is required and must be
   in the client's allowed scopes.
6. `jwt` validates the `id_token` shape and extracts `exp`.
7. `tokencache.Put` persists it; `execcred` writes the response with
   `status.expirationTimestamp = exp` (client-go applies its own refresh margin; the cache's skew
   is our own safety, applied at read time — see Q7).

On a cache hit, steps 3–6 are skipped entirely: the plugin does no network or KDC I/O, which is
what keeps per-`kubectl`-invocation overhead negligible.

### 2.3 Key technology choices

| Choice | Rationale |
|---|---|
| `github.com/jcmturner/gokrb5/v8` | The only mature pure-Go Kerberos/SPNEGO implementation; no cgo → trivially cross-compiled static binaries. Provides both the client (ccache/keytab) and an SPNEGO-aware `http.Client` wrapper. |
| `k8s.io/client-go/pkg/apis/clientauthentication/v1` types | The contract is defined by these types; hand-rolling the JSON invites drift. We import only the API types (plus `k8s.io/apimachinery` for `metav1.Time`), not the client machinery. |
| **No JWT signature verification** (parse `exp` only) | The plugin is a courier, not a verifier: the API server validates the token against the issuer's JWKS. Verifying locally would add an OIDC-discovery + JWKS network call on every cache miss and a `coreos/go-oidc` dependency for no security benefit (the token travels over TLS from the issuer we contacted). Flagged as Q4 in case the reviewer disagrees. |
| **Authorization-code + PKCE via manual redirect walk** | Direct grant can't do SPNEGO (Keycloak limitation); device flow is interactive by design. PKCE (S256) plus single-use `state` protects the code in transit even for a public client. Capturing `code` from the `Location` header avoids running a loopback listener entirely. |
| **No refresh tokens** | Re-running SPNEGO is already silent and cheap relative to token lifetime; storing refresh tokens on disk enlarges the theft surface and adds revocation/rotation edge cases. The disk cache holds only the short-lived `id_token`. |
| stdlib `flag` + env fallbacks (`KUBECTL_KRB_KEYCLOAK_*`) | Kubeconfig `exec` stanzas pass both `args` and `env`; supporting both costs ~30 lines and avoids cobra/viper weight in a binary that runs on every kubectl call. |
| Atomic cache writes (temp + `os.Rename`) | `kubectl` invocations race (shell pipelines, parallel tools, watch loops); rename-into-place makes concurrent writers last-wins-safe without lock files. |

### 2.4 Configuration

Precedence: flag > environment variable > default. All settable as kubeconfig `exec` `args`/`env`.

| Flag | Env | Default |
|---|---|---|
| `--issuer-url` | `KUBECTL_KRB_KEYCLOAK_ISSUER_URL` | *(required)* — e.g. `https://sso.example.com/realms/prod` |
| `--client-id` | `KUBECTL_KRB_KEYCLOAK_CLIENT_ID` | *(required)* |
| `--redirect-uri` | `KUBECTL_KRB_KEYCLOAK_REDIRECT_URI` | `http://localhost:8000` (registered in Keycloak; never bound) |
| `--scope` | `KUBECTL_KRB_KEYCLOAK_SCOPE` | `openid profile email` |
| `--cache-dir` | `KUBECTL_KRB_KEYCLOAK_CACHE_DIR` | `~/.kube/cache/krb-keycloak` |
| `--expiry-skew` | `KUBECTL_KRB_KEYCLOAK_EXPIRY_SKEW` | `60s` |
| `--krb5-conf` | `KRB5_CONFIG` | `/etc/krb5.conf` |
| `--ccache` | `KRB5CCNAME` | OS-default file ccache (`/tmp/krb5cc_<uid>`) |
| `--keytab` / `--realm` / `--principal` | `KUBECTL_KRB_KEYCLOAK_KEYTAB` / `..._REALM` / `..._PRINCIPAL` | *(unset — ccache mode)* |
| `--ca-file` | `KUBECTL_KRB_KEYCLOAK_CA_FILE` | system roots |
| `--insecure-skip-tls-verify` | — (flag only, deliberately) | `false` |

### 2.5 Robustness & security

- **Error taxonomy** — every failure exits non-zero with a one-line, actionable stderr message
  distinguishing: (1) bad/missing config; (2) no valid Kerberos ticket → suggest `kinit`
  (detecting expired-vs-absent ccache where gokrb5 lets us); (3) SPNEGO/Negotiate rejected by
  Keycloak → point at realm Kerberos-federation settings; (4) auth flow ended without a `code`
  (interaction required) → point at client/flow configuration; (5) token exchange rejected →
  include Keycloak's `error`/`error_description`; (6) `id_token` missing → remind about the
  `openid` scope; (7) TLS/CA failures → suggest `--ca-file`.
- **No secret leakage** — tokens, Kerberos material, and `Authorization`/`Set-Cookie` headers never
  appear in errors or any verbose output; error messages include URLs and status codes only.
- **TLS on by default**; `--insecure-skip-tls-verify` is flag-only (not env-settable) so it must be
  visible in the kubeconfig stanza, and it triggers a stderr warning.
- **Cache hygiene** — dir `0700`, files `0600`, and the cache file stores only the `id_token` +
  metadata (no refresh/access tokens).
- **Platform caveat (documented, not solved in v1)** — gokrb5 reads *file* ccaches only. macOS
  (`API:`/`KCM:` ccache) and Windows (LSA) defaults are not file-based; users there must
  `export KRB5CCNAME=FILE:...` + `kinit -c`, or use keytab mode. The README will cover this
  prominently (see Q5).

### 2.6 Testing strategy

- `tokencache`: table tests for hit / miss / expired / within-skew / corrupted-file / permissions,
  using the injected clock.
- `jwt`: valid token, missing `exp`, non-JWT input, padding/base64url edge cases.
- `keycloak`: full flow against `httptest.Server` fixtures — happy path (401→SPNEGO→302 chain→code
  →token), state mismatch, `error=` redirect, no-code HTML response, token endpoint error, response
  without `id_token`. The SPNEGO client is behind `Doer`, so these tests use a fake that asserts
  the Negotiate exchange was attempted, with no Kerberos infrastructure needed.
- `krb`: thin unit tests over ccache-path resolution and error classification; the gokrb5 calls
  themselves are exercised only by the optional integration harness (Milestone 6).
- `execcred`: golden-file round-trips of request parsing (stdin and `KUBERNETES_EXEC_INFO`) and
  response encoding, including apiVersion mismatch handling.

## 3. Proposed project layout

Single Go module at the repo root; one `cmd/` directory per plugin; plugin-specific logic under
`internal/<plugin>/`; genuinely shared code promoted to `internal/shared/` only when a second
plugin needs it (see Q1).

```
kubectl-plugins/
├── go.mod                                # module github.com/pliu/kubectl-plugins
├── Makefile                              # build/test/lint; cross-compile targets
├── README.md                             # repo index: one section per plugin
├── DESIGN.md                             # this document
├── cmd/
│   └── kubectl-krb_keycloak/
│       └── main.go
├── internal/
│   └── krbkeycloak/
│       ├── execcred/       execcred.go  execcred_test.go
│       ├── tokencache/     cache.go     cache_test.go
│       ├── jwt/            jwt.go       jwt_test.go
│       ├── keycloak/       flow.go      pkce.go  flow_test.go
│       └── krb/            client.go    client_test.go
├── docs/
│   └── kubectl-krb_keycloak.md           # full plugin README (kubeconfig stanza,
│                                         # Keycloak client settings, krb5 prereqs)
└── .github/workflows/ci.yml              # test + lint + cross-build matrix
```

Release builds: `CGO_ENABLED=0` for `linux/amd64`, `darwin/arm64`, `windows/amd64` via the
Makefile (goreleaser can be added later if the repo grows release cadence).

## 4. Milestones

Each milestone is a reviewable PR that compiles and passes tests.

1. **Scaffolding + ExecCredential I/O** — module, Makefile, CI; `internal/krbkeycloak/execcred`
   complete with tests; `main.go` wired with config parsing but a stubbed token source. The plugin
   runs end-to-end with a fake token.
2. **Token cache + JWT parsing** — `tokencache` and `jwt` with full unit tests; cache-hit path
   works for real (a manually planted token round-trips through kubectl).
3. **Keycloak flow (mocked transport)** — `keycloak` package: PKCE, state, redirect walk, code
   exchange, error taxonomy classes 4–6, all against `httptest`. Still no Kerberos.
4. **Kerberos/SPNEGO integration** — `internal/krbkeycloak/krb`: ccache/keytab loading, SPNEGO
   `Doer`, principal extraction, error classes 2–3. First real end-to-end login against a live
   Keycloak+KDC.
5. **Hardening + docs** — TLS options, skew flag, atomic-write races, stderr message polish;
   `docs/kubectl-krb_keycloak.md` with the kubeconfig stanza, Keycloak client checklist (public
   client, PKCE `S256` required, exact redirect URI, Kerberos user federation + `gss delegation
   credential` notes), krb5.conf prerequisites, and per-platform ccache guidance.
6. **(Optional) Integration harness** — docker-compose with Keycloak + a KDC (e.g.
   `kerberos-kdc` image) driving the real flow in CI behind a `make integration` target.

## 5. Clarifying questions

Answers to these would most change the design. Each has an assumed answer so work can proceed.

1. **Module layout for a multi-plugin repo** — one Go module at the root, or a module per plugin?
   *Assumed:* single root module (`github.com/pliu/kubectl-plugins`), `cmd/<plugin>` +
   `internal/<plugin>/`. One `go.sum`, one CI pipeline, easy code sharing; per-plugin modules can
   be split out later if dependency sets diverge badly.
2. **Binary name** — exec credential plugins are invoked by client-go via kubeconfig, so the
   `kubectl-*` prefix (krew-style) isn't technically required. *Assumed:* `kubectl-krb_keycloak`
   anyway, for repo-wide naming consistency and future krew distribution; the kubeconfig `command`
   field doesn't care.
3. **Redirect URI handling** — is a never-bound `http://localhost:8000` acceptable to the Keycloak
   administrators, or must we support an OOB (`urn:ietf:wg:oauth:2.0:oob`) style URI? *Assumed:*
   never-bound localhost is fine (we only need it registered as a valid redirect URI; nothing is
   ever sent to it since we capture the `Location` header). `--redirect-uri` covers deployments
   that prefer another value.
4. **Local id_token verification** — should the plugin verify the JWT signature against the
   issuer's JWKS before returning/caching it? *Assumed:* no — the API server is the verifier of
   record, the token arrives over TLS from the issuer, and skipping JWKS keeps cache misses to
   exactly two HTTP round trips. We parse `exp` (and require structural JWT validity) only.
5. **macOS/Windows ccache support depth** — gokrb5 cannot read macOS `API:`/`KCM:` or Windows LSA
   ccaches. Is documenting the `KRB5CCNAME=FILE:` workaround acceptable for v1, or is native
   support (e.g. shelling out to `klist`/SSPI) required? *Assumed:* documentation is acceptable
   for v1; native macOS/Windows credential-store support is future work.
6. **Keycloak versions** — may we assume a modern (quarkus-era, ≥17) Keycloak where the issuer
   path is `/realms/<realm>` (no `/auth` prefix), treating the issuer URL as opaque either way?
   *Assumed:* yes; since we build URLs by appending `/protocol/openid-connect/...` to the given
   issuer, legacy `/auth/realms/<realm>` issuers work automatically.
7. **ExecCredential apiVersion** — support only `client.authentication.k8s.io/v1`, or also
   `v1beta1` for older clusters/kubectl? *Assumed:* `v1` only (kubectl ≥1.24 defaults to it);
   the version-mismatch error will say exactly what to put in the kubeconfig stanza.
8. **Reported expiry** — return the raw `exp` as `status.expirationTimestamp` and keep the skew
   internal to the cache, or report `exp − skew` to make client-go itself re-invoke early?
   *Assumed:* raw `exp` (honest value; client-go already refreshes on 401), with skew applied
   only to our cache-validity check.
