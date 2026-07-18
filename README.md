# kubectl plugins

This repository contains independently versioned Go modules for kubectl plugins. Each plugin owns
its dependencies and build targets.

## Plugins

- [`kubectl-krb_keycloak`](docs/kubectl-krb_keycloak.md) — obtains Kubernetes exec credentials
  from Keycloak by using an existing Kerberos ticket or a keytab for silent SPNEGO authentication.

There are intentionally no repository automation workflows; use the root `Makefile` to build,
test, vet, or cross-compile the plugin locally.
