FROM golang:1.25-bookworm AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /kubectl-krb_keycloak ./cmd/kubectl-krb_keycloak

FROM debian:bookworm-slim

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y ca-certificates curl jq \
    && apt-get clean \
    && find /var/lib/apt/lists -mindepth 1 -delete

COPY --from=build /kubectl-krb_keycloak /usr/local/bin/kubectl-krb_keycloak
COPY integration/test/run.sh /usr/local/bin/run-integration-test

ENTRYPOINT ["/usr/local/bin/run-integration-test"]
