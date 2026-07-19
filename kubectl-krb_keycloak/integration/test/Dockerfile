FROM golang:1.25-bookworm AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /kubectl-krb_keycloak ./cmd/kubectl-krb_keycloak

FROM debian:bookworm-slim

ARG KUBECTL_VERSION=v1.33.1

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y \
        ca-certificates \
        curl \
        jq \
        openssl \
        python3 \
    && arch="$(dpkg --print-architecture)" \
    && curl -fsSL "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${arch}/kubectl" \
        -o /usr/local/bin/kubectl \
    && chmod 0755 /usr/local/bin/kubectl \
    && apt-get clean \
    && find /var/lib/apt/lists -mindepth 1 -delete

COPY --from=build /kubectl-krb_keycloak /usr/local/bin/kubectl-krb_keycloak
COPY integration/test/mock-apiserver.py /usr/local/bin/mock-apiserver.py
COPY integration/test/run.sh /usr/local/bin/run-integration-test

ENTRYPOINT ["/usr/local/bin/run-integration-test"]
