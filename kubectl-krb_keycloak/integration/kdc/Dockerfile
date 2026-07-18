FROM debian:bookworm-slim

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y krb5-admin-server krb5-kdc \
    && apt-get clean \
    && find /var/lib/apt/lists -mindepth 1 -delete

COPY krb5.conf /etc/krb5.conf
COPY kdc.conf /etc/krb5kdc/kdc.conf
COPY entrypoint.sh /usr/local/bin/kdc-entrypoint

EXPOSE 88/tcp 88/udp
ENTRYPOINT ["/usr/local/bin/kdc-entrypoint"]
