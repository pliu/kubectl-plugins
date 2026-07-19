FROM debian:bookworm-slim

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y ldap-utils slapd \
    && apt-get clean \
    && find /var/lib/apt/lists -mindepth 1 -delete \
    && find /var/lib/ldap -mindepth 1 -delete

COPY slapd.conf /etc/ldap/slapd-e2e.conf
COPY directory.ldif /etc/ldap/directory.ldif
COPY entrypoint.sh /usr/local/bin/ldap-entrypoint

EXPOSE 389/tcp
ENTRYPOINT ["/usr/local/bin/ldap-entrypoint"]
