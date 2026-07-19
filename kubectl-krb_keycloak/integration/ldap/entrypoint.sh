#!/bin/sh
set -eu

slapadd -f /etc/ldap/slapd-e2e.conf -l /etc/ldap/directory.ldif
chown -R openldap:openldap /var/lib/ldap

exec slapd -d 0 -u openldap -g openldap -f /etc/ldap/slapd-e2e.conf -h ldap://0.0.0.0:389
