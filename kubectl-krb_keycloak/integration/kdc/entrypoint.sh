#!/bin/sh
set -eu

kdb5_util create -s -r EXAMPLE.TEST -P integration-master-password
kadmin.local -q "add_principal -randkey alice@EXAMPLE.TEST"
kadmin.local -q "add_principal -randkey HTTP/keycloak.test@EXAMPLE.TEST"

kadmin.local -q "ktadd -k /kerberos/alice.keytab -norandkey alice@EXAMPLE.TEST"
kadmin.local -q "ktadd -k /kerberos/keycloak.keytab -norandkey HTTP/keycloak.test@EXAMPLE.TEST"
chmod 0644 /kerberos/alice.keytab /kerberos/keycloak.keytab
touch /kerberos/ready

exec krb5kdc -n
