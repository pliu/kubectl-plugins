package app

import (
	"io"
	"testing"
	"time"
)

func TestParseConfigPrecedenceAndDefaults(t *testing.T) {
	t.Parallel()
	environment := map[string]string{
		"KUBECTL_KRB_KEYCLOAK_ISSUER_URL": "https://env.example/realms/prod/",
		"KUBECTL_KRB_KEYCLOAK_CLIENT_ID":  "env-client",
		"KRB5_CONFIG":                     "/env/krb5.conf",
		"KRB5CCNAME":                      "FILE:~/tickets",
	}
	config, err := ParseConfig([]string{"--client-id=flag-client", "--expiry-skew=2m"}, func(key string) (string, bool) {
		value, ok := environment[key]
		return value, ok
	}, io.Discard)
	if err != nil {
		t.Fatalf("ParseConfig() error = %v", err)
	}
	if config.IssuerURL != "https://env.example/realms/prod" || config.ClientID != "flag-client" {
		t.Errorf("resolved identity config = %#v", config)
	}
	if config.RedirectURI != "http://localhost:8000" || config.Scope != "openid profile email" || config.ExpirySkew != 2*time.Minute {
		t.Errorf("defaults = %#v", config)
	}
	if config.KRB5Config != "/env/krb5.conf" || config.CCache == "FILE:~/tickets" {
		t.Errorf("Kerberos config = %#v", config)
	}
}

func TestParseConfigErrors(t *testing.T) {
	t.Parallel()
	env := func(string) (string, bool) { return "", false }
	for _, args := range [][]string{
		{},
		{"--issuer-url=https://sso.example", "--client-id=x", "--expiry-skew=nope"},
		{"--issuer-url=https://sso.example", "--client-id=x", "--keytab=file"},
		{"--issuer-url=https://sso.example", "--client-id=x", "--principal=alice"},
		{"--issuer-url=https://sso.example", "--client-id=x", "positional"},
	} {
		if _, err := ParseConfig(args, env, io.Discard); err == nil {
			t.Errorf("ParseConfig(%v) error = nil", args)
		}
	}
}
