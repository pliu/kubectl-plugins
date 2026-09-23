// Package app contains CLI configuration and top-level dependency wiring.
package app

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Config is the resolved flag and environment configuration.
type Config struct {
	IssuerURL             string
	ClientID              string
	RedirectURI           string
	Scope                 string
	CacheDir              string
	ExpirySkew            time.Duration
	KRB5Config            string
	CCache                string
	Keytab                string
	Principal             string
	CAFile                string
	InsecureSkipTLSVerify bool
}

// Environment provides testable environment lookup.
type Environment func(string) (string, bool)

// ParseConfig applies flag > environment > default precedence, except that keytab credentials are
// configured only through environment variables and take precedence over ccache configuration.
func ParseConfig(args []string, lookup Environment, output io.Writer) (Config, error) {
	if lookup == nil {
		lookup = os.LookupEnv
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return Config{}, fmt.Errorf("resolve home directory: %w", err)
	}
	value := func(name, fallback string) string {
		if result, ok := lookup(name); ok && result != "" {
			return result
		}
		return fallback
	}

	config := Config{
		Keytab:    value("KUBECTL_KRB_KEYCLOAK_KEYTAB", ""),
		Principal: value("KUBECTL_KRB_KEYCLOAK_PRINCIPAL", ""),
	}
	expirySkew := value("KUBECTL_KRB_KEYCLOAK_EXPIRY_SKEW", "60s")
	flags := flag.NewFlagSet("kubectl-krb_keycloak", flag.ContinueOnError)
	flags.SetOutput(output)
	flags.StringVar(&config.IssuerURL, "issuer-url", value("KUBECTL_KRB_KEYCLOAK_ISSUER_URL", ""), "Keycloak realm issuer URL (required)")
	flags.StringVar(&config.ClientID, "client-id", value("KUBECTL_KRB_KEYCLOAK_CLIENT_ID", ""), "Keycloak public OIDC client ID (required)")
	flags.StringVar(&config.RedirectURI, "redirect-uri", value("KUBECTL_KRB_KEYCLOAK_REDIRECT_URI", "http://localhost:8000"), "registered redirect URI (never bound)")
	flags.StringVar(&config.Scope, "scope", value("KUBECTL_KRB_KEYCLOAK_SCOPE", "openid profile email"), "OIDC scopes")
	flags.StringVar(&config.CacheDir, "cache-dir", value("KUBECTL_KRB_KEYCLOAK_CACHE_DIR", filepath.Join(home, ".kube", "cache", "krb-keycloak")), "ID token cache directory")
	flags.StringVar(&expirySkew, "expiry-skew", expirySkew, "duration before expiry at which cache entries become stale")
	flags.StringVar(&config.KRB5Config, "krb5-conf", value("KRB5_CONFIG", "/etc/krb5.conf"), "krb5.conf path")
	flags.StringVar(&config.CCache, "ccache", value("KRB5CCNAME", ""), "FILE credential cache path")
	flags.StringVar(&config.CAFile, "ca-file", value("KUBECTL_KRB_KEYCLOAK_CA_FILE", ""), "additional PEM CA bundle")
	flags.BoolVar(&config.InsecureSkipTLSVerify, "insecure-skip-tls-verify", false, "disable Keycloak TLS certificate verification (unsafe)")
	if err := flags.Parse(args); err != nil {
		return Config{}, err
	}
	if flags.NArg() != 0 {
		return Config{}, fmt.Errorf("unexpected positional arguments: %s", strings.Join(flags.Args(), " "))
	}

	config.IssuerURL = strings.TrimRight(strings.TrimSpace(config.IssuerURL), "/")
	config.ClientID = strings.TrimSpace(config.ClientID)
	config.RedirectURI = strings.TrimSpace(config.RedirectURI)
	config.Scope = strings.Join(strings.Fields(config.Scope), " ")
	config.Principal = strings.TrimSpace(config.Principal)
	if config.IssuerURL == "" {
		return Config{}, errors.New("--issuer-url is required (or set KUBECTL_KRB_KEYCLOAK_ISSUER_URL)")
	}
	if config.ClientID == "" {
		return Config{}, errors.New("--client-id is required (or set KUBECTL_KRB_KEYCLOAK_CLIENT_ID)")
	}
	if config.Scope == "" {
		return Config{}, errors.New("--scope must not be empty")
	}
	config.ExpirySkew, err = time.ParseDuration(expirySkew)
	if err != nil || config.ExpirySkew < 0 {
		return Config{}, fmt.Errorf("--expiry-skew must be a non-negative duration, got %q", expirySkew)
	}
	if config.Keytab != "" && config.Principal == "" {
		return Config{}, errors.New("KUBECTL_KRB_KEYCLOAK_KEYTAB requires KUBECTL_KRB_KEYCLOAK_PRINCIPAL")
	}
	if config.Keytab == "" && config.Principal != "" {
		return Config{}, errors.New("KUBECTL_KRB_KEYCLOAK_PRINCIPAL requires KUBECTL_KRB_KEYCLOAK_KEYTAB")
	}
	if config.Principal != "" {
		name, realm, err := splitPrincipal(config.Principal)
		if err != nil {
			return Config{}, err
		}
		config.Principal = name + "@" + realm
	}

	for name, path := range map[string]*string{
		"cache directory": &config.CacheDir,
		"krb5.conf":       &config.KRB5Config,
		"keytab":          &config.Keytab,
		"CA file":         &config.CAFile,
	} {
		if *path == "" {
			continue
		}
		expanded, err := expandHome(*path, home)
		if err != nil {
			return Config{}, fmt.Errorf("invalid %s: %w", name, err)
		}
		*path = expanded
	}
	if config.CCache != "" {
		prefix := ""
		path := config.CCache
		if strings.HasPrefix(strings.ToUpper(path), "FILE:") {
			prefix, path = path[:len("FILE:")], path[len("FILE:"):]
		}
		expanded, err := expandHome(path, home)
		if err != nil {
			return Config{}, fmt.Errorf("invalid ccache path: %w", err)
		}
		config.CCache = prefix + expanded
	}
	return config, nil
}

// splitPrincipal separates a name@REALM client principal. The realm is the text after the
// first @, so a host component stays in the name: svc/host.example.com@EXAMPLE.COM.
func splitPrincipal(principal string) (string, string, error) {
	name, realm, ok := strings.Cut(strings.TrimSpace(principal), "@")
	name = strings.TrimSpace(name)
	realm = strings.TrimSpace(realm)
	if !ok || name == "" || realm == "" || strings.Contains(realm, "@") {
		return "", "", errors.New("KUBECTL_KRB_KEYCLOAK_PRINCIPAL must be name@REALM")
	}
	return name, realm, nil
}

func expandHome(path, home string) (string, error) {
	if path == "~" {
		return home, nil
	}
	if strings.HasPrefix(path, "~/") || strings.HasPrefix(path, `~\`) {
		return filepath.Join(home, path[2:]), nil
	}
	if strings.HasPrefix(path, "~") {
		return "", errors.New("only ~/ home expansion is supported")
	}
	return path, nil
}
