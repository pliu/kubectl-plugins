// Package krb loads Kerberos credentials and performs HTTP Negotiate challenges with gokrb5.
package krb

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/spnego"
)

// Config selects either a file ccache or a keytab credential source.
type Config struct {
	KRB5Config string
	CCache     string
	Keytab     string
	Principal  string
	Realm      string
}

// HTTPConfig controls TLS for Keycloak connections.
type HTTPConfig struct {
	CAFile             string
	InsecureSkipVerify bool
	Timeout            time.Duration
}

// CredentialSource is the Keycloak flow's authenticated HTTP boundary.
type CredentialSource interface {
	Do(*http.Request) (*http.Response, error)
	Principal() string
	Close()
}

// Credential owns a gokrb5 client and answers Negotiate challenges on an HTTP client.
type Credential struct {
	client     *client.Client
	httpClient *http.Client
	principal  string
}

// NewHTTPClient constructs a cookie-aware, redirect-disabled HTTP client.
func NewHTTPClient(httpConfig HTTPConfig) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	tlsConfig := &tls.Config{ // #nosec G402 -- explicitly requested by a visible CLI-only flag.
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: httpConfig.InsecureSkipVerify,
	}
	if httpConfig.CAFile != "" {
		pem, err := os.ReadFile(httpConfig.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file %q: %w", httpConfig.CAFile, err)
		}
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("CA file %q does not contain a valid PEM certificate", httpConfig.CAFile)
		}
		tlsConfig.RootCAs = roots
	}
	transport.TLSClientConfig = tlsConfig
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("create Keycloak cookie jar: %w", err)
	}
	if httpConfig.Timeout <= 0 {
		httpConfig.Timeout = 30 * time.Second
	}
	return &http.Client{
		Transport: transport,
		Jar:       jar,
		Timeout:   httpConfig.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

// New loads Kerberos configuration and credentials. Keytab login is deferred until a challenge,
// so a valid token cache hit never contacts the KDC.
func New(krbConfig Config, httpClient *http.Client) (*Credential, error) {
	if httpClient == nil {
		return nil, errors.New("Kerberos HTTP client is required")
	}
	if krbConfig.KRB5Config == "" {
		return nil, errors.New("krb5.conf path is required")
	}
	krb5Config, err := config.Load(krbConfig.KRB5Config)
	if err != nil {
		return nil, fmt.Errorf("load krb5.conf %q: %w", krbConfig.KRB5Config, err)
	}

	if krbConfig.Keytab != "" {
		if krbConfig.Principal == "" || krbConfig.Realm == "" {
			return nil, errors.New("keytab mode requires --principal and --realm")
		}
		if strings.Contains(krbConfig.Principal, "@") {
			return nil, errors.New("--principal must not include a realm; pass it separately with --realm")
		}
		kt, err := keytab.Load(krbConfig.Keytab)
		if err != nil {
			return nil, fmt.Errorf("load Kerberos keytab %q: %w", krbConfig.Keytab, err)
		}
		krbClient := client.NewWithKeytab(krbConfig.Principal, krbConfig.Realm, kt, krb5Config)
		return &Credential{
			client:     krbClient,
			httpClient: httpClient,
			principal:  krbConfig.Principal + "@" + krbConfig.Realm,
		}, nil
	}
	if krbConfig.Principal != "" || krbConfig.Realm != "" {
		return nil, errors.New("--principal and --realm are only valid with --keytab")
	}

	ccachePath, err := resolveCCachePath(krbConfig.CCache, defaultCCachePath())
	if err != nil {
		return nil, err
	}
	cache, err := credentials.LoadCCache(ccachePath)
	if err != nil {
		return nil, fmt.Errorf("no valid Kerberos ticket cache at %q; run kinit or set --ccache: %w", ccachePath, err)
	}
	krbClient, err := client.NewFromCCache(cache, krb5Config)
	if err != nil {
		return nil, fmt.Errorf("no valid Kerberos TGT in %q; run kinit: %w", ccachePath, err)
	}
	principalName := cache.GetClientPrincipalName().PrincipalNameString() + "@" + cache.GetClientRealm()
	return &Credential{client: krbClient, httpClient: httpClient, principal: principalName}, nil
}

// Principal returns the identity included in the token cache key.
func (c *Credential) Principal() string {
	return c.principal
}

// Close destroys in-memory Kerberos sessions and tickets.
func (c *Credential) Close() {
	if c.client != nil {
		c.client.Destroy()
	}
}

// Do sends a request and, only after a 401 Negotiate challenge, retries it with SPNEGO.
func (c *Credential) Do(request *http.Request) (*http.Response, error) {
	response, err := c.httpClient.Do(request)
	if err != nil || response.StatusCode != http.StatusUnauthorized || !hasNegotiateChallenge(response.Header.Values("WWW-Authenticate")) {
		return response, err
	}
	retry, err := cloneForRetry(request)
	if err != nil {
		closeResponse(response)
		return nil, err
	}
	closeResponse(response)
	if err := spnego.SetSPNEGOHeader(c.client, retry, ""); err != nil {
		return nil, fmt.Errorf("could not acquire a Kerberos service ticket (run kinit for ccache mode or check keytab/KDC configuration): %w", err)
	}
	return c.httpClient.Do(retry)
}

func cloneForRetry(request *http.Request) (*http.Request, error) {
	retry := request.Clone(request.Context())
	if request.Body == nil {
		return retry, nil
	}
	if request.GetBody == nil {
		return nil, errors.New("cannot retry SPNEGO request body")
	}
	body, err := request.GetBody()
	if err != nil {
		return nil, fmt.Errorf("recreate SPNEGO request body: %w", err)
	}
	retry.Body = body
	return retry, nil
}

func hasNegotiateChallenge(values []string) bool {
	for _, value := range values {
		for challenge := range strings.SplitSeq(value, ",") {
			fields := strings.Fields(challenge)
			if len(fields) > 0 && strings.EqualFold(fields[0], "Negotiate") {
				return true
			}
		}
	}
	return false
}

func resolveCCachePath(value, fallback string) (string, error) {
	if value == "" {
		value = fallback
	}
	upper := strings.ToUpper(value)
	if strings.HasPrefix(upper, "FILE:") {
		value = value[len("FILE:"):]
	} else if index := strings.IndexByte(value, ':'); index > 1 {
		// A single character before the colon is a Windows drive letter, not a cache type.
		return "", fmt.Errorf("unsupported Kerberos credential cache type %q; gokrb5 requires a FILE: ccache", value[:index])
	}
	if value == "" {
		return "", errors.New("Kerberos credential cache path is empty")
	}
	return value, nil
}

func defaultCCachePath() string {
	directory := "/tmp"
	if runtime.GOOS == "windows" {
		directory = os.TempDir()
	}
	current, err := user.Current()
	if err == nil && current.Uid != "" {
		return filepath.Join(directory, "krb5cc_"+current.Uid)
	}
	return filepath.Join(directory, "krb5cc_default")
}

func closeResponse(response *http.Response) {
	if response == nil || response.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	_ = response.Body.Close()
}
