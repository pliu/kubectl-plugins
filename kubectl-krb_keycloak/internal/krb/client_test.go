package krb

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewPrefersKeytabOverCCache(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	krb5Config := filepath.Join(dir, "krb5.conf")
	if err := os.WriteFile(krb5Config, []byte("[libdefaults]\n default_realm = EXAMPLE.COM\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	httpClient, err := NewHTTPClient(HTTPConfig{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = New(Config{
		KRB5Config: krb5Config,
		CCache:     filepath.Join(dir, "missing.ccache"),
		Keytab:     filepath.Join(dir, "missing.keytab"),
		Principal:  "alice",
		Realm:      "EXAMPLE.COM",
	}, httpClient)
	if err == nil || !strings.Contains(err.Error(), "load Kerberos keytab") {
		t.Fatalf("New() error = %v; want keytab load error", err)
	}
}

func TestResolveCCachePath(t *testing.T) {
	t.Parallel()
	tests := []struct {
		value    string
		fallback string
		want     string
		wantErr  bool
	}{
		{"", "/tmp/default", "/tmp/default", false},
		{"/tmp/cache", "", "/tmp/cache", false},
		{"FILE:/tmp/cache", "", "/tmp/cache", false},
		{"file:/tmp/cache", "", "/tmp/cache", false},
		{`C:\Temp\krb5cc_alice`, "", "", true},
		{"KCM:123", "", "", true},
		{"API:abc", "", "", true},
		{"FILE:", "", "", true},
	}
	for _, test := range tests {
		got, err := resolveCCachePath(test.value, test.fallback)
		if (err != nil) != test.wantErr || got != test.want {
			t.Errorf("resolveCCachePath(%q, %q) = %q, %v; want %q, error=%v", test.value, test.fallback, got, err, test.want, test.wantErr)
		}
	}
}

func TestHasNegotiateChallenge(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		values []string
		want   bool
	}{
		{[]string{"Negotiate"}, true},
		{[]string{"Basic realm=x, negotiate token"}, true},
		{[]string{"Basic realm=x"}, false},
		{nil, false},
	} {
		if got := hasNegotiateChallenge(test.values); got != test.want {
			t.Errorf("hasNegotiateChallenge(%v) = %v, want %v", test.values, got, test.want)
		}
	}
}

func TestNewHTTPClient(t *testing.T) {
	t.Parallel()
	client, err := NewHTTPClient(HTTPConfig{})
	if err != nil {
		t.Fatalf("NewHTTPClient() error = %v", err)
	}
	if client.Jar == nil || client.CheckRedirect == nil || client.Timeout == 0 {
		t.Fatalf("HTTP client is incompletely configured: %#v", client)
	}
	request, _ := http.NewRequest(http.MethodGet, "https://example.com", nil)
	if err := client.CheckRedirect(request, nil); err != http.ErrUseLastResponse {
		t.Errorf("CheckRedirect() = %v", err)
	}
}

func TestNewHTTPClientRejectsInvalidCA(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewHTTPClient(HTTPConfig{CAFile: path}); err == nil {
		t.Fatal("NewHTTPClient() error = nil")
	}
}
