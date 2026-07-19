package keycloak

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func TestAuthenticateHappyPath(t *testing.T) {
	t.Parallel()
	stateBytes := bytes.Repeat([]byte{1}, 32)
	verifierBytes := bytes.Repeat([]byte{2}, 32)
	state := base64.RawURLEncoding.EncodeToString(stateBytes)
	verifier := base64.RawURLEncoding.EncodeToString(verifierBytes)
	challengeBytes := sha256.Sum256([]byte(verifier))
	wantChallenge := base64.RawURLEncoding.EncodeToString(challengeBytes[:])
	const idToken = "header.payload.signature"

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/realms/prod/protocol/openid-connect/auth":
			if request.Header.Get("Authorization") == "" {
				writer.Header().Set("WWW-Authenticate", "Negotiate")
				writer.WriteHeader(http.StatusUnauthorized)
				return
			}
			query := request.URL.Query()
			if query.Get("response_type") != "code" || query.Get("code_challenge_method") != "S256" || query.Get("code_challenge") != wantChallenge {
				t.Errorf("authorization query = %v", query)
			}
			http.SetCookie(writer, &http.Cookie{Name: "AUTH_SESSION_ID", Value: "session", Path: "/"})
			http.Redirect(writer, request, server.URL+"/realms/prod/login-actions/authenticate", http.StatusFound)
		case "/realms/prod/login-actions/authenticate":
			if cookie, err := request.Cookie("AUTH_SESSION_ID"); err != nil || cookie.Value != "session" {
				t.Errorf("session cookie = %v, %v", cookie, err)
			}
			http.Redirect(writer, request, "http://localhost:8000?code=the-code&state="+url.QueryEscape(state), http.StatusFound)
		case "/realms/prod/protocol/openid-connect/token":
			if err := request.ParseForm(); err != nil {
				t.Errorf("ParseForm() error = %v", err)
			}
			if request.Form.Get("code") != "the-code" || request.Form.Get("code_verifier") != verifier || request.Form.Get("redirect_uri") != "http://localhost:8000" {
				t.Errorf("token form = %v", request.Form)
			}
			writer.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(writer).Encode(map[string]string{"id_token": idToken, "access_token": "must-not-be-returned"})
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	jar, _ := cookiejar.New(nil)
	httpClient := server.Client()
	httpClient.Jar = jar
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	doer := &fakeNegotiateDoer{client: httpClient}
	flow, err := New(Config{
		IssuerURL:   server.URL + "/realms/prod",
		ClientID:    "kubectl",
		RedirectURI: "http://localhost:8000",
		Scope:       "openid profile email",
		Random:      bytes.NewReader(append(stateBytes, verifierBytes...)),
	}, doer)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	got, err := flow.Authenticate(context.Background())
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if got != idToken {
		t.Errorf("Authenticate() = %q, want %q", got, idToken)
	}
	if doer.challenges.Load() != 1 {
		t.Errorf("SPNEGO challenges = %d, want 1", doer.challenges.Load())
	}
}

func TestAuthenticateFlowErrors(t *testing.T) {
	t.Parallel()
	state := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	tests := map[string]struct {
		responses []scriptedResponse
		want      string
	}{
		"state mismatch": {
			responses: []scriptedResponse{{status: http.StatusFound, location: "http://localhost:8000?code=x&state=wrong"}},
			want:      "state mismatch",
		},
		"authorization error": {
			responses: []scriptedResponse{{status: http.StatusFound, location: "http://localhost:8000?error=access_denied&error_description=Kerberos+failed&state=" + state}},
			want:      "access_denied: Kerberos failed",
		},
		"interactive page": {
			responses: []scriptedResponse{{status: http.StatusOK}},
			want:      "interactive login page",
		},
		"SPNEGO rejected": {
			responses: []scriptedResponse{{status: http.StatusUnauthorized}},
			want:      "SPNEGO authentication was rejected",
		},
		"missing code": {
			responses: []scriptedResponse{{status: http.StatusFound, location: "http://localhost:8000?state=" + state}},
			want:      "did not contain an authorization code",
		},
		"external redirect": {
			responses: []scriptedResponse{{status: http.StatusFound, location: "https://evil.example/login"}},
			want:      "untrusted origin",
		},
		"token rejected": {
			responses: []scriptedResponse{
				{status: http.StatusFound, location: "http://localhost:8000?code=x&state=" + state},
				{status: http.StatusBadRequest, body: `{"error":"invalid_grant","error_description":"expired code"}`},
			},
			want: "invalid_grant: expired code",
		},
		"token rejected without error payload": {
			responses: []scriptedResponse{
				{status: http.StatusFound, location: "http://localhost:8000?code=x&state=" + state},
				{status: http.StatusServiceUnavailable, body: `{}`},
			},
			want: "returned HTTP 503",
		},
		"missing id token": {
			responses: []scriptedResponse{
				{status: http.StatusFound, location: "http://localhost:8000?code=x&state=" + state},
				{status: http.StatusOK, body: `{"access_token":"access-only"}`},
			},
			want: "openid scope",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			doer := &scriptedDoer{responses: test.responses}
			flow, err := New(Config{
				IssuerURL:   "https://sso.example/realms/prod",
				ClientID:    "kubectl",
				RedirectURI: "http://localhost:8000",
				Scope:       "openid",
				Random:      bytes.NewReader(make([]byte, 64)),
			}, doer)
			if err != nil {
				t.Fatal(err)
			}
			_, err = flow.Authenticate(context.Background())
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Authenticate() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestErrorDetailOmitsEmptyParts(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		parts []string
		want  string
	}{
		{[]string{"invalid_grant", "expired code"}, "invalid_grant: expired code"},
		{[]string{"invalid_grant", ""}, "invalid_grant"},
		{[]string{"", ""}, ""},
		{[]string{" access_denied ", "line one\nline two"}, "access_denied: line one line two"},
	} {
		if got := errorDetail(test.parts...); got != test.want {
			t.Errorf("errorDetail(%q) = %q, want %q", test.parts, got, test.want)
		}
	}
}

func TestNewRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()
	for _, config := range []Config{
		{},
		{ClientID: "client", Scope: "openid", IssuerURL: "not-url", RedirectURI: "http://localhost"},
		{ClientID: "client", Scope: "openid", IssuerURL: "https://sso.example", RedirectURI: "/relative"},
	} {
		if _, err := New(config, &scriptedDoer{}); err == nil {
			t.Errorf("New(%#v) error = nil", config)
		}
	}
}

type fakeNegotiateDoer struct {
	client     *http.Client
	challenges atomic.Int32
}

func (d *fakeNegotiateDoer) Do(request *http.Request) (*http.Response, error) {
	response, err := d.client.Do(request)
	if err != nil || response.StatusCode != http.StatusUnauthorized || !strings.Contains(response.Header.Get("WWW-Authenticate"), "Negotiate") {
		return response, err
	}
	closeResponse(response)
	d.challenges.Add(1)
	retry := request.Clone(request.Context())
	retry.Header.Set("Authorization", "Negotiate test-token")
	return d.client.Do(retry)
}

type scriptedResponse struct {
	status   int
	location string
	body     string
}

type scriptedDoer struct {
	responses []scriptedResponse
	index     int
}

func (d *scriptedDoer) Do(request *http.Request) (*http.Response, error) {
	if d.index >= len(d.responses) {
		return nil, io.EOF
	}
	item := d.responses[d.index]
	d.index++
	header := make(http.Header)
	if item.location != "" {
		header.Set("Location", item.location)
	}
	return &http.Response{
		StatusCode: item.status,
		Header:     header,
		Body:       io.NopCloser(strings.NewReader(item.body)),
		Request:    request,
	}, nil
}
