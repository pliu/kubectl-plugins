// Package keycloak implements a non-interactive Keycloak authorization-code flow with PKCE.
package keycloak

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const (
	defaultMaxRedirects = 10
	maxResponseBody     = 1 << 20
)

// Doer is implemented by both http.Client and the Kerberos SPNEGO client.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// Config contains the public OIDC client settings for one flow.
type Config struct {
	IssuerURL    string
	ClientID     string
	RedirectURI  string
	Scope        string
	MaxRedirects int
	Random       io.Reader
}

// Flow drives browser endpoints through the injected SPNEGO-aware client.
type Flow struct {
	doer        Doer
	config      Config
	issuer      *url.URL
	redirectURI *url.URL
}

// New validates config and constructs a flow.
func New(config Config, doer Doer) (*Flow, error) {
	if doer == nil {
		return nil, errors.New("Keycloak HTTP client is required")
	}
	if strings.TrimSpace(config.ClientID) == "" {
		return nil, errors.New("Keycloak client ID is required")
	}
	if strings.TrimSpace(config.Scope) == "" {
		return nil, errors.New("OIDC scope is required")
	}
	issuer, err := parseAbsoluteURL("issuer URL", config.IssuerURL)
	if err != nil {
		return nil, err
	}
	if issuer.RawQuery != "" || issuer.Fragment != "" {
		return nil, errors.New("issuer URL must not contain a query or fragment")
	}
	redirectURI, err := parseAbsoluteURL("redirect URI", config.RedirectURI)
	if err != nil {
		return nil, err
	}
	if redirectURI.Fragment != "" {
		return nil, errors.New("redirect URI must not contain a fragment")
	}
	if config.MaxRedirects <= 0 {
		config.MaxRedirects = defaultMaxRedirects
	}
	if config.Random == nil {
		config.Random = rand.Reader
	}
	return &Flow{doer: doer, config: config, issuer: issuer, redirectURI: redirectURI}, nil
}

// Authenticate obtains an ID token without opening a browser or binding the redirect URI.
func (f *Flow) Authenticate(ctx context.Context) (string, error) {
	state, err := randomValue(f.config.Random)
	if err != nil {
		return "", fmt.Errorf("generate OAuth state: %w", err)
	}
	verifier, err := randomValue(f.config.Random)
	if err != nil {
		return "", fmt.Errorf("generate PKCE verifier: %w", err)
	}
	challengeBytes := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(challengeBytes[:])

	authorizationURL := f.endpoint("protocol/openid-connect/auth")
	query := authorizationURL.Query()
	query.Set("response_type", "code")
	query.Set("client_id", f.config.ClientID)
	query.Set("redirect_uri", f.config.RedirectURI)
	query.Set("scope", f.config.Scope)
	query.Set("state", state)
	query.Set("code_challenge", challenge)
	query.Set("code_challenge_method", "S256")
	authorizationURL.RawQuery = query.Encode()

	code, err := f.walkAuthorization(ctx, authorizationURL, state)
	if err != nil {
		return "", err
	}
	return f.exchange(ctx, code, verifier)
}

func (f *Flow) walkAuthorization(ctx context.Context, current *url.URL, state string) (string, error) {
	for hop := 0; hop <= f.config.MaxRedirects; hop++ {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, current.String(), nil)
		if err != nil {
			return "", fmt.Errorf("build Keycloak authorization request: %w", err)
		}
		request.Header.Set("Accept", "text/html,application/xhtml+xml")
		response, err := f.doer.Do(request)
		if err != nil {
			return "", fmt.Errorf("Keycloak authorization request to %s failed: %w", safeURL(current), err)
		}

		if response.StatusCode == http.StatusUnauthorized {
			closeResponse(response)
			return "", errors.New("SPNEGO authentication was rejected by Keycloak; check realm Kerberos federation and browser-flow settings")
		}
		if response.StatusCode < 300 || response.StatusCode > 399 {
			status := response.StatusCode
			closeResponse(response)
			if status >= 200 && status < 300 {
				return "", errors.New("Keycloak returned an interactive login page instead of an authorization code; check Kerberos federation and client browser-flow settings")
			}
			return "", fmt.Errorf("Keycloak authorization endpoint returned HTTP %d", status)
		}

		location := response.Header.Get("Location")
		closeResponse(response)
		if location == "" {
			return "", errors.New("Keycloak redirect did not include a Location header")
		}
		next, err := current.Parse(location)
		if err != nil {
			return "", errors.New("Keycloak returned an invalid redirect Location")
		}
		if next.User != nil {
			return "", errors.New("Keycloak redirect must not contain user information")
		}
		if f.isRedirectTarget(next) {
			return authorizationCode(next, state)
		}
		if !sameOrigin(next, f.issuer) {
			return "", fmt.Errorf("Keycloak authorization redirected to an untrusted origin %q", next.Scheme+"://"+next.Host)
		}
		current = next
	}
	return "", fmt.Errorf("Keycloak authorization exceeded %d redirects", f.config.MaxRedirects)
}

func (f *Flow) exchange(ctx context.Context, code, verifier string) (string, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {f.config.RedirectURI},
		"client_id":     {f.config.ClientID},
		"code_verifier": {verifier},
	}
	tokenURL := f.endpoint("protocol/openid-connect/token")
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("build Keycloak token request: %w", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	response, err := f.doer.Do(request)
	if err != nil {
		return "", fmt.Errorf("Keycloak token request to %s failed: %w", safeURL(tokenURL), err)
	}
	defer response.Body.Close()
	body, err := readBounded(response.Body)
	if err != nil {
		return "", fmt.Errorf("read Keycloak token response: %w", err)
	}
	var payload struct {
		IDToken          string `json:"id_token"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			return "", fmt.Errorf("Keycloak token exchange returned HTTP %d", response.StatusCode)
		}
		return "", errors.New("Keycloak token endpoint returned invalid JSON")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 || payload.Error != "" {
		detail := errorDetail(payload.Error, payload.ErrorDescription)
		if detail == "" {
			return "", fmt.Errorf("Keycloak token exchange returned HTTP %d", response.StatusCode)
		}
		return "", fmt.Errorf("Keycloak token exchange rejected the authorization code: %s", detail)
	}
	if payload.IDToken == "" {
		return "", errors.New("Keycloak token response did not contain id_token; ensure the openid scope is requested and allowed for the client")
	}
	return payload.IDToken, nil
}

func authorizationCode(target *url.URL, expectedState string) (string, error) {
	query := target.Query()
	actualState := query.Get("state")
	if actualState == "" || subtle.ConstantTimeCompare([]byte(actualState), []byte(expectedState)) != 1 {
		return "", errors.New("Keycloak authorization state mismatch")
	}
	if oauthError := query.Get("error"); oauthError != "" {
		detail := errorDetail(oauthError, query.Get("error_description"))
		return "", fmt.Errorf("Keycloak authorization rejected SPNEGO login: %s", detail)
	}
	code := query.Get("code")
	if code == "" {
		return "", errors.New("Keycloak redirect did not contain an authorization code")
	}
	return code, nil
}

func (f *Flow) endpoint(suffix string) *url.URL {
	result := *f.issuer
	result.Path = strings.TrimRight(result.Path, "/") + "/" + suffix
	result.RawPath = ""
	result.RawQuery = ""
	result.Fragment = ""
	return &result
}

func (f *Flow) isRedirectTarget(target *url.URL) bool {
	if !sameOrigin(target, f.redirectURI) || target.EscapedPath() != f.redirectURI.EscapedPath() {
		return false
	}
	configuredQuery := f.redirectURI.Query()
	targetQuery := target.Query()
	for key, values := range configuredQuery {
		actual := targetQuery[key]
		if len(actual) != len(values) {
			return false
		}
		for i := range values {
			if actual[i] != values[i] {
				return false
			}
		}
	}
	return true
}

func parseAbsoluteURL(name, value string) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") {
		return nil, fmt.Errorf("%s must be an absolute HTTP(S) URL", name)
	}
	if parsed.User != nil {
		return nil, fmt.Errorf("%s must not contain user information", name)
	}
	return parsed, nil
}

func sameOrigin(left, right *url.URL) bool {
	return strings.EqualFold(left.Scheme, right.Scheme) && strings.EqualFold(left.Host, right.Host)
}

func randomValue(reader io.Reader) (string, error) {
	value := make([]byte, 32)
	if _, err := io.ReadFull(reader, value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func readBounded(reader io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(reader, maxResponseBody+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxResponseBody {
		return nil, errors.New("response body exceeded 1 MiB")
	}
	return body, nil
}

func closeResponse(response *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	_ = response.Body.Close()
}

func safeURL(value *url.URL) string {
	copy := *value
	copy.RawQuery = ""
	copy.Fragment = ""
	return copy.String()
}

func oneLine(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

func errorDetail(parts ...string) string {
	nonEmpty := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = oneLine(part); part != "" {
			nonEmpty = append(nonEmpty, part)
		}
	}
	return strings.Join(nonEmpty, ": ")
}
