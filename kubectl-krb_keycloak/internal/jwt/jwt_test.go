package jwt

import (
	"encoding/base64"
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	t.Parallel()
	exp := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	token := segment(`{"alg":"none"}`) + "." +
		segment(`{"exp":`+"1893553445"+`,"sub":"42","preferred_username":"alice"}`) + "." +
		segment("signature")

	claims, err := Parse(token)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if !claims.ExpiresAt.Equal(exp) {
		t.Errorf("ExpiresAt = %v, want %v", claims.ExpiresAt, exp)
	}
	if claims.Subject != "42" || claims.PreferredUsername != "alice" {
		t.Errorf("identity claims = %#v", claims)
	}
}

func TestParseErrors(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"not compact":      "not-a-jwt",
		"bad header":       "*." + segment(`{"exp":1}`) + "." + segment("sig"),
		"bad payload":      segment(`{}`) + ".*." + segment("sig"),
		"bad signature":    segment(`{}`) + "." + segment(`{"exp":1}`) + ".*",
		"malformed json":   segment(`{}`) + "." + segment(`{"exp":`) + "." + segment("sig"),
		"trailing json":    segment(`{}`) + "." + segment(`{"exp":1} {}`) + "." + segment("sig"),
		"missing exp":      segment(`{}`) + "." + segment(`{"sub":"1"}`) + "." + segment("sig"),
		"fractional exp":   segment(`{}`) + "." + segment(`{"exp":1.5}`) + "." + segment("sig"),
		"non-positive exp": segment(`{}`) + "." + segment(`{"exp":0}`) + "." + segment("sig"),
	}
	for name, token := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := Parse(token); err == nil {
				t.Fatal("Parse() error = nil")
			}
		})
	}
}

func TestParsePaddedBase64URL(t *testing.T) {
	t.Parallel()
	encode := base64.URLEncoding.EncodeToString
	token := encode([]byte(`{}`)) + "." + encode([]byte(`{"exp":1893553445}`)) + "." + encode([]byte("sig"))
	if _, err := Parse(token); err != nil {
		t.Fatalf("Parse() padded token error = %v", err)
	}
}

func segment(value string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(value))
}
