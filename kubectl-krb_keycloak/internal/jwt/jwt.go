// Package jwt parses the small subset of JWT claims needed by the credential plugin.
// It deliberately does not verify signatures; Kubernetes remains the token verifier.
package jwt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// Claims contains the diagnostic identity claims and mandatory expiry used by the plugin.
type Claims struct {
	ExpiresAt         time.Time
	Subject           string
	PreferredUsername string
}

// Parse validates the compact JWT structure and extracts selected payload claims.
func Parse(token string) (Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return Claims{}, errors.New("token is not a compact JWT with three non-empty segments")
	}

	if _, err := decodeSegment(parts[0]); err != nil {
		return Claims{}, fmt.Errorf("invalid JWT header encoding: %w", err)
	}
	payload, err := decodeSegment(parts[1])
	if err != nil {
		return Claims{}, fmt.Errorf("invalid JWT payload encoding: %w", err)
	}
	if _, err := decodeSegment(parts[2]); err != nil {
		return Claims{}, fmt.Errorf("invalid JWT signature encoding: %w", err)
	}

	var raw struct {
		ExpiresAt         json.Number `json:"exp"`
		Subject           string      `json:"sub"`
		PreferredUsername string      `json:"preferred_username"`
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if err := decoder.Decode(&raw); err != nil {
		return Claims{}, fmt.Errorf("invalid JWT payload JSON: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Claims{}, errors.New("invalid JWT payload JSON: trailing data")
	}
	if raw.ExpiresAt == "" {
		return Claims{}, errors.New("JWT payload is missing the exp claim")
	}
	exp, err := raw.ExpiresAt.Int64()
	if err != nil || exp <= 0 {
		return Claims{}, errors.New("JWT exp claim must be a positive integer")
	}

	return Claims{
		ExpiresAt:         time.Unix(exp, 0).UTC(),
		Subject:           raw.Subject,
		PreferredUsername: raw.PreferredUsername,
	}, nil
}

func decodeSegment(segment string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(segment)
	if err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(segment)
}
