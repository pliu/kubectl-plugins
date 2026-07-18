package execcred

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	clientauthenticationv1 "k8s.io/client-go/pkg/apis/clientauthentication/v1"
)

const validRequest = `{"apiVersion":"client.authentication.k8s.io/v1","kind":"ExecCredential","spec":{"interactive":false}}`

func TestReadFromEnvironmentOrStdin(t *testing.T) {
	t.Parallel()
	request, err := Read(strings.NewReader("invalid"), validRequest)
	if err != nil {
		t.Fatalf("Read() env error = %v", err)
	}
	if request.Spec.Interactive {
		t.Error("Interactive = true, want false")
	}
	request, err = Read(strings.NewReader(validRequest), "")
	if err != nil || request.APIVersion != APIVersion {
		t.Fatalf("Read() stdin = %#v, %v", request, err)
	}
}

func TestReadRejectsInvalidInput(t *testing.T) {
	t.Parallel()
	tests := []string{
		"",
		"not-json",
		validRequest + validRequest,
		`{"apiVersion":"client.authentication.k8s.io/v1beta1","kind":"ExecCredential"}`,
		`{"apiVersion":"client.authentication.k8s.io/v1","kind":"Other"}`,
	}
	for _, input := range tests {
		if _, err := Read(strings.NewReader(input), ""); err == nil {
			t.Errorf("Read(%q) error = nil", input)
		}
	}
}

func TestWrite(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	expiresAt := time.Date(2030, 1, 2, 3, 4, 5, 0, time.FixedZone("offset", 3600))
	if err := Write(&output, "id-token", expiresAt); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	var got clientauthenticationv1.ExecCredential
	if err := json.Unmarshal(output.Bytes(), &got); err != nil {
		t.Fatalf("response JSON: %v", err)
	}
	if got.APIVersion != APIVersion || got.Kind != Kind || got.Status == nil || got.Status.Token != "id-token" {
		t.Fatalf("response = %#v", got)
	}
	if want := expiresAt.UTC(); !got.Status.ExpirationTimestamp.Time.Equal(want) {
		t.Errorf("expiration = %v, want %v", got.Status.ExpirationTimestamp.Time, want)
	}
}
