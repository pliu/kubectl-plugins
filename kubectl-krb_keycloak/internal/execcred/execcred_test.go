package execcred

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	clientauthenticationv1 "k8s.io/client-go/pkg/apis/clientauthentication/v1"
)

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
