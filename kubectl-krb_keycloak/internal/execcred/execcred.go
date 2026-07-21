// Package execcred writes Kubernetes client.authentication.k8s.io/v1 ExecCredential values.
package execcred

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientauthenticationv1 "k8s.io/client-go/pkg/apis/clientauthentication/v1"
)

const (
	// APIVersion is the ExecCredential API version emitted by the plugin.
	APIVersion = "client.authentication.k8s.io/v1"
	Kind       = "ExecCredential"
)

// Write emits a successful credential response.
func Write(writer io.Writer, token string, expiresAt time.Time) error {
	if token == "" {
		return errors.New("cannot write an empty credential token")
	}
	expiry := metav1.NewTime(expiresAt.UTC())
	response := clientauthenticationv1.ExecCredential{
		TypeMeta: metav1.TypeMeta{APIVersion: APIVersion, Kind: Kind},
		Status: &clientauthenticationv1.ExecCredentialStatus{
			Token:               token,
			ExpirationTimestamp: &expiry,
		},
	}
	if err := json.NewEncoder(writer).Encode(response); err != nil {
		return fmt.Errorf("encode ExecCredential response: %w", err)
	}
	return nil
}
