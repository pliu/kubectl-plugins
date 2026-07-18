// Package execcred reads and writes Kubernetes client.authentication.k8s.io/v1 ExecCredential values.
package execcred

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientauthenticationv1 "k8s.io/client-go/pkg/apis/clientauthentication/v1"
)

const (
	// APIVersion is the only ExecCredential API version supported by the plugin.
	APIVersion = "client.authentication.k8s.io/v1"
	Kind       = "ExecCredential"
)

// Read gets the request from KUBERNETES_EXEC_INFO when present, otherwise from stdin.
func Read(stdin io.Reader, execInfo string) (*clientauthenticationv1.ExecCredential, error) {
	var source io.Reader = stdin
	if strings.TrimSpace(execInfo) != "" {
		source = strings.NewReader(execInfo)
	} else if isTerminal(stdin) {
		return nil, errors.New("KUBERNETES_EXEC_INFO was not provided; pipe an ExecCredential JSON request on stdin for manual use")
	}
	decoder := json.NewDecoder(source)
	var request clientauthenticationv1.ExecCredential
	if err := decoder.Decode(&request); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("ExecCredential request is empty; KUBERNETES_EXEC_INFO was not provided")
		}
		return nil, fmt.Errorf("decode ExecCredential request: %w", err)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("decode ExecCredential request: unexpected trailing JSON")
	}
	if request.APIVersion != APIVersion {
		return nil, fmt.Errorf("unsupported ExecCredential apiVersion %q; set apiVersion: %s in the kubeconfig exec stanza", request.APIVersion, APIVersion)
	}
	if request.Kind != Kind {
		return nil, fmt.Errorf("unsupported credential kind %q; expected %s", request.Kind, Kind)
	}
	return &request, nil
}

func isTerminal(reader io.Reader) bool {
	statter, ok := reader.(interface {
		Stat() (os.FileInfo, error)
	})
	if !ok {
		return false
	}
	info, err := statter.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// ReadFromEnvironment reads the request from stdin and KUBERNETES_EXEC_INFO.
func ReadFromEnvironment() (*clientauthenticationv1.ExecCredential, error) {
	return Read(os.Stdin, os.Getenv("KUBERNETES_EXEC_INFO"))
}

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
