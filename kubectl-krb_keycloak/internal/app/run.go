package app

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/pliu/kubectl-plugins/kubectl-krb_keycloak/internal/execcred"
	"github.com/pliu/kubectl-plugins/kubectl-krb_keycloak/internal/jwt"
	"github.com/pliu/kubectl-plugins/kubectl-krb_keycloak/internal/keycloak"
	"github.com/pliu/kubectl-plugins/kubectl-krb_keycloak/internal/krb"
	"github.com/pliu/kubectl-plugins/kubectl-krb_keycloak/internal/tokencache"
)

// Run obtains one credential. stdout is reserved exclusively for ExecCredential JSON.
func Run(ctx context.Context, config Config, stdout, stderr io.Writer) error {
	if config.InsecureSkipTLSVerify {
		_, _ = fmt.Fprintln(stderr, "warning: Keycloak TLS certificate verification is disabled")
	}
	httpClient, err := krb.NewHTTPClient(krb.HTTPConfig{
		CAFile:             config.CAFile,
		InsecureSkipVerify: config.InsecureSkipTLSVerify,
	})
	if err != nil {
		return err
	}
	credential, err := krb.New(krb.Config{
		KRB5Config: config.KRB5Config,
		CCache:     config.CCache,
		Keytab:     config.Keytab,
		Principal:  config.Principal,
		Realm:      config.Realm,
	}, httpClient)
	if err != nil {
		return err
	}
	defer credential.Close()

	identity := tokencache.Identity{
		IssuerURL: config.IssuerURL,
		ClientID:  config.ClientID,
		Scope:     config.Scope,
		Principal: credential.Principal(),
	}
	cache := tokencache.Cache{Dir: config.CacheDir, Skew: config.ExpirySkew}
	cacheKey := tokencache.Key(identity)
	entry, hit, err := cache.Get(cacheKey)
	if err != nil {
		return err
	}
	if hit {
		claims, err := jwt.Parse(entry.IDToken)
		if err == nil && claims.ExpiresAt.Equal(entry.ExpiresAt) {
			return execcred.Write(stdout, entry.IDToken, entry.ExpiresAt)
		}
	}

	flow, err := keycloak.New(keycloak.Config{
		IssuerURL:   config.IssuerURL,
		ClientID:    config.ClientID,
		RedirectURI: config.RedirectURI,
		Scope:       config.Scope,
	}, credential)
	if err != nil {
		return err
	}
	token, err := flow.Authenticate(ctx)
	if err != nil {
		return addTLSHint(err)
	}
	claims, err := jwt.Parse(token)
	if err != nil {
		return fmt.Errorf("Keycloak returned an invalid id_token: %w", err)
	}
	if !time.Now().Before(claims.ExpiresAt.Add(-config.ExpirySkew)) {
		return errors.New("Keycloak returned an id_token that is expired or too close to expiry")
	}
	entry = tokencache.Entry{IDToken: token, ExpiresAt: claims.ExpiresAt}
	if err := cache.Put(cacheKey, entry); err != nil {
		return err
	}
	return execcred.Write(stdout, token, claims.ExpiresAt)
}

func addTLSHint(err error) error {
	var unknownAuthority x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthority) {
		return fmt.Errorf("%w (use --ca-file for a private Keycloak CA)", err)
	}
	var hostnameError x509.HostnameError
	if errors.As(err, &hostnameError) {
		return fmt.Errorf("%w (verify the issuer hostname and certificate, or use --ca-file for a private CA)", err)
	}
	return err
}
