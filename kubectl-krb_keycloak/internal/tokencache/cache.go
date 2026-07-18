// Package tokencache provides a small, permission-restricted on-disk ID token cache.
package tokencache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Clock makes cache expiry deterministic in tests.
type Clock func() time.Time

// Identity identifies the security context in which a cached token may be reused.
type Identity struct {
	IssuerURL string
	ClientID  string
	Scope     string
	Principal string
}

// Key returns a filesystem-safe, non-identifying cache key.
func Key(identity Identity) string {
	sum := sha256.Sum256([]byte(identity.IssuerURL + "|" + identity.ClientID + "|" + identity.Scope + "|" + identity.Principal))
	return hex.EncodeToString(sum[:])
}

// Entry is the only data persisted in a cache file. Access and refresh tokens are never stored.
type Entry struct {
	IDToken   string    `json:"id_token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Cache stores token entries under Dir and considers them stale within Skew of expiry.
type Cache struct {
	Dir   string
	Skew  time.Duration
	Clock Clock
}

// Get returns a valid cached entry. Missing, malformed, incomplete, and expired entries are cache
// misses so a successful authentication can replace them. Filesystem and permission failures are
// returned because silently bypassing them could hide an unsafe cache configuration.
func (c Cache) Get(key string) (Entry, bool, error) {
	if err := validateKey(key); err != nil {
		return Entry{}, false, err
	}
	path := filepath.Join(c.Dir, key+".json")
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return Entry{}, false, nil
	}
	if err != nil {
		return Entry{}, false, fmt.Errorf("inspect token cache: %w", err)
	}
	if !info.Mode().IsRegular() {
		return Entry{}, false, errors.New("token cache entry is not a regular file")
	}
	if unsafeFilePermissions(info.Mode()) {
		return Entry{}, false, fmt.Errorf("token cache entry %q has unsafe permissions %04o; expected 0600", path, info.Mode().Perm())
	}

	f, err := os.Open(path)
	if err != nil {
		return Entry{}, false, fmt.Errorf("open token cache: %w", err)
	}
	defer f.Close()
	var entry Entry
	decoder := json.NewDecoder(io.LimitReader(f, 2<<20))
	if err := decoder.Decode(&entry); err != nil {
		return Entry{}, false, nil
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Entry{}, false, nil
	}
	if entry.IDToken == "" || entry.ExpiresAt.IsZero() {
		return Entry{}, false, nil
	}
	now := time.Now()
	if c.Clock != nil {
		now = c.Clock()
	}
	if !now.Before(entry.ExpiresAt.Add(-c.Skew)) {
		return Entry{}, false, nil
	}
	return entry, true, nil
}

// Put atomically writes an entry with private directory and file permissions.
func (c Cache) Put(key string, entry Entry) error {
	if err := validateKey(key); err != nil {
		return err
	}
	if entry.IDToken == "" || entry.ExpiresAt.IsZero() {
		return errors.New("cannot cache an entry with an empty token or expiry")
	}
	if err := os.MkdirAll(c.Dir, 0o700); err != nil {
		return fmt.Errorf("create token cache directory: %w", err)
	}
	if err := os.Chmod(c.Dir, 0o700); err != nil {
		return fmt.Errorf("secure token cache directory: %w", err)
	}

	temporary, err := os.CreateTemp(c.Dir, ".token-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary token cache: %w", err)
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("secure temporary token cache: %w", err)
	}
	encoder := json.NewEncoder(temporary)
	if err := encoder.Encode(entry); err != nil {
		return fmt.Errorf("encode token cache: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync token cache: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close token cache: %w", err)
	}
	path := filepath.Join(c.Dir, key+".json")
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace token cache: %w", err)
	}
	committed = true
	return nil
}

func validateKey(key string) error {
	if len(key) != sha256.Size*2 {
		return errors.New("invalid token cache key")
	}
	if _, err := hex.DecodeString(key); err != nil {
		return errors.New("invalid token cache key")
	}
	return nil
}
