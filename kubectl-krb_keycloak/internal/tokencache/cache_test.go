package tokencache

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestCacheRoundTripAndPermissions(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "cache")
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	cache := Cache{Dir: dir, Skew: time.Minute, Clock: func() time.Time { return now }}
	key := Key(Identity{IssuerURL: "issuer", ClientID: "client", Scope: "openid", Principal: "alice@EXAMPLE.COM"})
	want := Entry{IDToken: "header.payload.signature", ExpiresAt: now.Add(5 * time.Minute)}
	if err := cache.Put(key, want); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	got, ok, err := cache.Get(key)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !ok || got.IDToken != want.IDToken || !got.ExpiresAt.Equal(want.ExpiresAt) {
		t.Fatalf("Get() = %#v, %v; want %#v, true", got, ok, want)
	}
	assertPermissions(t, dir, 0o700)
	assertPermissions(t, filepath.Join(dir, key+".json"), 0o600)
}

func TestCacheMissAndExpiry(t *testing.T) {
	t.Parallel()
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	cache := Cache{Dir: t.TempDir(), Skew: time.Minute, Clock: func() time.Time { return now }}
	key := Key(Identity{Principal: "alice"})
	if _, ok, err := cache.Get(key); err != nil || ok {
		t.Fatalf("missing Get() ok = %v, error = %v", ok, err)
	}
	for name, expiry := range map[string]time.Time{
		"expired":     now.Add(-time.Second),
		"within skew": now.Add(time.Minute),
	} {
		t.Run(name, func(t *testing.T) {
			if err := cache.Put(key, Entry{IDToken: "token", ExpiresAt: expiry}); err != nil {
				t.Fatalf("Put() error = %v", err)
			}
			if _, ok, err := cache.Get(key); err != nil || ok {
				t.Fatalf("Get() ok = %v, error = %v", ok, err)
			}
		})
	}
}

func TestCacheTreatsCorruptionAsMissAndRejectsUnsafePermissions(t *testing.T) {
	dir := t.TempDir()
	cache := Cache{Dir: dir}
	key := Key(Identity{Principal: "alice"})
	path := filepath.Join(dir, key+".json")
	for name, contents := range map[string]string{
		"invalid JSON":     "not-json",
		"missing fields":   `{}`,
		"trailing content": `{"id_token":"x","expires_at":"2030-01-01T00:00:00Z"} {}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, ok, err := cache.Get(key); err != nil || ok {
				t.Fatalf("Get() corrupted entry ok = %v, error = %v; want miss", ok, err)
			}
		})
	}
	if runtime.GOOS == "windows" {
		return
	}
	if err := os.WriteFile(path, []byte(`{"id_token":"x","expires_at":"2030-01-01T00:00:00Z"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := cache.Get(key); err == nil {
		t.Fatal("Get() unsafe permissions error = nil")
	}
}

func TestConcurrentCacheWritersProduceACompleteEntry(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	cache := Cache{Dir: dir, Clock: func() time.Time { return now }}
	key := Key(Identity{Principal: "alice"})
	const writers = 16
	errors := make(chan error, writers)
	var wait sync.WaitGroup
	for writer := range writers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			errors <- cache.Put(key, Entry{IDToken: fmt.Sprintf("token-%d", writer), ExpiresAt: now.Add(time.Hour)})
		}()
	}
	wait.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatalf("concurrent Put() error = %v", err)
		}
	}
	entry, ok, err := cache.Get(key)
	if err != nil || !ok || entry.IDToken == "" {
		t.Fatalf("Get() after concurrent writes = %#v, %v, %v", entry, ok, err)
	}
}

func assertPermissions(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Errorf("%s permissions = %04o, want %04o", path, got, want)
	}
}
