package store

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newTestStore(t *testing.T) (*Store, MemoryKeyring, string) {
	t.Helper()
	ring := MemoryKeyring{}
	path := filepath.Join(t.TempDir(), "secrets.toml")
	return Open(path, ring), ring, path
}

func TestPutGetValue(t *testing.T) {
	s, _, _ := newTestStore(t)
	policy := Policy{Hosts: []string{"api.stripe.com"}, Auth: "bearer", AllowRun: true}
	if err := s.Put("STRIPE_KEY", "sk_test_123", Meta{Description: "Stripe test key"}, policy); err != nil {
		t.Fatal(err)
	}

	got, err := s.Get("STRIPE_KEY")
	if err != nil {
		t.Fatal(err)
	}
	if got.Description != "Stripe test key" || got.Hosts[0] != "api.stripe.com" || !got.AllowRun {
		t.Fatalf("unexpected secret: %+v", got)
	}
	if got.Added.IsZero() {
		t.Error("Added was not set")
	}

	v, err := s.Value("STRIPE_KEY")
	if err != nil || v != "sk_test_123" {
		t.Fatalf("Value = %q, %v", v, err)
	}
}

func TestIndexNeverContainsValueOrPolicy(t *testing.T) {
	s, _, path := newTestStore(t)
	err := s.Put("TOKEN", "super-secret-value", Meta{Description: "d"}, Policy{Hosts: []string{"example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, leaked := range []string{"super-secret-value", "example.com"} {
		if strings.Contains(string(data), leaked) {
			t.Errorf("index contains %q:\n%s", leaked, data)
		}
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Errorf("index mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestEditingIndexDoesNotChangePolicy(t *testing.T) {
	s, _, path := newTestStore(t)
	if err := s.Put("TOKEN", "v", Meta{}, Policy{Hosts: []string{"good.com"}}); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("hosts = [\"evil.com\"]\n")
	f.Close()

	got, err := s.Get("TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Hosts) != 1 || got.Hosts[0] != "good.com" {
		t.Fatalf("hosts = %v", got.Hosts)
	}
}

func TestListSorted(t *testing.T) {
	s, _, _ := newTestStore(t)
	for _, n := range []string{"B", "A", "C"} {
		if err := s.Put(n, "value", Meta{}, Policy{}); err != nil {
			t.Fatal(err)
		}
	}
	list, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, sec := range list {
		names = append(names, sec.Name)
	}
	if strings.Join(names, ",") != "A,B,C" {
		t.Fatalf("names = %v", names)
	}
}

func TestRemove(t *testing.T) {
	s, ring, _ := newTestStore(t)
	if err := s.Put("X", "value", Meta{}, Policy{}); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove("X"); err != nil {
		t.Fatal(err)
	}
	if len(ring) != 0 {
		t.Errorf("keychain still has entries: %v", ring)
	}
	if _, err := s.Get("X"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get after Remove: %v", err)
	}
	if err := s.Remove("X"); !errors.Is(err, ErrNotFound) {
		t.Errorf("second Remove: %v", err)
	}
}

func TestSetPolicyAndUpdateMeta(t *testing.T) {
	s, _, _ := newTestStore(t)
	if err := s.Put("X", "value", Meta{}, Policy{}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetPolicy("X", Policy{Hosts: []string{"a.com"}, AllowRun: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateMeta("X", func(m *Meta) { m.Description = "new" }); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Get("X")
	if got.Description != "new" || got.Hosts[0] != "a.com" {
		t.Fatalf("got %+v", got)
	}
	if v, _ := s.Value("X"); v != "value" {
		t.Errorf("SetPolicy changed the value to %q", v)
	}
}

func TestValidateName(t *testing.T) {
	for _, ok := range []string{"A", "_x", "STRIPE_KEY_2"} {
		if err := ValidateName(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "2X", "A-B", "a b", "x.y"} {
		if err := ValidateName(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestMissingKeychainEntry(t *testing.T) {
	s, ring, _ := newTestStore(t)
	if err := s.Put("X", "value", Meta{}, Policy{}); err != nil {
		t.Fatal(err)
	}
	delete(ring, Service+"/X")
	if _, err := s.Get("X"); err == nil || !strings.Contains(err.Error(), "missing from the keychain") {
		t.Fatalf("err = %v", err)
	}
}
