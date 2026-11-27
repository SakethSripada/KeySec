// Package store keeps secret values in the OS keychain and descriptive
// metadata in a TOML index file.
//
// The index is safe to show to an agent. Everything that controls how a
// secret may be used (its policy) is stored in the keychain next to the value,
// so editing the index cannot widen what a secret is allowed to do.
package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"github.com/BurntSushi/toml"
)

// Service is the keychain service name every secret is stored under.
const Service = "keysec"

// ErrNotFound is returned when a secret does not exist.
var ErrNotFound = errors.New("secret not found")

var validName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

// Meta describes a secret. It never contains the value.
type Meta struct {
	Description string    `toml:"description,omitempty" json:"description,omitempty"`
	Provider    string    `toml:"provider,omitempty" json:"provider,omitempty"`
	Mode        string    `toml:"mode,omitempty" json:"mode,omitempty"`
	Scopes      []string  `toml:"scopes,omitempty" json:"scopes,omitempty"`
	Env         string    `toml:"env,omitempty" json:"env,omitempty"`
	Expires     string    `toml:"expires,omitempty" json:"expires,omitempty"`
	Added       time.Time `toml:"added" json:"added"`
}

// Policy controls where and how a secret may be used.
type Policy struct {
	// Hosts lists the hostnames an HTTP request may send the secret to.
	// A leading "*." matches any subdomain.
	Hosts []string `json:"hosts,omitempty"`
	// Auth says how the secret is attached to HTTP requests. See package
	// request for the accepted forms.
	Auth string `json:"auth,omitempty"`
	// AllowRun permits injecting the secret into a command's environment.
	AllowRun bool `json:"allow_run"`
}

// Secret is everything about a secret except its value.
type Secret struct {
	Name string `json:"name"`
	Meta
	Policy
}

// EnvName returns the environment variable the secret is exposed as.
func (s Secret) EnvName() string {
	if s.Env != "" {
		return s.Env
	}
	return s.Name
}

// Keyring is the subset of an OS keychain the store needs.
type Keyring interface {
	Get(service, user string) (string, error)
	Set(service, user, password string) error
	Delete(service, user string) error
}

// Store reads and writes secrets.
type Store struct {
	path string
	ring Keyring
}

// Open returns a store whose index lives at path.
func Open(path string, ring Keyring) *Store {
	return &Store{path: path, ring: ring}
}

// DefaultPath returns the index location: $KEYSEC_HOME/secrets.toml, or
// $XDG_CONFIG_HOME/keysec/secrets.toml, or ~/.config/keysec/secrets.toml.
func DefaultPath() (string, error) {
	if dir := os.Getenv("KEYSEC_HOME"); dir != "" {
		return filepath.Join(dir, "secrets.toml"), nil
	}
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		return filepath.Join(dir, "keysec", "secrets.toml"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "keysec", "secrets.toml"), nil
}

// ValidateName reports whether name can be used as a secret name.
func ValidateName(name string) error {
	if !validName.MatchString(name) {
		return fmt.Errorf("invalid name %q: use letters, digits and underscores, starting with a letter or underscore", name)
	}
	return nil
}

// List returns all secrets sorted by name.
func (s *Store) List() ([]Secret, error) {
	idx, err := s.load()
	if err != nil {
		return nil, err
	}
	out := make([]Secret, 0, len(idx.Secrets))
	for name, meta := range idx.Secrets {
		p, err := s.payload(name)
		if err != nil {
			return nil, err
		}
		out = append(out, Secret{Name: name, Meta: meta, Policy: p.Policy})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Get returns a secret without its value.
func (s *Store) Get(name string) (Secret, error) {
	idx, err := s.load()
	if err != nil {
		return Secret{}, err
	}
	meta, ok := idx.Secrets[name]
	if !ok {
		return Secret{}, fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	p, err := s.payload(name)
	if err != nil {
		return Secret{}, err
	}
	return Secret{Name: name, Meta: meta, Policy: p.Policy}, nil
}

// Value returns the secret's value.
func (s *Store) Value(name string) (string, error) {
	if _, err := s.Get(name); err != nil {
		return "", err
	}
	p, err := s.payload(name)
	if err != nil {
		return "", err
	}
	return p.Value, nil
}

// Values returns the values of every secret, keyed by name.
func (s *Store) Values() (map[string]string, error) {
	idx, err := s.load()
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(idx.Secrets))
	for name := range idx.Secrets {
		p, err := s.payload(name)
		if err != nil {
			return nil, err
		}
		out[name] = p.Value
	}
	return out, nil
}

// Exists reports whether a secret with the given name exists.
func (s *Store) Exists(name string) (bool, error) {
	idx, err := s.load()
	if err != nil {
		return false, err
	}
	_, ok := idx.Secrets[name]
	return ok, nil
}

// Put creates or replaces a secret.
func (s *Store) Put(name, value string, meta Meta, policy Policy) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	if value == "" {
		return errors.New("value is empty")
	}
	idx, err := s.load()
	if err != nil {
		return err
	}
	if meta.Added.IsZero() {
		meta.Added = time.Now().UTC().Truncate(time.Second)
	}
	if err := s.setPayload(name, payload{Version: 1, Value: value, Policy: policy}); err != nil {
		return err
	}
	idx.Secrets[name] = meta
	return s.save(idx)
}

// UpdateMeta applies fn to a secret's metadata and saves the result.
func (s *Store) UpdateMeta(name string, fn func(*Meta)) error {
	idx, err := s.load()
	if err != nil {
		return err
	}
	meta, ok := idx.Secrets[name]
	if !ok {
		return fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	fn(&meta)
	idx.Secrets[name] = meta
	return s.save(idx)
}

// SetPolicy replaces a secret's policy.
func (s *Store) SetPolicy(name string, policy Policy) error {
	if _, err := s.Get(name); err != nil {
		return err
	}
	p, err := s.payload(name)
	if err != nil {
		return err
	}
	p.Policy = policy
	return s.setPayload(name, p)
}

// Remove deletes a secret from the keychain and the index.
func (s *Store) Remove(name string) error {
	idx, err := s.load()
	if err != nil {
		return err
	}
	if _, ok := idx.Secrets[name]; !ok {
		return fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	if err := s.ring.Delete(Service, name); err != nil && !errors.Is(err, ErrNotFound) {
		return fmt.Errorf("deleting %s from keychain: %w", name, err)
	}
	delete(idx.Secrets, name)
	return s.save(idx)
}

// payload is the JSON document stored in the keychain for each secret.
type payload struct {
	Version int    `json:"v"`
	Value   string `json:"value"`
	Policy
}

func (s *Store) payload(name string) (payload, error) {
	raw, err := s.ring.Get(Service, name)
	if errors.Is(err, ErrNotFound) {
		return payload{}, fmt.Errorf("%s is in the index but missing from the keychain; remove it with `keysec rm %s`", name, name)
	}
	if err != nil {
		return payload{}, fmt.Errorf("reading %s from keychain: %w", name, err)
	}
	var p payload
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return payload{}, fmt.Errorf("keychain entry for %s is not a keysec entry", name)
	}
	return p, nil
}

func (s *Store) setPayload(name string, p payload) error {
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if err := s.ring.Set(Service, name, string(raw)); err != nil {
		return fmt.Errorf("writing %s to keychain: %w", name, err)
	}
	return nil
}

type index struct {
	Secrets map[string]Meta `toml:"secrets"`
}

func (s *Store) load() (index, error) {
	idx := index{Secrets: map[string]Meta{}}
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return idx, nil
	}
	if err != nil {
		return idx, err
	}
	if _, err := toml.Decode(string(data), &idx); err != nil {
		return idx, fmt.Errorf("parsing %s: %w", s.path, err)
	}
	if idx.Secrets == nil {
		idx.Secrets = map[string]Meta{}
	}
	return idx, nil
}

func (s *Store) save(idx index) error {
	var buf bytes.Buffer
	buf.WriteString("# Managed by keysec. Values live in the OS keychain, not here.\n\n")
	if err := toml.NewEncoder(&buf).Encode(idx); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
