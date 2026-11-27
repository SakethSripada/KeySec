package store

import (
	"errors"

	"github.com/zalando/go-keyring"
)

// SystemKeyring returns a Keyring backed by the OS keychain: Keychain on
// macOS, the Secret Service on Linux and Credential Manager on Windows.
func SystemKeyring() Keyring {
	return systemKeyring{}
}

type systemKeyring struct{}

func (systemKeyring) Get(service, user string) (string, error) {
	v, err := keyring.Get(service, user)
	return v, mapErr(err)
}

func (systemKeyring) Set(service, user, password string) error {
	return mapErr(keyring.Set(service, user, password))
}

func (systemKeyring) Delete(service, user string) error {
	return mapErr(keyring.Delete(service, user))
}

func mapErr(err error) error {
	if errors.Is(err, keyring.ErrNotFound) {
		return ErrNotFound
	}
	return err
}

// MemoryKeyring is an in-process Keyring for tests.
type MemoryKeyring map[string]string

// Get implements Keyring.
func (m MemoryKeyring) Get(service, user string) (string, error) {
	v, ok := m[service+"/"+user]
	if !ok {
		return "", ErrNotFound
	}
	return v, nil
}

// Set implements Keyring.
func (m MemoryKeyring) Set(service, user, password string) error {
	m[service+"/"+user] = password
	return nil
}

// Delete implements Keyring.
func (m MemoryKeyring) Delete(service, user string) error {
	if _, ok := m[service+"/"+user]; !ok {
		return ErrNotFound
	}
	delete(m, service+"/"+user)
	return nil
}
