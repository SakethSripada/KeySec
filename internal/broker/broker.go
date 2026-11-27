// Package broker performs the operations that use secret values: running a
// command, sending an HTTP request and pushing to a provider. The CLI and the
// MCP server are thin layers over it, so policy is enforced in one place.
package broker

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/sakethsripada/keysec/internal/push"
	"github.com/sakethsripada/keysec/internal/redact"
	"github.com/sakethsripada/keysec/internal/request"
	"github.com/sakethsripada/keysec/internal/runner"
	"github.com/sakethsripada/keysec/internal/store"
)

// Broker uses secrets from a store.
type Broker struct {
	Store *store.Store
	HTTP  request.Client
}

// Run runs cmd with the named secrets in its environment. Output is redacted
// for every stored secret, not just the injected ones.
func (b *Broker) Run(ctx context.Context, names []string, cmd runner.Command) (int, error) {
	values, err := b.Store.Values()
	if err != nil {
		return 0, err
	}
	env := map[string]string{}
	for _, name := range names {
		sec, err := b.Store.Get(name)
		if err != nil {
			return 0, err
		}
		if !sec.AllowRun {
			return 0, fmt.Errorf("%s may only be used through HTTP requests (allow_run is off)", name)
		}
		env[sec.EnvName()] = values[name]
	}
	if cmd.Env == nil {
		cmd.Env = map[string]string{}
	}
	for k, v := range env {
		cmd.Env[k] = v
	}
	cmd.Redactor = redact.New(values)
	return runner.Run(ctx, cmd)
}

// Request sends an HTTP request with the named secret attached.
func (b *Broker) Request(ctx context.Context, name string, req request.Request) (request.Response, error) {
	sec, err := b.Store.Get(name)
	if err != nil {
		return request.Response{}, err
	}
	value, err := b.Store.Value(name)
	if err != nil {
		return request.Response{}, err
	}
	cred := request.Credential{Name: name, Value: value, Hosts: sec.Hosts, Auth: sec.Auth}
	return b.HTTP.Do(ctx, cred, req)
}

// Push copies the named secret to a provider. If o.Name is empty the
// secret's environment variable name is used.
func (b *Broker) Push(ctx context.Context, name, target string, o push.Options, stdout, stderr io.Writer) (int, error) {
	sec, err := b.Store.Get(name)
	if err != nil {
		return 0, err
	}
	value, err := b.Store.Value(name)
	if err != nil {
		return 0, err
	}
	if o.Name == "" {
		o.Name = sec.EnvName()
	}
	o.Value = value
	inv, err := push.Build(target, o)
	if err != nil {
		return 0, err
	}
	return runner.Run(ctx, runner.Command{
		Args:     inv.Args,
		Stdin:    strings.NewReader(inv.Stdin),
		Stdout:   stdout,
		Stderr:   stderr,
		Redactor: redact.New(map[string]string{name: value}),
	})
}
