// Package push builds the provider CLI invocations that copy a secret into a
// hosting provider. The value is always passed on stdin, never as an argument.
package push

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Options describes where a secret goes.
type Options struct {
	Name        string // variable name at the destination
	Value       string
	Environment string // vercel: required; github and cloudflare: optional
	Repo        string // github: owner/repo
	App         string // fly: app name
}

// Invocation is a command to run and the data to write to its stdin.
type Invocation struct {
	Args  []string
	Stdin string
}

type target func(Options) (Invocation, error)

var targets = map[string]target{
	"github": func(o Options) (Invocation, error) {
		args := []string{"gh", "secret", "set", o.Name}
		if o.Repo != "" {
			args = append(args, "--repo", o.Repo)
		}
		if o.Environment != "" {
			args = append(args, "--env", o.Environment)
		}
		return Invocation{Args: args, Stdin: o.Value}, nil
	},
	"vercel": func(o Options) (Invocation, error) {
		if o.Environment == "" {
			return Invocation{}, errors.New("vercel needs an environment: production, preview or development")
		}
		return Invocation{Args: []string{"vercel", "env", "add", o.Name, o.Environment}, Stdin: o.Value}, nil
	},
	"fly": func(o Options) (Invocation, error) {
		if strings.ContainsAny(o.Value, "\r\n") {
			return Invocation{}, errors.New("fly secrets import does not accept multi-line values")
		}
		args := []string{"fly", "secrets", "import"}
		if o.App != "" {
			args = append(args, "--app", o.App)
		}
		return Invocation{Args: args, Stdin: o.Name + "=" + o.Value + "\n"}, nil
	},
	"cloudflare": func(o Options) (Invocation, error) {
		args := []string{"wrangler", "secret", "put", o.Name}
		if o.Environment != "" {
			args = append(args, "--env", o.Environment)
		}
		return Invocation{Args: args, Stdin: o.Value}, nil
	},
}

// Targets returns the supported target names.
func Targets() []string {
	names := make([]string, 0, len(targets))
	for name := range targets {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Build returns the invocation for a target.
func Build(targetName string, o Options) (Invocation, error) {
	t, ok := targets[targetName]
	if !ok {
		return Invocation{}, fmt.Errorf("unknown target %q (supported: %s)", targetName, strings.Join(Targets(), ", "))
	}
	return t(o)
}
