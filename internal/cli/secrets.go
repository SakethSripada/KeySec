package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/sakethsripada/keysec/internal/detect"
	"github.com/sakethsripada/keysec/internal/store"
)

type metaFlags struct {
	description, provider, mode, env, expires string
	scopes                                    list
}

func (m *metaFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&m.description, "d", "", "description")
	fs.StringVar(&m.provider, "provider", "", "provider, e.g. stripe")
	fs.StringVar(&m.mode, "mode", "", "live or test")
	fs.StringVar(&m.env, "env", "", "environment variable name (default: the secret's name)")
	fs.StringVar(&m.expires, "expires", "", "expiry date, e.g. 2027-01-31")
	fs.Var(&m.scopes, "scope", "scope or permission, repeatable")
}

func (m *metaFlags) apply(meta *store.Meta, given map[string]bool) {
	if given["d"] {
		meta.Description = m.description
	}
	if given["provider"] {
		meta.Provider = m.provider
	}
	if given["mode"] {
		meta.Mode = m.mode
	}
	if given["env"] {
		meta.Env = m.env
	}
	if given["expires"] {
		meta.Expires = m.expires
	}
	if given["scope"] {
		meta.Scopes = m.scopes
	}
}

func (a *app) add(args []string) error {
	fs := a.flags("add")
	var m metaFlags
	m.register(fs)
	var hosts list
	fs.Var(&hosts, "host", "host the secret may be sent to, repeatable (\"*.example.com\" for subdomains)")
	auth := fs.String("auth", "", `how to attach it to requests: bearer, basic, header:NAME, query:PARAM or none`)
	noRun := fs.Bool("no-run", false, "only allow use through HTTP requests, never in a command's environment")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if err := exactly(fs, pos, 1); err != nil {
		return err
	}
	name := pos[0]
	if err := store.ValidateName(name); err != nil {
		return err
	}
	st, err := a.store()
	if err != nil {
		return err
	}
	exists, err := st.Exists(name)
	if err != nil {
		return err
	}
	if exists {
		ok, err := a.prompt.Confirm(fmt.Sprintf("%s already exists. Replace its value and policy?", name))
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("cancelled")
		}
	}

	value, err := a.readValue(name)
	if err != nil {
		return err
	}
	if value == "" {
		return errors.New("no value given")
	}

	given := set(fs)
	var meta store.Meta
	m.apply(&meta, given)
	policy := store.Policy{Hosts: hosts, Auth: *auth, AllowRun: !*noRun}
	fillFromGuess(value, &meta, &policy, given)

	if err := st.Put(name, value, meta, policy); err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "Saved %s", name)
	if meta.Description != "" {
		fmt.Fprintf(a.stdout, " (%s)", meta.Description)
	}
	fmt.Fprintf(a.stdout, ".\n%s\n", formatPolicy(policy))
	return nil
}

// fillFromGuess fills anything the user did not set from the value's format.
func fillFromGuess(value string, meta *store.Meta, policy *store.Policy, given map[string]bool) {
	g, ok := detect.Detect(value)
	if !ok {
		return
	}
	if !given["d"] {
		meta.Description = g.Description
	}
	if !given["provider"] {
		meta.Provider = g.Provider
	}
	if !given["mode"] {
		meta.Mode = g.Mode
	}
	if !given["host"] {
		policy.Hosts = g.Hosts
	}
	if !given["auth"] {
		policy.Auth = g.Auth
	}
}

func (a *app) readValue(name string) (string, error) {
	if a.stdinIsTerminal() {
		return a.prompt.Secret(fmt.Sprintf("Value for %s (input hidden): ", name))
	}
	b, err := io.ReadAll(io.LimitReader(a.stdin, 64<<10))
	return strings.TrimRight(string(b), "\r\n"), err
}

func (a *app) list(args []string) error {
	fs := a.flags("list")
	asJSON := fs.Bool("json", false, "print JSON")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	st, err := a.store()
	if err != nil {
		return err
	}
	secrets, err := st.List()
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(a.stdout, secrets)
	}
	if len(secrets) == 0 {
		fmt.Fprintln(a.stdout, "No secrets yet. Add one with `keysec add NAME` or `keysec import .env`.")
		return nil
	}
	tw := tabwriter.NewWriter(a.stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tPROVIDER\tMODE\tHOSTS\tDESCRIPTION")
	for _, s := range secrets {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", s.Name, dash(s.Provider), dash(s.Mode), dash(strings.Join(s.Hosts, ",")), s.Description)
	}
	return tw.Flush()
}

func (a *app) show(args []string) error {
	fs := a.flags("show")
	asJSON := fs.Bool("json", false, "print JSON")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if err := exactly(fs, pos, 1); err != nil {
		return err
	}
	st, err := a.store()
	if err != nil {
		return err
	}
	s, err := st.Get(pos[0])
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(a.stdout, s)
	}
	tw := tabwriter.NewWriter(a.stdout, 0, 0, 2, ' ', 0)
	row := func(k, v string) {
		if v != "" {
			fmt.Fprintf(tw, "%s\t%s\n", k, v)
		}
	}
	row("Name", s.Name)
	row("Description", s.Description)
	row("Provider", s.Provider)
	row("Mode", s.Mode)
	row("Scopes", strings.Join(s.Scopes, ", "))
	row("Env var", s.EnvName())
	row("Expires", s.Expires)
	row("Added", s.Added.Format("2006-01-02"))
	row("Allowed hosts", dash(strings.Join(s.Hosts, ", ")))
	row("Auth", dash(s.Auth))
	row("Run", map[bool]string{true: "allowed", false: "not allowed"}[s.AllowRun])
	return tw.Flush()
}

func (a *app) edit(args []string) error {
	fs := a.flags("edit")
	var m metaFlags
	m.register(fs)
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if err := exactly(fs, pos, 1); err != nil {
		return err
	}
	given := set(fs)
	if len(given) == 0 {
		fs.Usage()
		return errors.New("nothing to change")
	}
	st, err := a.store()
	if err != nil {
		return err
	}
	if err := st.UpdateMeta(pos[0], func(meta *store.Meta) { m.apply(meta, given) }); err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "Updated %s.\n", pos[0])
	return nil
}

func (a *app) policy(args []string) error {
	fs := a.flags("policy")
	var hosts list
	fs.Var(&hosts, "host", "allowed host, repeatable; replaces the current list")
	auth := fs.String("auth", "", "bearer, basic, header:NAME, query:PARAM or none")
	allowRun := fs.Bool("run", false, "allow use in a command's environment")
	noRun := fs.Bool("no-run", false, "only allow use through HTTP requests")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if err := exactly(fs, pos, 1); err != nil {
		return err
	}
	st, err := a.store()
	if err != nil {
		return err
	}
	s, err := st.Get(pos[0])
	if err != nil {
		return err
	}
	given := set(fs)
	if len(given) == 0 {
		fmt.Fprintln(a.stdout, formatPolicy(s.Policy))
		return nil
	}
	if given["run"] && given["no-run"] {
		return errors.New("use only one of --run and --no-run")
	}

	p := s.Policy
	if given["host"] {
		p.Hosts = hosts
	}
	if given["auth"] {
		p.Auth = *auth
	}
	if given["run"] {
		p.AllowRun = *allowRun
	}
	if given["no-run"] {
		p.AllowRun = !*noRun
	}

	fmt.Fprintf(a.stderr, "Current: %s\nNew:     %s\n", formatPolicy(s.Policy), formatPolicy(p))
	ok, err := a.prompt.Confirm("Apply?")
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("cancelled")
	}
	if err := st.SetPolicy(pos[0], p); err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "Updated policy for %s.\n", pos[0])
	return nil
}

func (a *app) remove(args []string) error {
	fs := a.flags("rm")
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if err := exactly(fs, pos, 1); err != nil {
		return err
	}
	st, err := a.store()
	if err != nil {
		return err
	}
	exists, err := st.Exists(pos[0])
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("%w: %s", store.ErrNotFound, pos[0])
	}
	if !*yes {
		ok, err := a.prompt.Confirm(fmt.Sprintf("Delete %s? This cannot be undone.", pos[0]))
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("cancelled")
		}
	}
	if err := st.Remove(pos[0]); err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "Deleted %s.\n", pos[0])
	return nil
}

func formatPolicy(p store.Policy) string {
	hosts := "none"
	if len(p.Hosts) > 0 {
		hosts = strings.Join(p.Hosts, ", ")
	}
	auth := p.Auth
	if auth == "" {
		auth = "bearer"
	}
	run := "allowed"
	if !p.AllowRun {
		run = "not allowed"
	}
	return fmt.Sprintf("hosts: %s; auth: %s; run: %s", hosts, auth, run)
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
