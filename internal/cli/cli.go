// Package cli implements the keysec command line.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/sakethsripada/keysec/internal/broker"
	"github.com/sakethsripada/keysec/internal/store"
)

type command struct {
	name    string
	args    string
	summary string
	run     func(a *app, args []string) error
}

var commands []command

func init() {
	commands = []command{
		{"add", "NAME [flags]", "Store a secret (value read from a hidden prompt or stdin)", (*app).add},
		{"import", "FILE [--delete]", "Store every value in a .env file", (*app).importEnv},
		{"list", "[--json]", "List secrets", (*app).list},
		{"show", "NAME [--json]", "Show a secret's metadata and policy", (*app).show},
		{"edit", "NAME [flags]", "Change a secret's description and other metadata", (*app).edit},
		{"policy", "NAME [flags]", "Show or change where a secret may be used", (*app).policy},
		{"rm", "NAME [--yes]", "Delete a secret", (*app).remove},
		{"run", "-s NAME... -- COMMAND", "Run a command with secrets in its environment", (*app).run},
		{"request", "NAME URL [flags]", "Send an HTTP request with a secret attached", (*app).request},
		{"push", "NAME TARGET [flags]", "Copy a secret to github, vercel, fly or cloudflare", (*app).push},
		{"init", "[--remove]", "Register keysec with Claude Code, Codex and Cursor", (*app).initAgents},
		{"mcp", "", "Run the MCP server on stdio (started by agents)", (*app).mcp},
		{"hook", "claude", "Run the Claude Code PreToolUse hook (started by Claude Code)", (*app).hook},
		{"version", "", "Print the version", (*app).printVersion},
	}
}

type app struct {
	stdin   io.Reader
	stdout  io.Writer
	stderr  io.Writer
	version string
	prompt  prompter
	broker  *broker.Broker
}

// exitCode carries a child process's exit status out of a command.
type exitCode int

func (e exitCode) Error() string { return fmt.Sprintf("exit status %d", int(e)) }

// Main runs the CLI and returns the process exit code.
func Main(args []string, version string) int {
	a := &app{
		stdin:   os.Stdin,
		stdout:  os.Stdout,
		stderr:  os.Stderr,
		version: version,
		prompt:  terminal{},
	}
	return a.main(args)
}

func (a *app) main(args []string) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		a.usage(a.stdout)
		return 0
	}
	for _, c := range commands {
		if c.name != args[0] {
			continue
		}
		err := c.run(a, args[1:])
		var code exitCode
		switch {
		case err == nil:
			return 0
		case errors.Is(err, flag.ErrHelp):
			return 0
		case errors.As(err, &code):
			return int(code)
		default:
			fmt.Fprintf(a.stderr, "keysec: %v\n", err)
			return 1
		}
	}
	fmt.Fprintf(a.stderr, "keysec: unknown command %q\n\n", args[0])
	a.usage(a.stderr)
	return 2
}

func (a *app) usage(w io.Writer) {
	fmt.Fprint(w, "keysec lets coding agents use your secrets without seeing them.\n\nUsage:\n")
	tw := tabwriter.NewWriter(w, 0, 0, 3, ' ', 0)
	for _, c := range commands {
		fmt.Fprintf(tw, "  keysec %s %s\t%s\n", c.name, c.args, c.summary)
	}
	tw.Flush()
	fmt.Fprint(w, "\nRun `keysec COMMAND -h` for a command's flags.\n")
}

// store returns the secret store, opening it on first use.
func (a *app) store() (*store.Store, error) {
	b, err := a.getBroker()
	if err != nil {
		return nil, err
	}
	return b.Store, nil
}

func (a *app) getBroker() (*broker.Broker, error) {
	if a.broker != nil {
		return a.broker, nil
	}
	path, err := store.DefaultPath()
	if err != nil {
		return nil, err
	}
	a.broker = &broker.Broker{Store: store.Open(path, store.SystemKeyring())}
	return a.broker, nil
}

// flags returns a FlagSet for a command that prints usage to stderr.
func (a *app) flags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	fs.Usage = func() {
		for _, c := range commands {
			if c.name == name {
				fmt.Fprintf(a.stderr, "Usage: keysec %s %s\n\n%s.\n", c.name, c.args, c.summary)
			}
		}
		var hasFlags bool
		fs.VisitAll(func(*flag.Flag) { hasFlags = true })
		if hasFlags {
			fmt.Fprintln(a.stderr, "\nFlags:")
			fs.PrintDefaults()
		}
	}
	return fs
}

// parse parses flags that may appear before, between or after positional
// arguments, and returns the positional ones.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return positional, nil
		}
		positional = append(positional, args[0])
		args = args[1:]
	}
}

// exactly returns an error unless n positional arguments were given.
func exactly(fs *flag.FlagSet, pos []string, n int) error {
	if len(pos) != n {
		fs.Usage()
		return fmt.Errorf("expected %d argument(s), got %d", n, len(pos))
	}
	return nil
}

// set reports which flags were given on the command line.
func set(fs *flag.FlagSet) map[string]bool {
	m := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { m[f.Name] = true })
	return m
}

// list is a repeatable string flag.
type list []string

func (l *list) String() string { return strings.Join(*l, ",") }

func (l *list) Set(v string) error {
	for _, part := range strings.Split(v, ",") {
		if part = strings.TrimSpace(part); part != "" {
			*l = append(*l, part)
		}
	}
	return nil
}
