package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"slices"
	"strings"

	"github.com/sakethsripada/keysec/internal/push"
	"github.com/sakethsripada/keysec/internal/request"
	"github.com/sakethsripada/keysec/internal/runner"
)

func (a *app) run(args []string) error {
	fs := a.flags("run")
	var names list
	fs.Var(&names, "s", "secret to inject, repeatable")
	all := fs.Bool("all", false, "inject every secret that allows it")

	// Everything after "--" is the command, untouched by flag parsing.
	i := slices.Index(args, "--")
	if i < 0 {
		fs.Usage()
		return errors.New("missing -- before the command")
	}
	cmdArgs := args[i+1:]
	if _, err := parse(fs, args[:i]); err != nil {
		return err
	}
	if len(cmdArgs) == 0 {
		return errors.New("no command given after --")
	}

	b, err := a.getBroker()
	if err != nil {
		return err
	}
	if *all {
		secrets, err := b.Store.List()
		if err != nil {
			return err
		}
		for _, s := range secrets {
			if s.AllowRun && !slices.Contains(names, s.Name) {
				names = append(names, s.Name)
			}
		}
	}
	if len(names) == 0 {
		return errors.New("no secrets selected; pass -s NAME or --all")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	code, err := b.Run(ctx, names, runner.Command{
		Args:   cmdArgs,
		Stdin:  a.stdin,
		Stdout: a.stdout,
		Stderr: a.stderr,
	})
	if err != nil {
		return err
	}
	if code != 0 {
		return exitCode(code)
	}
	return nil
}

func (a *app) request(args []string) error {
	fs := a.flags("request")
	method := fs.String("X", "GET", "HTTP method")
	var headers list
	fs.Var(&headers, "H", `header "Name: value", repeatable`)
	body := fs.String("d", "", "request body")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if err := exactly(fs, pos, 2); err != nil {
		return err
	}
	hdrs := map[string]string{}
	for _, h := range headers {
		k, v, ok := strings.Cut(h, ":")
		if !ok {
			return fmt.Errorf("invalid header %q, expected \"Name: value\"", h)
		}
		hdrs[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}

	b, err := a.getBroker()
	if err != nil {
		return err
	}
	resp, err := b.Request(context.Background(), pos[0], request.Request{
		Method:  *method,
		URL:     pos[1],
		Headers: hdrs,
		Body:    *body,
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(a.stderr, "HTTP %d\n", resp.Status)
	fmt.Fprint(a.stdout, resp.Body)
	if resp.Truncated {
		fmt.Fprintln(a.stderr, "(response truncated)")
	}
	if resp.Status >= 400 {
		return exitCode(1)
	}
	return nil
}

func (a *app) push(args []string) error {
	fs := a.flags("push")
	var o push.Options
	fs.StringVar(&o.Name, "as", "", "variable name at the destination (default: the secret's env var)")
	fs.StringVar(&o.Environment, "env", "", "vercel: production, preview or development; github, cloudflare: environment name")
	fs.StringVar(&o.Repo, "repo", "", "github: owner/repo")
	fs.StringVar(&o.App, "app", "", "fly: app name")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if err := exactly(fs, pos, 2); err != nil {
		return err
	}
	b, err := a.getBroker()
	if err != nil {
		return err
	}
	code, err := b.Push(context.Background(), pos[0], pos[1], o, a.stdout, a.stderr)
	if err != nil {
		return err
	}
	if code != 0 {
		return exitCode(code)
	}
	return nil
}
