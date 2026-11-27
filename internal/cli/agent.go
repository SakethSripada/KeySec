package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sakethsripada/keysec/internal/hook"
	"github.com/sakethsripada/keysec/internal/mcpserver"
	"github.com/sakethsripada/keysec/internal/setup"
)

func (a *app) initAgents(args []string) error {
	fs := a.flags("init")
	remove := fs.Bool("remove", false, "unregister keysec instead")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	exe, err := setup.Executable()
	if err != nil {
		return err
	}

	found, failed := 0, 0
	for _, agent := range setup.Agents() {
		if !agent.Detected() {
			fmt.Fprintf(a.stdout, "%s: not installed\n", agent.Name)
			continue
		}
		found++
		var changes []string
		if *remove {
			changes, err = agent.Remove()
		} else {
			changes, err = agent.Install(exe)
		}
		for _, c := range changes {
			fmt.Fprintf(a.stdout, "%s: %s\n", agent.Name, c)
		}
		switch {
		case err != nil:
			fmt.Fprintf(a.stderr, "%s: %v\n", agent.Name, err)
			failed++
		case len(changes) == 0 && *remove:
			fmt.Fprintf(a.stdout, "%s: nothing to remove\n", agent.Name)
		case len(changes) == 0:
			fmt.Fprintf(a.stdout, "%s: already set up\n", agent.Name)
		}
	}

	if found == 0 {
		return errors.New("no supported agents found (Claude Code, Codex, Cursor)")
	}
	if failed > 0 {
		return fmt.Errorf("%d agent(s) failed", failed)
	}
	if !*remove {
		fmt.Fprintln(a.stdout, "\nRestart running agents to pick up the change. Add secrets with `keysec add NAME` or `keysec import .env`.")
	}
	return nil
}

func (a *app) mcp(args []string) error {
	if _, err := parse(a.flags("mcp"), args); err != nil {
		return err
	}
	b, err := a.getBroker()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return mcpserver.New(b, a.version).Run(ctx, &mcp.StdioTransport{})
}

func (a *app) hook(args []string) error {
	fs := a.flags("hook")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 || pos[0] != "claude" {
		fs.Usage()
		return errors.New(`the only supported hook is "claude"`)
	}
	return hook.Run(a.stdin, a.stdout)
}

func (a *app) printVersion([]string) error {
	fmt.Fprintf(a.stdout, "keysec %s\n", a.version)
	return nil
}
