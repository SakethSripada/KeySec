// Package runner executes a command with secrets in its environment and
// redacts their values from its output.
package runner

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"

	"github.com/sakethsripada/keysec/internal/redact"
)

// Command describes a process to run.
type Command struct {
	Args   []string
	Dir    string
	Env    map[string]string // added to the current environment
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	// Redactor is applied to Stdout and Stderr. Nil disables redaction.
	Redactor *redact.Redactor
}

// Run starts the command and waits for it. It returns the exit code. A
// non-zero exit is not an error; failing to start the process is.
func Run(ctx context.Context, c Command) (int, error) {
	if len(c.Args) == 0 {
		return 0, errors.New("no command given")
	}
	cmd := exec.CommandContext(ctx, c.Args[0], c.Args[1:]...)
	cmd.Dir = c.Dir
	cmd.Stdin = c.Stdin
	cmd.Env = os.Environ()
	for k, v := range c.Env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}

	stdout := redact.NewWriter(c.Redactor, orDiscard(c.Stdout))
	stderr := redact.NewWriter(c.Redactor, orDiscard(c.Stderr))
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	err := cmd.Run()
	flushErr := errors.Join(stdout.Close(), stderr.Close())

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), flushErr
	}
	if err != nil {
		return 0, err
	}
	return 0, flushErr
}

func orDiscard(w io.Writer) io.Writer {
	if w == nil {
		return io.Discard
	}
	return w
}
