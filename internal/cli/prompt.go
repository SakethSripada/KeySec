package cli

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// prompter asks the person at the terminal. It reads from the controlling
// terminal rather than stdin, so a process without one (such as an agent's
// shell) cannot answer.
type prompter interface {
	Confirm(question string) (bool, error)
	Secret(label string) (string, error)
}

var errNoTerminal = errors.New("this needs confirmation from a terminal; run the command yourself")

type terminal struct{}

func (terminal) Confirm(question string) (bool, error) {
	in, out, err := openTTY()
	if err != nil {
		return false, errNoTerminal
	}
	defer closeTTY(in, out)
	fmt.Fprintf(out, "%s [y/N] ", question)
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil {
		return false, err
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes", nil
}

func (terminal) Secret(label string) (string, error) {
	in, out, err := openTTY()
	if err != nil {
		return "", errNoTerminal
	}
	defer closeTTY(in, out)
	fmt.Fprint(out, label)
	b, err := term.ReadPassword(int(in.Fd()))
	fmt.Fprintln(out)
	return string(b), err
}

func closeTTY(in, out *os.File) {
	in.Close()
	if out != in {
		out.Close()
	}
}

// stdinIsTerminal reports whether stdin is an interactive terminal.
func (a *app) stdinIsTerminal() bool {
	f, ok := a.stdin.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}
