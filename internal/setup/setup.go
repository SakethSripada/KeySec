// Package setup registers keysec with coding agents installed on this machine.
package setup

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Agent is a coding agent keysec can register with.
type Agent struct {
	Name string
	// Detected reports whether the agent is installed.
	Detected func() bool
	// Install registers keysec and returns a description of each change.
	Install func(exe string) ([]string, error)
	// Remove undoes Install.
	Remove func() ([]string, error)
}

// Agents returns every supported agent.
func Agents() []Agent {
	return []Agent{claudeCode(), codex(), cursor()}
}

// Executable returns how agents should invoke keysec: "keysec" when that
// resolves to the running binary, otherwise its absolute path.
func Executable() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	if onPath, err := exec.LookPath("keysec"); err == nil && sameFile(self, onPath) {
		return "keysec", nil
	}
	return self, nil
}

func sameFile(a, b string) bool {
	ai, err1 := os.Stat(a)
	bi, err2 := os.Stat(b)
	return err1 == nil && err2 == nil && os.SameFile(ai, bi)
}

func onPath(bin string) func() bool {
	return func() bool {
		_, err := exec.LookPath(bin)
		return err == nil
	}
}

func homeDir(parts ...string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(append([]string{home}, parts...)...)
}

// run executes a command and includes its output in any error.
func run(name string, args ...string) error {
	var out bytes.Buffer
	cmd := exec.Command(name, args...)
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(out.String()))
	}
	return nil
}

// succeeds reports whether a command exits zero.
func succeeds(name string, args ...string) bool {
	return exec.Command(name, args...).Run() == nil
}

func readJSON(path string) (map[string]any, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]any{}, nil
	}
	if err != nil {
		return nil, err
	}
	doc := map[string]any{}
	if len(bytes.TrimSpace(data)) == 0 {
		return doc, nil
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return doc, nil
}

func writeJSON(path string, doc map[string]any) error {
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	mode := os.FileMode(0o644)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	tmp := path + ".keysec-tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// object returns doc[key] as a JSON object, creating it if needed.
func object(doc map[string]any, key string) map[string]any {
	if m, ok := doc[key].(map[string]any); ok {
		return m
	}
	m := map[string]any{}
	doc[key] = m
	return m
}
