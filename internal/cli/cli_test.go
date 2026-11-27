package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sakethsripada/keysec/internal/broker"
	"github.com/sakethsripada/keysec/internal/store"
)

// fakePrompt answers confirmations with a fixed reply, or fails like a
// process without a terminal when noTTY is set.
type fakePrompt struct {
	answer bool
	noTTY  bool
}

func (f fakePrompt) Confirm(string) (bool, error) {
	if f.noTTY {
		return false, errNoTerminal
	}
	return f.answer, nil
}

func (f fakePrompt) Secret(string) (string, error) { return "", errNoTerminal }

type harness struct {
	app    *app
	store  *store.Store
	out    *bytes.Buffer
	errOut *bytes.Buffer
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	st := store.Open(filepath.Join(t.TempDir(), "secrets.toml"), store.MemoryKeyring{})
	h := &harness{store: st, out: &bytes.Buffer{}, errOut: &bytes.Buffer{}}
	h.app = &app{
		stdin:   strings.NewReader(""),
		stdout:  h.out,
		stderr:  h.errOut,
		version: "test",
		prompt:  fakePrompt{noTTY: true},
		broker:  &broker.Broker{Store: st},
	}
	return h
}

func (h *harness) run(stdin string, args ...string) int {
	h.out.Reset()
	h.errOut.Reset()
	h.app.stdin = strings.NewReader(stdin)
	return h.app.main(args)
}

func TestAddDetectsAndList(t *testing.T) {
	h := newHarness(t)
	if code := h.run("sk_live_abcdefghijkl\n", "add", "STRIPE_KEY"); code != 0 {
		t.Fatalf("add failed: %s", h.errOut)
	}
	if !strings.Contains(h.out.String(), "Stripe secret key") {
		t.Errorf("add output: %s", h.out)
	}
	if v, _ := h.store.Value("STRIPE_KEY"); v != "sk_live_abcdefghijkl" {
		t.Errorf("stored value = %q", v)
	}

	h.run("", "list")
	if !strings.Contains(h.out.String(), "api.stripe.com") || strings.Contains(h.out.String(), "sk_live_") {
		t.Errorf("list output: %s", h.out)
	}
}

func TestAddFlagsOverrideDetection(t *testing.T) {
	h := newHarness(t)
	code := h.run("sk_live_abcdefghijkl", "add", "K", "--host", "proxy.internal", "-d", "custom", "--no-run")
	if code != 0 {
		t.Fatalf("add failed: %s", h.errOut)
	}
	s, _ := h.store.Get("K")
	if s.Description != "custom" || s.Hosts[0] != "proxy.internal" || s.AllowRun {
		t.Fatalf("got %+v", s)
	}
}

func TestReplacingNeedsTerminal(t *testing.T) {
	h := newHarness(t)
	h.run("first-value", "add", "K")
	if code := h.run("second-value", "add", "K"); code == 0 {
		t.Fatal("replaced a secret without a terminal")
	}
	if v, _ := h.store.Value("K"); v != "first-value" {
		t.Fatalf("value changed to %q", v)
	}

	h.app.prompt = fakePrompt{answer: true}
	if code := h.run("second-value", "add", "K"); code != 0 {
		t.Fatalf("replace with confirmation failed: %s", h.errOut)
	}
}

func TestPolicyChangeNeedsTerminal(t *testing.T) {
	h := newHarness(t)
	h.run("value-123456", "add", "K", "--host", "good.com")
	if code := h.run("", "policy", "K", "--host", "evil.com"); code == 0 {
		t.Fatal("policy changed without a terminal")
	}
	s, _ := h.store.Get("K")
	if s.Hosts[0] != "good.com" {
		t.Fatalf("hosts = %v", s.Hosts)
	}

	h.app.prompt = fakePrompt{answer: true}
	if code := h.run("", "policy", "K", "--host", "api.good.com", "--no-run"); code != 0 {
		t.Fatalf("policy failed: %s", h.errOut)
	}
	s, _ = h.store.Get("K")
	if s.Hosts[0] != "api.good.com" || s.AllowRun {
		t.Fatalf("got %+v", s.Policy)
	}
}

func TestEditDoesNotNeedTerminal(t *testing.T) {
	h := newHarness(t)
	h.run("value-123456", "add", "K")
	if code := h.run("", "edit", "K", "-d", "described", "--scope", "read,write"); code != 0 {
		t.Fatalf("edit failed: %s", h.errOut)
	}
	s, _ := h.store.Get("K")
	if s.Description != "described" || len(s.Scopes) != 2 {
		t.Fatalf("got %+v", s.Meta)
	}
}

func TestRunRedactsAndPropagatesExitCode(t *testing.T) {
	h := newHarness(t)
	h.run("tok_abcdef123456", "add", "TOKEN")
	code := h.run("", "run", "-s", "TOKEN", "--", "sh", "-c", `echo "$TOKEN"; exit 7`)
	if code != 7 {
		t.Errorf("exit code = %d, want 7 (stderr: %s)", code, h.errOut)
	}
	if strings.TrimSpace(h.out.String()) != "[keysec:TOKEN]" {
		t.Errorf("output = %q", h.out)
	}
}

func TestRunRequiresSeparator(t *testing.T) {
	h := newHarness(t)
	if code := h.run("", "run", "-s", "X", "echo"); code == 0 {
		t.Fatal("expected failure without --")
	}
}

func TestImport(t *testing.T) {
	h := newHarness(t)
	path := filepath.Join(t.TempDir(), ".env")
	os.WriteFile(path, []byte("OPENAI_API_KEY=sk-proj-abcdef123\nEMPTY=\nbad-name=x\n"), 0o600)

	if code := h.run("", "import", path, "--delete"); code == 0 {
		t.Fatal("deleted the file although entries were skipped")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("file was deleted")
	}
	s, err := h.store.Get("OPENAI_API_KEY")
	if err != nil || s.Provider != "openai" {
		t.Fatalf("secret = %+v, err = %v", s, err)
	}
}

func TestRemove(t *testing.T) {
	h := newHarness(t)
	h.run("value-123456", "add", "K")
	if code := h.run("", "rm", "K"); code == 0 {
		t.Fatal("removed without confirmation")
	}
	if code := h.run("", "rm", "K", "--yes"); code != 0 {
		t.Fatalf("rm --yes failed: %s", h.errOut)
	}
	if code := h.run("", "rm", "K", "--yes"); code == 0 {
		t.Fatal("removing a missing secret succeeded")
	}
}

func TestShowNeverPrintsValue(t *testing.T) {
	h := newHarness(t)
	h.run("sk_test_abcdefghijkl", "add", "K")
	for _, args := range [][]string{{"show", "K"}, {"show", "K", "--json"}, {"list", "--json"}} {
		h.run("", args...)
		if strings.Contains(h.out.String(), "sk_test_abcdefghijkl") {
			t.Errorf("%v printed the value", args)
		}
	}
}

func TestUnknownCommand(t *testing.T) {
	h := newHarness(t)
	if code := h.run("", "frobnicate"); code != 2 {
		t.Fatalf("code = %d", code)
	}
}
