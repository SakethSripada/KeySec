package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeEnv(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReimportAppliesChanges(t *testing.T) {
	h := newHarness(t)
	env := filepath.Join(t.TempDir(), ".env")
	writeEnv(t, env, "STRIPE_KEY=sk_test_aaaaaaaaaaaa\nOLD_TOKEN=old-value-123\n")
	if code := h.run("", "import", env); code != 0 {
		t.Fatalf("first import failed: %s", h.errOut)
	}

	// The user tightens the policy, then the file changes.
	h.app.prompt = fakePrompt{answer: true}
	h.run("", "policy", "STRIPE_KEY", "--no-run")
	writeEnv(t, env, "STRIPE_KEY=sk_live_bbbbbbbbbbbb\nNEW_TOKEN=new-value-456\n")

	if code := h.run("", "import", env); code != 0 {
		t.Fatalf("reimport failed: %s", h.errOut)
	}
	out := h.out.String()
	for _, want := range []string{"update  STRIPE_KEY", "add     NEW_TOKEN", "keep    OLD_TOKEN", "1 added, 1 updated, 0 unchanged."} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}

	s, _ := h.store.Get("STRIPE_KEY")
	if v, _ := h.store.Value("STRIPE_KEY"); v != "sk_live_bbbbbbbbbbbb" {
		t.Errorf("value = %q", v)
	}
	if s.Mode != "live" || s.AllowRun {
		t.Errorf("mode=%q allow_run=%v; want live and the user's policy kept", s.Mode, s.AllowRun)
	}
	if ok, _ := h.store.Exists("OLD_TOKEN"); !ok {
		t.Error("OLD_TOKEN removed without --prune")
	}

	if code := h.run("", "import", env, "--prune"); code != 0 {
		t.Fatalf("prune failed: %s", h.errOut)
	}
	if ok, _ := h.store.Exists("OLD_TOKEN"); ok {
		t.Error("OLD_TOKEN not removed with --prune")
	}
}

func TestReimportWithoutTerminalChangesNothing(t *testing.T) {
	h := newHarness(t)
	env := filepath.Join(t.TempDir(), ".env")
	writeEnv(t, env, "TOKEN=first-value-1\n")
	h.run("", "import", env)

	writeEnv(t, env, "TOKEN=second-value-2\nEXTRA=extra-value-3\n")
	if code := h.run("", "import", env); code == 0 {
		t.Fatal("reimport changed a value without a terminal")
	}
	if v, _ := h.store.Value("TOKEN"); v != "first-value-1" {
		t.Errorf("value changed to %q", v)
	}
	if ok, _ := h.store.Exists("EXTRA"); ok {
		t.Error("a refused import still added secrets")
	}
}

func TestReimportUnchangedNeedsNoTerminal(t *testing.T) {
	h := newHarness(t)
	env := filepath.Join(t.TempDir(), ".env")
	writeEnv(t, env, "TOKEN=first-value-1\n")
	h.run("", "import", env)
	if code := h.run("", "import", env); code != 0 {
		t.Fatalf("reimporting an unchanged file failed: %s", h.errOut)
	}
	if !strings.Contains(h.out.String(), "0 added, 0 updated, 1 unchanged.") {
		t.Errorf("output: %s", h.out)
	}
}

func TestImportDryRun(t *testing.T) {
	h := newHarness(t)
	env := filepath.Join(t.TempDir(), ".env")
	writeEnv(t, env, "TOKEN=first-value-1\n")
	if code := h.run("", "import", env, "--dry-run"); code != 0 {
		t.Fatalf("dry run failed: %s", h.errOut)
	}
	if !strings.Contains(h.out.String(), "add  TOKEN") {
		t.Errorf("output: %s", h.out)
	}
	if ok, _ := h.store.Exists("TOKEN"); ok {
		t.Error("dry run stored a secret")
	}
}

func TestImportRecordsSource(t *testing.T) {
	h := newHarness(t)
	env := filepath.Join(t.TempDir(), ".env")
	writeEnv(t, env, "TOKEN=first-value-1\n")
	h.run("", "import", env)
	s, _ := h.store.Get("TOKEN")
	if s.Source != env {
		t.Errorf("source = %q, want %q", s.Source, env)
	}
}
