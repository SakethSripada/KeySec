package broker

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sakethsripada/keysec/internal/runner"
	"github.com/sakethsripada/keysec/internal/store"
)

func newBroker(t *testing.T) *Broker {
	t.Helper()
	st := store.Open(filepath.Join(t.TempDir(), "secrets.toml"), store.MemoryKeyring{})
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(st.Put("RUNNABLE", "runnable-value-1", store.Meta{Env: "APP_TOKEN"}, store.Policy{AllowRun: true}))
	must(st.Put("HTTP_ONLY", "http-only-value-2", store.Meta{}, store.Policy{Hosts: []string{"api.example.com"}}))
	return &Broker{Store: st}
}

func TestRunUsesEnvNameAndRedactsAll(t *testing.T) {
	b := newBroker(t)
	var out bytes.Buffer
	code, err := b.Run(context.Background(), []string{"RUNNABLE"}, runner.Command{
		Args:   []string{"sh", "-c", `echo "$APP_TOKEN"; echo http-only-value-2`},
		Stdout: &out,
	})
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v", code, err)
	}
	want := "[keysec:RUNNABLE]\n[keysec:HTTP_ONLY]\n"
	if out.String() != want {
		t.Fatalf("got %q, want %q", out.String(), want)
	}
}

func TestRunRefusesHTTPOnlySecret(t *testing.T) {
	b := newBroker(t)
	_, err := b.Run(context.Background(), []string{"HTTP_ONLY"}, runner.Command{Args: []string{"true"}})
	if err == nil || !strings.Contains(err.Error(), "allow_run") {
		t.Fatalf("err = %v", err)
	}
}

func TestRunUnknownSecret(t *testing.T) {
	b := newBroker(t)
	if _, err := b.Run(context.Background(), []string{"NOPE"}, runner.Command{Args: []string{"true"}}); err == nil {
		t.Fatal("expected an error")
	}
}
