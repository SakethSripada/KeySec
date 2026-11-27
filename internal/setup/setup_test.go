package setup

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func parse(t *testing.T, s string) map[string]any {
	t.Helper()
	doc := map[string]any{}
	if err := json.Unmarshal([]byte(s), &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func dump(doc map[string]any) string {
	b, _ := json.Marshal(doc)
	return string(b)
}

func TestAddHookPreservesExisting(t *testing.T) {
	doc := parse(t, `{"model":"opus","hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"other"}]}]}}`)
	if !addHook(doc, "keysec hook claude") {
		t.Fatal("addHook reported no change")
	}
	if addHook(doc, "/usr/local/bin/keysec hook claude") {
		t.Fatal("second addHook changed the document")
	}
	entries := doc["hooks"].(map[string]any)["PreToolUse"].([]any)
	if len(entries) != 2 || doc["model"] != "opus" {
		t.Fatalf("unexpected document: %s", dump(doc))
	}
}

func TestRemoveHook(t *testing.T) {
	doc := parse(t, `{"hooks":{"PreToolUse":[
		{"matcher":"Bash","hooks":[{"type":"command","command":"other"},{"type":"command","command":"keysec hook claude"}]},
		{"matcher":"Bash|Read","hooks":[{"type":"command","command":"/opt/bin/keysec hook claude"}]}
	]}}`)
	if !removeHook(doc) {
		t.Fatal("removeHook reported no change")
	}
	want := `{"hooks":{"PreToolUse":[{"hooks":[{"command":"other","type":"command"}],"matcher":"Bash"}]}}`
	if got := dump(doc); got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	if removeHook(doc) {
		t.Fatal("second removeHook changed the document")
	}
}

func TestAddThenRemoveLeavesNoTrace(t *testing.T) {
	doc := parse(t, `{"model":"opus"}`)
	addHook(doc, "keysec hook claude")
	removeHook(doc)
	if got := dump(doc); got != `{"model":"opus"}` {
		t.Fatalf("got %s", got)
	}
}

func TestWriteJSONKeepsMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(path, map[string]any{"a": 1}); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v", info.Mode().Perm())
	}
	doc, err := readJSON(path)
	if err != nil || doc["a"] != float64(1) {
		t.Fatalf("doc=%v err=%v", doc, err)
	}
}
