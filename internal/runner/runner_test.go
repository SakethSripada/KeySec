package runner

import (
	"bytes"
	"context"
	"testing"

	"github.com/sakethsripada/keysec/internal/redact"
)

func TestRunInjectsAndRedacts(t *testing.T) {
	var out bytes.Buffer
	code, err := Run(context.Background(), Command{
		Args:     []string{"sh", "-c", `echo "token is $API_TOKEN"; echo "$API_TOKEN" >&2; exit 3`},
		Env:      map[string]string{"API_TOKEN": "tok_abcdef123456"},
		Stdout:   &out,
		Stderr:   &out,
		Redactor: redact.New(map[string]string{"API_TOKEN": "tok_abcdef123456"}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if code != 3 {
		t.Errorf("exit code = %d, want 3", code)
	}
	if bytes.Contains(out.Bytes(), []byte("tok_abcdef123456")) {
		t.Fatalf("value leaked: %q", out.String())
	}
	if !bytes.Contains(out.Bytes(), []byte("token is [keysec:API_TOKEN]")) {
		t.Fatalf("unexpected output: %q", out.String())
	}
}

func TestRunMissingBinary(t *testing.T) {
	if _, err := Run(context.Background(), Command{Args: []string{"keysec-no-such-binary"}}); err == nil {
		t.Fatal("expected an error")
	}
}

func TestRunNoArgs(t *testing.T) {
	if _, err := Run(context.Background(), Command{}); err == nil {
		t.Fatal("expected an error")
	}
}
