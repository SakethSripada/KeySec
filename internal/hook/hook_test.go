package hook

import (
	"bytes"
	"strings"
	"testing"
)

func bash(cmd string) Input {
	var in Input
	in.ToolName = "Bash"
	in.ToolInput.Command = cmd
	return in
}

func TestBashCommands(t *testing.T) {
	blocked := []string{
		"cat .env",
		"cat ./apps/web/.env.local",
		"grep STRIPE .env",
		"source .env && echo $STRIPE",
		". .env.production",
		"python3 script.py < .env",
		"security find-generic-password -s keysec -w",
		"security dump-keychain",
		"secret-tool lookup service keysec",
		"env",
		"printenv",
		"ls && env | grep KEY",
		"export -p",
		"/bin/cat .env",
	}
	allowed := []string{
		"ls -la",
		"npm test",
		"cat .env.example",
		"cp .env.example .env",
		"rm .env",
		"touch .env",
		"git status",
		"env FOO=bar npm test",
		"printenv HOME",
		"echo environment",
		"keysec run -s STRIPE -- npm test",
	}
	for _, c := range blocked {
		if _, deny := Check(bash(c)); !deny {
			t.Errorf("not blocked: %q", c)
		}
	}
	for _, c := range allowed {
		if reason, deny := Check(bash(c)); deny {
			t.Errorf("blocked %q: %s", c, reason)
		}
	}
}

func TestFileTools(t *testing.T) {
	var in Input
	in.ToolName = "Read"
	in.ToolInput.FilePath = "/repo/.env.local"
	if _, deny := Check(in); !deny {
		t.Error("Read of .env.local allowed")
	}
	in.ToolInput.FilePath = "/repo/.env.example"
	if _, deny := Check(in); deny {
		t.Error("Read of .env.example blocked")
	}
	in.ToolName = "Grep"
	in.ToolInput.FilePath = ""
	in.ToolInput.Path = "/repo/.env"
	if _, deny := Check(in); !deny {
		t.Error("Grep in .env allowed")
	}
}

func TestIsEnvFile(t *testing.T) {
	yes := []string{".env", ".env.local", "/a/b/.env.production", "prod.env", ".ENV"}
	no := []string{"env", ".envrc", "environment.ts", ".env.example", ".env.sample", "config.env.template"}
	for _, p := range yes {
		if !IsEnvFile(p) {
			t.Errorf("IsEnvFile(%q) = false", p)
		}
	}
	for _, p := range no {
		if IsEnvFile(p) {
			t.Errorf("IsEnvFile(%q) = true", p)
		}
	}
}

func TestRunOutput(t *testing.T) {
	var out bytes.Buffer
	if err := Run(strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"cat .env"}}`), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"permissionDecision":"deny"`) {
		t.Fatalf("got %s", out.String())
	}

	out.Reset()
	if err := Run(strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"ls"}}`), &out); err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 {
		t.Fatalf("allowed call produced output: %s", out.String())
	}
}
