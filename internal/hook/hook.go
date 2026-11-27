// Package hook implements a Claude Code PreToolUse hook that stops the agent
// from reading secret material directly and points it to keysec instead.
//
// It is a guardrail against accidental reads, not a sandbox. Shell commands
// are matched with simple heuristics and a determined agent can get around
// them. See SECURITY.md.
package hook

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"
)

// Input is the part of the hook payload keysec inspects.
type Input struct {
	ToolName  string `json:"tool_name"`
	ToolInput struct {
		Command  string `json:"command"`
		FilePath string `json:"file_path"`
		Path     string `json:"path"`
	} `json:"tool_input"`
}

type output struct {
	HookSpecificOutput struct {
		HookEventName            string `json:"hookEventName"`
		PermissionDecision       string `json:"permissionDecision"`
		PermissionDecisionReason string `json:"permissionDecisionReason"`
	} `json:"hookSpecificOutput"`
}

const advice = "Secrets are managed by keysec. Use the keysec MCP tools (list_secrets, http_request, run_command) " +
	"or `keysec run -s NAME -- <command>` instead of reading them directly."

// Run reads a hook payload from r and writes a deny decision to w when the
// tool call should be blocked. Writing nothing lets the call proceed.
func Run(r io.Reader, w io.Writer) error {
	var in Input
	if err := json.NewDecoder(r).Decode(&in); err != nil {
		return fmt.Errorf("reading hook input: %w", err)
	}
	reason, deny := Check(in)
	if !deny {
		return nil
	}
	var out output
	out.HookSpecificOutput.HookEventName = "PreToolUse"
	out.HookSpecificOutput.PermissionDecision = "deny"
	out.HookSpecificOutput.PermissionDecisionReason = reason + " " + advice
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(out)
}

// Check returns a reason and true if the tool call should be blocked.
func Check(in Input) (string, bool) {
	switch in.ToolName {
	case "Read", "Edit", "Write", "NotebookEdit":
		if IsEnvFile(in.ToolInput.FilePath) {
			return fmt.Sprintf("Blocked access to %s.", in.ToolInput.FilePath), true
		}
	case "Grep":
		if IsEnvFile(in.ToolInput.Path) {
			return fmt.Sprintf("Blocked search in %s.", in.ToolInput.Path), true
		}
	case "Bash":
		return checkCommand(in.ToolInput.Command)
	}
	return "", false
}

// IsEnvFile reports whether path names a dotenv file that may hold real
// values. Templates such as .env.example are allowed.
func IsEnvFile(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	if base != ".env" && !strings.HasPrefix(base, ".env.") && !strings.HasSuffix(base, ".env") {
		return false
	}
	for _, suffix := range []string{".example", ".sample", ".template", ".dist", ".defaults"} {
		if strings.HasSuffix(base, suffix) {
			return false
		}
	}
	return true
}

var (
	keychainRead = regexp.MustCompile(`\bsecurity\s+(find-generic-password|find-internet-password|dump-keychain)\b|\bsecret-tool\s+(lookup|search)\b|\bcmdkey\s+/list\b`)
	envDump      = regexp.MustCompile(`(^|[;&|(]\s*)(env|printenv|export\s+-p|set)\s*($|[;&|)])`)
)

// readers are commands that print or interpret a file's contents.
var readers = map[string]bool{
	"cat": true, "less": true, "more": true, "head": true, "tail": true, "bat": true,
	"grep": true, "rg": true, "ag": true, "awk": true, "sed": true, "cut": true,
	"sort": true, "uniq": true, "nl": true, "strings": true, "xxd": true, "od": true,
	"hexdump": true, "base64": true, "source": true, ".": true, "jq": true, "tac": true,
	"diff": true, "curl": true, "nc": true, "python": true,
	"python3": true, "node": true, "ruby": true, "perl": true, "dotenv": true,
}

func checkCommand(cmd string) (string, bool) {
	if keychainRead.MatchString(cmd) {
		return "Blocked a command that reads the system keychain.", true
	}
	if envDump.MatchString(cmd) {
		return "Blocked a command that prints the whole environment.", true
	}
	words := strings.FieldsFunc(cmd, func(r rune) bool {
		return strings.ContainsRune(" \t\n;|&()<>`'\"$", r)
	})
	hasReader, envFile := false, ""
	for _, w := range words {
		if readers[filepath.Base(w)] {
			hasReader = true
		}
		if IsEnvFile(w) {
			envFile = w
		}
	}
	if envFile != "" && (hasReader || strings.Contains(cmd, "<")) {
		return fmt.Sprintf("Blocked a command that reads %s.", envFile), true
	}
	return "", false
}
