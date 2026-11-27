package setup

import (
	"os"
	"path/filepath"
	"strings"
)

// hookMatcher lists the Claude Code tools the hook inspects.
const hookMatcher = "Bash|Read|Edit|Write|Grep"

func claudeCode() Agent {
	return Agent{
		Name:     "Claude Code",
		Detected: onPath("claude"),
		Install: func(exe string) ([]string, error) {
			var changes []string
			if !succeeds("claude", "mcp", "get", "keysec") {
				if err := run("claude", "mcp", "add", "--scope", "user", "keysec", "--", exe, "mcp"); err != nil {
					return changes, err
				}
				changes = append(changes, "added MCP server (user scope)")
			}
			path := claudeSettingsPath()
			doc, err := readJSON(path)
			if err != nil {
				return changes, err
			}
			if addHook(doc, exe+" hook claude") {
				if err := writeJSON(path, doc); err != nil {
					return changes, err
				}
				changes = append(changes, "added PreToolUse hook to "+path)
			}
			return changes, nil
		},
		Remove: func() ([]string, error) {
			var changes []string
			if succeeds("claude", "mcp", "get", "keysec") {
				if err := run("claude", "mcp", "remove", "--scope", "user", "keysec"); err != nil {
					return changes, err
				}
				changes = append(changes, "removed MCP server")
			}
			path := claudeSettingsPath()
			doc, err := readJSON(path)
			if err != nil {
				return changes, err
			}
			if removeHook(doc) {
				if err := writeJSON(path, doc); err != nil {
					return changes, err
				}
				changes = append(changes, "removed PreToolUse hook from "+path)
			}
			return changes, nil
		},
	}
}

func claudeSettingsPath() string {
	if dir := os.Getenv("CLAUDE_CONFIG_DIR"); dir != "" {
		return filepath.Join(dir, "settings.json")
	}
	return homeDir(".claude", "settings.json")
}

func isKeysecHook(h any) bool {
	m, ok := h.(map[string]any)
	if !ok {
		return false
	}
	cmd, _ := m["command"].(string)
	return strings.Contains(cmd, "keysec") && strings.HasSuffix(cmd, " hook claude")
}

// addHook adds the keysec PreToolUse hook to Claude Code settings. It
// reports whether doc changed.
func addHook(doc map[string]any, command string) bool {
	hooks := object(doc, "hooks")
	entries, _ := hooks["PreToolUse"].([]any)
	for _, e := range entries {
		if m, ok := e.(map[string]any); ok {
			inner, _ := m["hooks"].([]any)
			for _, h := range inner {
				if isKeysecHook(h) {
					return false
				}
			}
		}
	}
	hooks["PreToolUse"] = append(entries, map[string]any{
		"matcher": hookMatcher,
		"hooks":   []any{map[string]any{"type": "command", "command": command}},
	})
	return true
}

// removeHook removes every keysec hook and any matcher left empty. It
// reports whether doc changed.
func removeHook(doc map[string]any) bool {
	hooks, ok := doc["hooks"].(map[string]any)
	if !ok {
		return false
	}
	entries, _ := hooks["PreToolUse"].([]any)
	changed := false
	kept := entries[:0]
	for _, e := range entries {
		m, ok := e.(map[string]any)
		if !ok {
			kept = append(kept, e)
			continue
		}
		inner, _ := m["hooks"].([]any)
		var rest []any
		for _, h := range inner {
			if isKeysecHook(h) {
				changed = true
			} else {
				rest = append(rest, h)
			}
		}
		if len(rest) > 0 {
			m["hooks"] = rest
			kept = append(kept, m)
		}
	}
	if !changed {
		return false
	}
	if len(kept) == 0 {
		delete(hooks, "PreToolUse")
	} else {
		hooks["PreToolUse"] = kept
	}
	if len(hooks) == 0 {
		delete(doc, "hooks")
	}
	return true
}
