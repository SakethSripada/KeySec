package setup

func codex() Agent {
	return Agent{
		Name:     "Codex",
		Detected: onPath("codex"),
		Install: func(exe string) ([]string, error) {
			if succeeds("codex", "mcp", "get", "keysec") {
				return nil, nil
			}
			if err := run("codex", "mcp", "add", "keysec", "--", exe, "mcp"); err != nil {
				return nil, err
			}
			return []string{"added MCP server"}, nil
		},
		Remove: func() ([]string, error) {
			if !succeeds("codex", "mcp", "get", "keysec") {
				return nil, nil
			}
			if err := run("codex", "mcp", "remove", "keysec"); err != nil {
				return nil, err
			}
			return []string{"removed MCP server"}, nil
		},
	}
}
