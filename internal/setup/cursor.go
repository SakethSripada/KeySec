package setup

import "os"

func cursor() Agent {
	path := homeDir(".cursor", "mcp.json")
	return Agent{
		Name: "Cursor",
		Detected: func() bool {
			info, err := os.Stat(homeDir(".cursor"))
			return err == nil && info.IsDir()
		},
		Install: func(exe string) ([]string, error) {
			doc, err := readJSON(path)
			if err != nil {
				return nil, err
			}
			servers := object(doc, "mcpServers")
			if _, ok := servers["keysec"]; ok {
				return nil, nil
			}
			servers["keysec"] = map[string]any{"command": exe, "args": []any{"mcp"}}
			if err := writeJSON(path, doc); err != nil {
				return nil, err
			}
			return []string{"added MCP server to " + path}, nil
		},
		Remove: func() ([]string, error) {
			doc, err := readJSON(path)
			if err != nil {
				return nil, err
			}
			servers, ok := doc["mcpServers"].(map[string]any)
			if !ok {
				return nil, nil
			}
			if _, ok := servers["keysec"]; !ok {
				return nil, nil
			}
			delete(servers, "keysec")
			if err := writeJSON(path, doc); err != nil {
				return nil, err
			}
			return []string{"removed MCP server from " + path}, nil
		},
	}
}
