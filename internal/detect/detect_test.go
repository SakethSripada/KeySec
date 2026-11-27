package detect

import "testing"

func TestDetect(t *testing.T) {
	tests := []struct {
		value, provider, mode, host string
	}{
		{"sk_live_abc", "stripe", "live", "api.stripe.com"},
		{"sk_test_abc", "stripe", "test", "api.stripe.com"},
		{"sk-ant-api03-xyz", "anthropic", "", "api.anthropic.com"},
		{"sk-proj-xyz", "openai", "", "api.openai.com"},
		{"github_pat_11ABC", "github", "", "api.github.com"},
		{"ghp_abc", "github", "", "api.github.com"},
		{"AIzaSyD", "google", "", "*.googleapis.com"},
		{"  xoxb-123  ", "slack", "", "slack.com"},
		{"postgres://u:p@db.example.com:5432/app", "postgres", "", ""},
		{"mongodb+srv://u:p@cluster0.mongodb.net/x", "mongodb", "", ""},
	}
	for _, tt := range tests {
		g, ok := Detect(tt.value)
		if !ok {
			t.Errorf("%q: not detected", tt.value)
			continue
		}
		if g.Provider != tt.provider || g.Mode != tt.mode {
			t.Errorf("%q: got provider=%q mode=%q", tt.value, g.Provider, g.Mode)
		}
		if tt.host != "" && (len(g.Hosts) == 0 || g.Hosts[0] != tt.host) {
			t.Errorf("%q: hosts = %v", tt.value, g.Hosts)
		}
	}
}

func TestDetectUnknown(t *testing.T) {
	for _, v := range []string{"", "hunter2", "https://example.com", "sk-plain"} {
		if g, ok := Detect(v); ok {
			t.Errorf("%q detected as %+v", v, g)
		}
	}
}

func TestDetectReturnsCopy(t *testing.T) {
	g, _ := Detect("sk_live_x")
	g.Hosts[0] = "evil.com"
	g2, _ := Detect("sk_live_x")
	if g2.Hosts[0] != "api.stripe.com" {
		t.Fatal("rule table was modified through a returned guess")
	}
}

func TestDatabaseDescriptionHasNoCredentials(t *testing.T) {
	g, _ := Detect("postgres://admin:hunter2@db.example.com/app")
	if g.Description != "Postgres connection string for db.example.com" {
		t.Fatalf("description = %q", g.Description)
	}
}
