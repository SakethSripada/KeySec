// Package detect recognizes well-known credential formats and suggests
// metadata and a policy for them.
package detect

import (
	"net/url"
	"strings"
)

// Guess is what can be inferred from a value.
type Guess struct {
	Provider    string
	Description string
	Mode        string
	Hosts       []string
	Auth        string
}

type rule struct {
	prefix string
	Guess
}

// Rules are checked in order, so longer prefixes come before shorter ones
// that share a start.
var rules = []rule{
	{"sk_live_", Guess{"stripe", "Stripe secret key", "live", []string{"api.stripe.com"}, "bearer"}},
	{"sk_test_", Guess{"stripe", "Stripe secret key", "test", []string{"api.stripe.com"}, "bearer"}},
	{"rk_live_", Guess{"stripe", "Stripe restricted key", "live", []string{"api.stripe.com"}, "bearer"}},
	{"rk_test_", Guess{"stripe", "Stripe restricted key", "test", []string{"api.stripe.com"}, "bearer"}},
	{"whsec_", Guess{"stripe", "Stripe webhook signing secret", "", nil, "none"}},
	{"sk-ant-", Guess{"anthropic", "Anthropic API key", "", []string{"api.anthropic.com"}, "header:x-api-key"}},
	{"sk-proj-", Guess{"openai", "OpenAI project API key", "", []string{"api.openai.com"}, "bearer"}},
	{"sk-svcacct-", Guess{"openai", "OpenAI service account key", "", []string{"api.openai.com"}, "bearer"}},
	{"sk-admin-", Guess{"openai", "OpenAI admin key", "", []string{"api.openai.com"}, "bearer"}},
	{"github_pat_", Guess{"github", "GitHub fine-grained personal access token", "", []string{"api.github.com", "uploads.github.com"}, "bearer"}},
	{"ghp_", Guess{"github", "GitHub personal access token (classic)", "", []string{"api.github.com", "uploads.github.com"}, "bearer"}},
	{"gho_", Guess{"github", "GitHub OAuth token", "", []string{"api.github.com"}, "bearer"}},
	{"ghs_", Guess{"github", "GitHub App installation token", "", []string{"api.github.com"}, "bearer"}},
	{"glpat-", Guess{"gitlab", "GitLab personal access token", "", []string{"gitlab.com"}, "bearer"}},
	{"xoxb-", Guess{"slack", "Slack bot token", "", []string{"slack.com"}, "bearer"}},
	{"xoxp-", Guess{"slack", "Slack user token", "", []string{"slack.com"}, "bearer"}},
	{"SG.", Guess{"sendgrid", "SendGrid API key", "", []string{"api.sendgrid.com"}, "bearer"}},
	{"AIza", Guess{"google", "Google API key", "", []string{"*.googleapis.com"}, "header:x-goog-api-key"}},
	{"hf_", Guess{"huggingface", "Hugging Face access token", "", []string{"huggingface.co", "*.huggingface.co"}, "bearer"}},
	{"npm_", Guess{"npm", "npm access token", "", []string{"registry.npmjs.org"}, "bearer"}},
	{"sbp_", Guess{"supabase", "Supabase personal access token", "", []string{"api.supabase.com"}, "bearer"}},
	{"lin_api_", Guess{"linear", "Linear API key", "", []string{"api.linear.app"}, "header:Authorization"}},
	{"gsk_", Guess{"groq", "Groq API key", "", []string{"api.groq.com"}, "bearer"}},
	{"xai-", Guess{"xai", "xAI API key", "", []string{"api.x.ai"}, "bearer"}},
	{"pplx-", Guess{"perplexity", "Perplexity API key", "", []string{"api.perplexity.ai"}, "bearer"}},
	{"r8_", Guess{"replicate", "Replicate API token", "", []string{"api.replicate.com"}, "bearer"}},
	{"dop_v1_", Guess{"digitalocean", "DigitalOcean personal access token", "", []string{"api.digitalocean.com"}, "bearer"}},
	{"shpat_", Guess{"shopify", "Shopify Admin API access token", "", []string{"*.myshopify.com"}, "header:X-Shopify-Access-Token"}},
	{"AKIA", Guess{"aws", "AWS access key ID", "", nil, "none"}},
}

var databaseSchemes = map[string]string{
	"postgres":    "Postgres",
	"postgresql":  "Postgres",
	"mysql":       "MySQL",
	"mongodb":     "MongoDB",
	"mongodb+srv": "MongoDB",
	"redis":       "Redis",
	"rediss":      "Redis",
	"amqp":        "RabbitMQ",
	"amqps":       "RabbitMQ",
}

// Detect returns what can be inferred about a value, and whether anything
// was recognized.
func Detect(value string) (Guess, bool) {
	value = strings.TrimSpace(value)
	for _, r := range rules {
		if strings.HasPrefix(value, r.prefix) {
			g := r.Guess
			g.Hosts = append([]string(nil), g.Hosts...)
			return g, true
		}
	}
	if u, err := url.Parse(value); err == nil && u.Host != "" {
		if name, ok := databaseSchemes[strings.ToLower(u.Scheme)]; ok {
			return Guess{
				Provider:    strings.ToLower(name),
				Description: name + " connection string for " + u.Hostname(),
				Auth:        "none",
			}, true
		}
	}
	return Guess{}, false
}
