// Package mcpserver exposes keysec to agents over the Model Context Protocol.
package mcpserver

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sakethsripada/keysec/internal/broker"
	"github.com/sakethsripada/keysec/internal/push"
	"github.com/sakethsripada/keysec/internal/request"
	"github.com/sakethsripada/keysec/internal/runner"
	"github.com/sakethsripada/keysec/internal/store"
)

const instructions = `keysec holds the user's API keys and other secrets. You can see every
secret's name, description, provider, scopes and allowed hosts, but never its value.

- Call list_secrets to see what is available before asking the user for a key.
- Use http_request to call an API with a secret. keysec attaches it and only sends it to the secret's allowed hosts.
- Use run_command to run tests, scripts or deploy tools that read secrets from environment variables.
- Use push_secret to copy a secret into GitHub Actions, Vercel, Fly or Cloudflare.
- Do not read .env files or keychains directly, and do not try to recover secret values.
  Values in output appear as [keysec:NAME].`

// maxOutput caps command output returned to the agent.
const maxOutput = 64 << 10

// New returns an MCP server backed by b.
func New(b *broker.Broker, version string) *mcp.Server {
	s := mcp.NewServer(
		&mcp.Implementation{Name: "keysec", Version: version},
		&mcp.ServerOptions{Instructions: instructions},
	)
	h := handlers{b: b}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_secrets",
		Description: "List available secrets with their descriptions and policies. Never returns values.",
	}, h.list)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "describe_secret",
		Description: "Show everything known about one secret except its value.",
	}, h.describe)
	mcp.AddTool(s, &mcp.Tool{
		Name: "http_request",
		Description: "Send an HTTPS request with a secret attached according to its auth setting. " +
			"Only hosts in the secret's policy are allowed. Write {{NAME}} in the URL path or query, a header or the body to place the value yourself. " +
			"Redirects are not followed.",
	}, h.request)
	mcp.AddTool(s, &mcp.Tool{
		Name: "run_command",
		Description: "Run a shell command with the given secrets set as environment variables. " +
			"Secret values are replaced with [keysec:NAME] in the output.",
	}, h.run)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "push_secret",
		Description: "Copy a secret into a provider using its CLI (gh, vercel, fly or wrangler must be installed and logged in).",
	}, h.push)
	return s
}

type handlers struct {
	b *broker.Broker
}

// Info is the agent-visible view of a secret.
type Info struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Provider    string   `json:"provider,omitempty"`
	Mode        string   `json:"mode,omitempty"`
	Scopes      []string `json:"scopes,omitempty"`
	EnvVar      string   `json:"env_var"`
	Expires     string   `json:"expires,omitempty"`
	Hosts       []string `json:"allowed_hosts,omitempty"`
	Auth        string   `json:"auth,omitempty"`
	AllowRun    bool     `json:"allow_run"`
}

func info(s store.Secret) Info {
	return Info{
		Name:        s.Name,
		Description: s.Description,
		Provider:    s.Provider,
		Mode:        s.Mode,
		Scopes:      s.Scopes,
		EnvVar:      s.EnvName(),
		Expires:     s.Expires,
		Hosts:       s.Hosts,
		Auth:        s.Auth,
		AllowRun:    s.AllowRun,
	}
}

type listOut struct {
	Secrets []Info `json:"secrets"`
}

func (h handlers) list(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, listOut, error) {
	secrets, err := h.b.Store.List()
	if err != nil {
		return nil, listOut{}, err
	}
	out := listOut{Secrets: make([]Info, 0, len(secrets))}
	for _, s := range secrets {
		out.Secrets = append(out.Secrets, info(s))
	}
	return nil, out, nil
}

type nameIn struct {
	Name string `json:"name" jsonschema:"secret name"`
}

func (h handlers) describe(_ context.Context, _ *mcp.CallToolRequest, in nameIn) (*mcp.CallToolResult, Info, error) {
	s, err := h.b.Store.Get(in.Name)
	if err != nil {
		return nil, Info{}, err
	}
	return nil, info(s), nil
}

type requestIn struct {
	Secret  string            `json:"secret" jsonschema:"name of the secret to attach"`
	Method  string            `json:"method,omitempty" jsonschema:"HTTP method, default GET"`
	URL     string            `json:"url" jsonschema:"full https URL"`
	Headers map[string]string `json:"headers,omitempty" jsonschema:"extra request headers"`
	Body    string            `json:"body,omitempty" jsonschema:"request body"`
}

func (h handlers) request(ctx context.Context, _ *mcp.CallToolRequest, in requestIn) (*mcp.CallToolResult, request.Response, error) {
	resp, err := h.b.Request(ctx, in.Secret, request.Request{
		Method:  in.Method,
		URL:     in.URL,
		Headers: in.Headers,
		Body:    in.Body,
	})
	return nil, resp, err
}

type runIn struct {
	Command        string   `json:"command" jsonschema:"shell command, run with sh -c"`
	Secrets        []string `json:"secrets" jsonschema:"names of secrets to set as environment variables"`
	Cwd            string   `json:"cwd,omitempty" jsonschema:"working directory"`
	TimeoutSeconds int      `json:"timeout_seconds,omitempty" jsonschema:"default 300"`
}

type runOut struct {
	ExitCode  int    `json:"exit_code"`
	Output    string `json:"output"`
	Truncated bool   `json:"truncated,omitempty"`
}

func (h handlers) run(ctx context.Context, _ *mcp.CallToolRequest, in runIn) (*mcp.CallToolResult, runOut, error) {
	timeout := time.Duration(in.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	out := &capped{limit: maxOutput}
	code, err := h.b.Run(ctx, in.Secrets, runner.Command{
		Args:   []string{"sh", "-c", in.Command},
		Dir:    in.Cwd,
		Stdout: out,
		Stderr: out,
	})
	if err != nil {
		return nil, runOut{}, err
	}
	if ctx.Err() != nil {
		return nil, runOut{}, fmt.Errorf("command timed out after %s", timeout)
	}
	return nil, runOut{ExitCode: code, Output: out.String(), Truncated: out.truncated}, nil
}

type pushIn struct {
	Secret      string `json:"secret" jsonschema:"name of the secret to push"`
	Target      string `json:"target" jsonschema:"github, vercel, fly or cloudflare"`
	As          string `json:"as,omitempty" jsonschema:"variable name at the destination, default is the secret's env var"`
	Environment string `json:"environment,omitempty" jsonschema:"vercel: production, preview or development (required); github and cloudflare: environment name"`
	Repo        string `json:"repo,omitempty" jsonschema:"github: owner/repo, default is the current repository"`
	App         string `json:"app,omitempty" jsonschema:"fly: app name"`
}

func (h handlers) push(ctx context.Context, _ *mcp.CallToolRequest, in pushIn) (*mcp.CallToolResult, runOut, error) {
	out := &capped{limit: maxOutput}
	code, err := h.b.Push(ctx, in.Secret, in.Target, push.Options{
		Name:        in.As,
		Environment: in.Environment,
		Repo:        in.Repo,
		App:         in.App,
	}, out, out)
	if err != nil {
		return nil, runOut{}, err
	}
	return nil, runOut{ExitCode: code, Output: out.String(), Truncated: out.truncated}, nil
}

// capped is a concurrency-safe buffer that keeps the first limit bytes.
type capped struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (c *capped) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	room := c.limit - c.buf.Len()
	if room < len(p) {
		c.truncated = true
		if room > 0 {
			c.buf.Write(p[:room])
		}
		return len(p), nil
	}
	return c.buf.Write(p)
}

func (c *capped) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}
