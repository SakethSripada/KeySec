// Package request sends an HTTP request with a secret attached, but only to
// hosts the secret's policy allows.
package request

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sakethsripada/keysec/internal/redact"
)

// Credential is a secret and the rules for sending it.
type Credential struct {
	Name  string
	Value string
	Hosts []string
	// Auth is one of:
	//   "bearer" (default)   Authorization: Bearer <value>
	//   "basic"              Authorization: Basic, value is "user:pass" or a bare username
	//   "header:<Name>"      <Name>: <value>
	//   "query:<param>"      ?<param>=<value>
	//   "none"               only {{NAME}} placeholders are substituted
	Auth string
}

// Request is what the caller wants to send. Any "{{NAME}}" in the URL path or
// query, a header value or the body is replaced with the secret's value.
type Request struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    string
}

// Response is the redacted result.
type Response struct {
	Status    int               `json:"status"`
	Headers   map[string]string `json:"headers"`
	Body      string            `json:"body"`
	Truncated bool              `json:"truncated,omitempty"`
}

// Client sends requests. The zero value is usable.
type Client struct {
	HTTP    *http.Client // defaults to a client with a 60s timeout
	MaxBody int64        // defaults to 1 MiB
}

// Do sends req with cred attached. The secret's value is redacted from the
// response and from any error.
func (c *Client) Do(ctx context.Context, cred Credential, req Request) (Response, error) {
	red := redact.New(map[string]string{cred.Name: cred.Value})
	resp, err := c.do(ctx, cred, req)
	if err != nil {
		return Response{}, errors.New(red.String(err.Error()))
	}
	resp.Body = red.String(resp.Body)
	for k, v := range resp.Headers {
		resp.Headers[k] = red.String(v)
	}
	return resp, nil
}

func (c *Client) do(ctx context.Context, cred Credential, req Request) (Response, error) {
	u, err := url.Parse(req.URL)
	if err != nil {
		return Response{}, fmt.Errorf("invalid url: %w", err)
	}
	placeholder := "{{" + cred.Name + "}}"
	if strings.Contains(u.Host, placeholder) {
		return Response{}, errors.New("the secret cannot be placed in the hostname")
	}
	if err := CheckHost(u, cred.Hosts); err != nil {
		return Response{}, fmt.Errorf("%s: %w", cred.Name, err)
	}

	sub := func(s string) string { return strings.ReplaceAll(s, placeholder, cred.Value) }
	method := strings.ToUpper(req.Method)
	if method == "" {
		method = http.MethodGet
	}
	var body io.Reader
	if req.Body != "" {
		body = strings.NewReader(sub(req.Body))
	}
	hreq, err := http.NewRequestWithContext(ctx, method, sub(req.URL), body)
	if err != nil {
		return Response{}, err
	}
	if hreq.URL.Host != u.Host {
		return Response{}, errors.New("url host changed after substitution")
	}
	for k, v := range req.Headers {
		hreq.Header.Set(k, sub(v))
	}
	if err := attach(hreq, cred); err != nil {
		return Response{}, err
	}

	hresp, err := c.httpClient().Do(hreq)
	if err != nil {
		return Response{}, err
	}
	defer hresp.Body.Close()

	limit := c.MaxBody
	if limit <= 0 {
		limit = 1 << 20
	}
	data, err := io.ReadAll(io.LimitReader(hresp.Body, limit+1))
	if err != nil {
		return Response{}, err
	}
	out := Response{Status: hresp.StatusCode, Headers: map[string]string{}}
	if int64(len(data)) > limit {
		data = data[:limit]
		out.Truncated = true
	}
	out.Body = string(data)
	for k := range hresp.Header {
		out.Headers[k] = hresp.Header.Get(k)
	}
	return out, nil
}

func (c *Client) httpClient() *http.Client {
	base := c.HTTP
	if base == nil {
		base = &http.Client{Timeout: 60 * time.Second}
	}
	// Never follow redirects: a redirect to another host would carry the
	// secret with it. The caller sees the 3xx and can decide.
	cl := *base
	cl.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &cl
}

func attach(r *http.Request, cred Credential) error {
	kind, arg, _ := strings.Cut(cred.Auth, ":")
	switch kind {
	case "", "bearer":
		r.Header.Set("Authorization", "Bearer "+cred.Value)
	case "basic":
		user, pass, _ := strings.Cut(cred.Value, ":")
		r.SetBasicAuth(user, pass)
	case "header":
		if arg == "" {
			return errors.New(`auth "header" needs a header name, e.g. "header:X-Api-Key"`)
		}
		r.Header.Set(arg, cred.Value)
	case "query":
		if arg == "" {
			return errors.New(`auth "query" needs a parameter name, e.g. "query:key"`)
		}
		q := r.URL.Query()
		q.Set(arg, cred.Value)
		r.URL.RawQuery = q.Encode()
	case "none":
	default:
		return fmt.Errorf("unknown auth %q", cred.Auth)
	}
	return nil
}

// CheckHost returns an error unless u may receive a secret limited to hosts.
// HTTPS is required except for loopback addresses.
func CheckHost(u *url.URL, hosts []string) error {
	host := strings.ToLower(u.Hostname())
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopback(host) {
			return errors.New("refusing to send a secret over plain http")
		}
	default:
		return fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	if len(hosts) == 0 {
		return errors.New("no allowed hosts are set; add one with `keysec policy`")
	}
	if !HostAllowed(host, hosts) {
		return fmt.Errorf("host %q is not allowed (allowed: %s)", host, strings.Join(hosts, ", "))
	}
	return nil
}

// HostAllowed reports whether host matches one of the patterns. "*.x.com"
// matches subdomains of x.com but not x.com itself.
func HostAllowed(host string, patterns []string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, p := range patterns {
		p = strings.ToLower(p)
		if suffix, ok := strings.CutPrefix(p, "*."); ok {
			if strings.HasSuffix(host, "."+suffix) {
				return true
			}
		} else if host == p {
			return true
		}
	}
	return false
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
