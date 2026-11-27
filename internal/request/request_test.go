package request

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const value = "example-secret-abcdefghijklmnop"

// echoServer responds with the request's auth-carrying parts so tests can
// check what was sent and that the response is redacted.
func echoServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Echo", r.Header.Get("Authorization"))
		io.WriteString(w, strings.Join([]string{
			r.Method,
			r.URL.String(),
			r.Header.Get("Authorization"),
			r.Header.Get("X-Api-Key"),
			string(body),
		}, "\n"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func cred(auth string) Credential {
	return Credential{Name: "KEY", Value: value, Hosts: []string{"127.0.0.1"}, Auth: auth}
}

func TestAuthStyles(t *testing.T) {
	srv := echoServer(t)
	var c Client
	for _, auth := range []string{"", "bearer", "basic", "header:X-Api-Key", "query:key"} {
		t.Run(auth, func(t *testing.T) {
			resp, err := c.Do(context.Background(), cred(auth), Request{URL: srv.URL + "/v1"})
			if err != nil {
				t.Fatal(err)
			}
			if resp.Status != 200 {
				t.Fatalf("status %d", resp.Status)
			}
			if strings.Contains(resp.Body, value) || strings.Contains(resp.Headers["X-Echo"], value) {
				t.Fatalf("value leaked in response: %+v", resp)
			}
			if auth != "basic" && !strings.Contains(resp.Body, "[keysec:KEY]") {
				t.Fatalf("server did not receive the secret: %q", resp.Body)
			}
		})
	}
}

func TestPlaceholders(t *testing.T) {
	srv := echoServer(t)
	var c Client
	resp, err := c.Do(context.Background(), cred("none"), Request{
		Method:  "post",
		URL:     srv.URL + "/bot{{KEY}}/send",
		Headers: map[string]string{"X-Api-Key": "{{KEY}}"},
		Body:    `{"token":"{{KEY}}"}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "POST\n/bot[keysec:KEY]/send\n\n[keysec:KEY]\n{\"token\":\"[keysec:KEY]\"}"
	if resp.Body != want {
		t.Fatalf("got\n%s\nwant\n%s", resp.Body, want)
	}
}

func TestHostNotAllowed(t *testing.T) {
	srv := echoServer(t)
	c := cred("")
	c.Hosts = []string{"api.stripe.com"}
	_, err := new(Client).Do(context.Background(), c, Request{URL: srv.URL})
	if err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("err = %v", err)
	}
}

func TestPlaceholderInHostRejected(t *testing.T) {
	c := cred("none")
	c.Hosts = []string{"*.example.com"}
	_, err := new(Client).Do(context.Background(), c, Request{URL: "https://{{KEY}}.example.com/"})
	if err == nil {
		t.Fatal("expected an error")
	}
}

func TestRedirectsNotFollowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://evil.example/", http.StatusFound)
	}))
	defer srv.Close()
	resp, err := new(Client).Do(context.Background(), cred(""), Request{URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != http.StatusFound {
		t.Fatalf("status = %d", resp.Status)
	}
}

func TestErrorsAreRedacted(t *testing.T) {
	c := cred("query:key")
	// Nothing listens on port 1, so the error message includes the URL.
	_, err := new(Client).Do(context.Background(), c, Request{URL: "http://127.0.0.1:1/"})
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), value) {
		t.Fatalf("value leaked in error: %v", err)
	}
}

func TestTruncation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, strings.Repeat("x", 100))
	}))
	defer srv.Close()
	resp, err := (&Client{MaxBody: 10}).Do(context.Background(), cred(""), Request{URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Truncated || len(resp.Body) != 10 {
		t.Fatalf("truncated=%v len=%d", resp.Truncated, len(resp.Body))
	}
}

func TestCheckHost(t *testing.T) {
	tests := []struct {
		url   string
		hosts []string
		ok    bool
	}{
		{"https://api.stripe.com/v1", []string{"api.stripe.com"}, true},
		{"https://API.STRIPE.COM/v1", []string{"api.stripe.com"}, true},
		{"https://api.stripe.com.evil.com/", []string{"api.stripe.com"}, false},
		{"https://x.googleapis.com/", []string{"*.googleapis.com"}, true},
		{"https://googleapis.com/", []string{"*.googleapis.com"}, false},
		{"https://evilgoogleapis.com/", []string{"*.googleapis.com"}, false},
		{"http://api.stripe.com/", []string{"api.stripe.com"}, false},
		{"http://localhost:3000/", []string{"localhost"}, true},
		{"ftp://api.stripe.com/", []string{"api.stripe.com"}, false},
		{"https://api.stripe.com/", nil, false},
	}
	for _, tt := range tests {
		u, _ := url.Parse(tt.url)
		err := CheckHost(u, tt.hosts)
		if (err == nil) != tt.ok {
			t.Errorf("CheckHost(%s, %v) = %v, want ok=%v", tt.url, tt.hosts, err, tt.ok)
		}
	}
}
