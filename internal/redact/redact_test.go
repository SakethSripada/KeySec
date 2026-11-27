package redact

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strings"
	"testing"
)

const secret = "example-secret-value-0123456789"

func TestString(t *testing.T) {
	r := New(map[string]string{"STRIPE": secret})
	tests := map[string]string{
		"raw":         "key=" + secret + " done",
		"base64":      base64.StdEncoding.EncodeToString([]byte("Authorization: Basic " + secret + ":")),
		"base64 url":  base64.URLEncoding.EncodeToString([]byte("x" + secret)),
		"hex":         hex.EncodeToString([]byte(secret)),
		"hex upper":   strings.ToUpper(hex.EncodeToString([]byte(secret))),
		"query":       "?k=" + url.QueryEscape(secret+"/+="),
		"offset by 2": base64.StdEncoding.EncodeToString([]byte("ab" + secret)),
	}
	for name, in := range tests {
		t.Run(name, func(t *testing.T) {
			out := r.String(in)
			if !strings.Contains(out, "[keysec:STRIPE]") {
				t.Errorf("not redacted: %q -> %q", in, out)
			}
		})
	}
}

func TestRawValueRemoved(t *testing.T) {
	r := New(map[string]string{"A": secret})
	out := r.String("before " + secret + " after " + secret)
	if out != "before [keysec:A] after [keysec:A]" {
		t.Fatalf("got %q", out)
	}
}

func TestLongestMatchWins(t *testing.T) {
	r := New(map[string]string{"SHORT": "abcdef", "LONG": "abcdefghij"})
	if got := r.String("xabcdefghijx"); got != "x[keysec:LONG]x" {
		t.Fatalf("got %q", got)
	}
}

func TestShortValuesIgnored(t *testing.T) {
	r := New(map[string]string{"PIN": "1234"})
	if got := r.String("1234"); got != "1234" {
		t.Fatalf("got %q", got)
	}
}

func TestNilAndEmpty(t *testing.T) {
	var r *Redactor
	if r.String("x") != "x" {
		t.Fatal("nil redactor changed input")
	}
	if New(nil).String("x") != "x" {
		t.Fatal("empty redactor changed input")
	}
}

func TestWriterSplitAcrossWrites(t *testing.T) {
	r := New(map[string]string{"S": secret})
	input := "start " + secret + " middle " + secret + " end"
	for chunk := 1; chunk <= len(input); chunk++ {
		var buf bytes.Buffer
		w := NewWriter(r, &buf)
		for i := 0; i < len(input); i += chunk {
			if _, err := w.Write([]byte(input[i:min(i+chunk, len(input))])); err != nil {
				t.Fatal(err)
			}
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		want := "start [keysec:S] middle [keysec:S] end"
		if buf.String() != want {
			t.Fatalf("chunk %d: got %q", chunk, buf.String())
		}
	}
}

func TestWriterPassthroughWithoutSecrets(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(New(nil), &buf)
	w.Write([]byte("hello"))
	w.Close()
	if buf.String() != "hello" {
		t.Fatalf("got %q", buf.String())
	}
}
