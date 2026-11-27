// Package redact replaces secret values in text with placeholders.
//
// Besides the raw value it matches the encodings a value most often leaks in:
// base64 (standard and URL-safe, at any byte alignment), hex and URL query
// escaping. It cannot catch arbitrary transformations; see SECURITY.md.
package redact

import (
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/url"
	"sort"
	"strings"
)

// MinLength is the shortest value that is redacted. Shorter values would
// match ordinary text too often to be useful.
const MinLength = 6

// minEncoded is the shortest encoded fragment that is redacted.
const minEncoded = 8

type pattern struct {
	match       []byte
	replacement []byte
}

// Redactor replaces known secret values. The zero value redacts nothing.
type Redactor struct {
	byFirst map[byte][]pattern
	maxLen  int
}

// New returns a Redactor for the given name to value map.
func New(secrets map[string]string) *Redactor {
	r := &Redactor{byFirst: map[byte][]pattern{}}
	seen := map[string]bool{}
	for name, value := range secrets {
		repl := []byte("[keysec:" + name + "]")
		for _, v := range variants(value) {
			if seen[v] {
				continue
			}
			seen[v] = true
			r.byFirst[v[0]] = append(r.byFirst[v[0]], pattern{match: []byte(v), replacement: repl})
			r.maxLen = max(r.maxLen, len(v))
		}
	}
	// Prefer the longest match at any position.
	for _, ps := range r.byFirst {
		sort.Slice(ps, func(i, j int) bool { return len(ps[i].match) > len(ps[j].match) })
	}
	return r
}

func variants(value string) []string {
	if len(value) < MinLength {
		return nil
	}
	out := []string{value}
	add := func(s string) {
		if len(s) >= minEncoded {
			out = append(out, s)
		}
	}
	if q := url.QueryEscape(value); q != value {
		add(q)
	}
	add(hex.EncodeToString([]byte(value)))
	add(strings.ToUpper(hex.EncodeToString([]byte(value))))

	// A value embedded in a larger base64 payload can start at any of three
	// byte offsets within a 3-byte group. For each offset, the characters
	// produced by whole groups of the value's bytes are fixed regardless of
	// the surrounding data.
	for skip := 0; skip < 3 && skip < len(value); skip++ {
		b := []byte(value[skip:])
		b = b[:len(b)/3*3]
		add(base64.StdEncoding.EncodeToString(b))
		add(base64.URLEncoding.EncodeToString(b))
	}
	return out
}

// String returns s with every secret replaced.
func (r *Redactor) String(s string) string {
	if r == nil || r.maxLen == 0 {
		return s
	}
	out, _ := r.scan([]byte(s), len(s))
	return string(out)
}

// scan redacts matches that start before limit. It returns the output and
// how many input bytes it consumed, which is at least limit.
func (r *Redactor) scan(in []byte, limit int) ([]byte, int) {
	out := make([]byte, 0, len(in))
	i := 0
	for i < limit && i < len(in) {
		if p, ok := r.matchAt(in[i:]); ok {
			out = append(out, p.replacement...)
			i += len(p.match)
			continue
		}
		out = append(out, in[i])
		i++
	}
	return out, i
}

func (r *Redactor) matchAt(b []byte) (pattern, bool) {
	for _, p := range r.byFirst[b[0]] {
		if len(b) >= len(p.match) && string(b[:len(p.match)]) == string(p.match) {
			return p, true
		}
	}
	return pattern{}, false
}

// Writer redacts everything written to it before passing it on. A value
// split across two writes is still caught. Close must be called to flush
// the final bytes.
type Writer struct {
	r       *Redactor
	w       io.Writer
	pending []byte
}

// NewWriter returns a Writer that redacts into w.
func NewWriter(r *Redactor, w io.Writer) *Writer {
	return &Writer{r: r, w: w}
}

func (w *Writer) Write(p []byte) (int, error) {
	if w.r == nil || w.r.maxLen == 0 {
		return w.w.Write(p)
	}
	w.pending = append(w.pending, p...)
	// Any match starting before limit lies entirely within pending.
	limit := len(w.pending) - (w.r.maxLen - 1)
	if limit <= 0 {
		return len(p), nil
	}
	out, n := w.r.scan(w.pending, limit)
	w.pending = append(w.pending[:0], w.pending[n:]...)
	if _, err := w.w.Write(out); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close flushes any buffered bytes.
func (w *Writer) Close() error {
	if len(w.pending) == 0 {
		return nil
	}
	out, _ := w.r.scan(w.pending, len(w.pending))
	w.pending = nil
	_, err := w.w.Write(out)
	return err
}
