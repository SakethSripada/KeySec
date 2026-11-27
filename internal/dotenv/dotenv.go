// Package dotenv parses .env files.
package dotenv

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// Entry is one KEY=VALUE assignment.
type Entry struct {
	Key   string
	Value string
}

// Parse reads assignments in file order. It supports an optional "export "
// prefix, single quotes (literal), double quotes (with \n, \t, \" and \\
// escapes, may span lines) and trailing " #" comments on unquoted values.
func Parse(r io.Reader) ([]Entry, error) {
	var out []Entry
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		key, raw, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: expected KEY=VALUE", lineNo)
		}
		key = strings.TrimSpace(key)
		raw = strings.TrimSpace(raw)

		var value string
		switch {
		case strings.HasPrefix(raw, `"`):
			// Double-quoted values may continue onto following lines.
			for !closedDouble(raw) {
				if !sc.Scan() {
					return nil, fmt.Errorf("line %d: unterminated double quote", lineNo)
				}
				lineNo++
				raw += "\n" + sc.Text()
			}
			value = unescape(raw[1:strings.LastIndex(raw, `"`)])
		case strings.HasPrefix(raw, "'"):
			end := strings.LastIndex(raw, "'")
			if end == 0 {
				return nil, fmt.Errorf("line %d: unterminated single quote", lineNo)
			}
			value = raw[1:end]
		default:
			if i := strings.Index(raw, " #"); i >= 0 {
				raw = raw[:i]
			}
			value = strings.TrimSpace(raw)
		}
		out = append(out, Entry{Key: key, Value: value})
	}
	return out, sc.Err()
}

// closedDouble reports whether s, which starts with a double quote, contains
// an unescaped closing quote.
func closedDouble(s string) bool {
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '"':
			return true
		}
	}
	return false
}

func unescape(s string) string {
	return strings.NewReplacer(`\n`, "\n", `\t`, "\t", `\"`, `"`, `\\`, `\`).Replace(s)
}
