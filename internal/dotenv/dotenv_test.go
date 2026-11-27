package dotenv

import (
	"reflect"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	in := `
# comment
PLAIN=value
export EXPORTED=yes
SPACED = padded
COMMENTED=abc # trailing
HASH=abc#def
SINGLE='it''s literal \n'
DOUBLE="line1\nline2 \"q\""
MULTI="first
second"
EMPTY=
`
	got, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	want := []Entry{
		{"PLAIN", "value"},
		{"EXPORTED", "yes"},
		{"SPACED", "padded"},
		{"COMMENTED", "abc"},
		{"HASH", "abc#def"},
		{"SINGLE", `it''s literal \n`},
		{"DOUBLE", "line1\nline2 \"q\""},
		{"MULTI", "first\nsecond"},
		{"EMPTY", ""},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}

func TestParseErrors(t *testing.T) {
	for _, in := range []string{"NOEQUALS", `A="unterminated`, "A='open"} {
		if _, err := Parse(strings.NewReader(in)); err == nil {
			t.Errorf("%q: expected an error", in)
		}
	}
}
