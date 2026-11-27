package push

import (
	"slices"
	"strings"
	"testing"
)

func TestValueNeverInArgs(t *testing.T) {
	o := Options{Name: "API_KEY", Value: "secret-value", Environment: "production", Repo: "o/r", App: "a"}
	for _, name := range Targets() {
		inv, err := Build(name, o)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, a := range inv.Args {
			if strings.Contains(a, o.Value) {
				t.Errorf("%s: value in argument %q", name, a)
			}
		}
		if !strings.Contains(inv.Stdin, o.Value) {
			t.Errorf("%s: value not on stdin", name)
		}
	}
}

func TestGithub(t *testing.T) {
	inv, _ := Build("github", Options{Name: "K", Value: "v", Repo: "o/r"})
	want := []string{"gh", "secret", "set", "K", "--repo", "o/r"}
	if !slices.Equal(inv.Args, want) {
		t.Fatalf("args = %v", inv.Args)
	}
}

func TestVercelNeedsEnvironment(t *testing.T) {
	if _, err := Build("vercel", Options{Name: "K", Value: "v"}); err == nil {
		t.Fatal("expected an error")
	}
}

func TestFlyRejectsMultiline(t *testing.T) {
	if _, err := Build("fly", Options{Name: "K", Value: "a\nb"}); err == nil {
		t.Fatal("expected an error")
	}
}

func TestUnknownTarget(t *testing.T) {
	if _, err := Build("heroku", Options{}); err == nil || !strings.Contains(err.Error(), "github") {
		t.Fatalf("err = %v", err)
	}
}
