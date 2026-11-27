package envsync

import (
	"reflect"
	"testing"

	"github.com/sakethsripada/keysec/internal/dotenv"
)

const src = "/repo/.env"

func TestPlan(t *testing.T) {
	entries := []dotenv.Entry{
		{Key: "NEW", Value: "n"},
		{Key: "SAME", Value: "s"},
		{Key: "CHANGED", Value: "c2"},
		{Key: "MANUAL", Value: "m2"},
		{Key: "EMPTY", Value: ""},
		{Key: "bad-name", Value: "x"},
	}
	existing := map[string]Existing{
		"SAME":        {Source: src, Value: "s"},
		"CHANGED":     {Source: src, Value: "c1"},
		"MANUAL":      {Source: "", Value: "m1"},
		"GONE":        {Source: src, Value: "g"},
		"OTHER_FILE":  {Source: "/other/.env", Value: "o"},
		"ADDED_BY_ME": {Source: "", Value: "a"},
	}
	got := Plan(entries, existing, src)
	want := []Change{
		{Name: "NEW", Action: Add, Value: "n"},
		{Name: "SAME", Action: Unchanged},
		{Name: "CHANGED", Action: Update, Value: "c2"},
		{Name: "MANUAL", Action: Update, Value: "m2", Reason: "replaces a value not imported from this file"},
		{Name: "EMPTY", Action: Skip, Reason: "empty"},
		{Name: "bad-name", Action: Skip, Reason: "invalid name"},
		{Name: "GONE", Action: Remove},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got\n%+v\nwant\n%+v", got, want)
	}
}

func TestPlanDuplicateKeysLastWins(t *testing.T) {
	entries := []dotenv.Entry{{Key: "A", Value: "1"}, {Key: "B", Value: "b"}, {Key: "A", Value: "2"}}
	got := Plan(entries, nil, src)
	want := []Change{
		{Name: "A", Action: Add, Value: "2"},
		{Name: "B", Action: Add, Value: "b"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v", got)
	}
}

func TestEmptyEntryIsNotARemoval(t *testing.T) {
	entries := []dotenv.Entry{{Key: "A", Value: ""}}
	got := Plan(entries, map[string]Existing{"A": {Source: src, Value: "x"}}, src)
	if len(got) != 1 || got[0].Action != Skip {
		t.Fatalf("got %+v", got)
	}
}

func TestCount(t *testing.T) {
	c := []Change{{Action: Add}, {Action: Add}, {Action: Remove}}
	if Count(c, Add) != 2 || Count(c, Remove) != 1 || Count(c, Update) != 0 {
		t.Fatal("wrong counts")
	}
}
