package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/sakethsripada/keysec/internal/detect"
	"github.com/sakethsripada/keysec/internal/dotenv"
	"github.com/sakethsripada/keysec/internal/envsync"
	"github.com/sakethsripada/keysec/internal/store"
)

func (a *app) importEnv(args []string) error {
	fs := a.flags("import")
	prune := fs.Bool("prune", false, "delete secrets that were imported from this file but are no longer in it")
	dryRun := fs.Bool("dry-run", false, "show what would change without changing anything")
	del := fs.Bool("delete", false, "delete the file after a successful import")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if err := exactly(fs, pos, 1); err != nil {
		return err
	}
	source, err := filepath.Abs(pos[0])
	if err != nil {
		return err
	}
	entries, err := readEnvFile(source)
	if err != nil {
		return err
	}
	st, err := a.store()
	if err != nil {
		return err
	}
	existing, err := existingSecrets(st)
	if err != nil {
		return err
	}

	changes := envsync.Plan(entries, existing, source)
	printed := a.printPlan(changes, *prune, pos[0])
	if *dryRun {
		return nil
	}

	updates := envsync.Count(changes, envsync.Update)
	removals := 0
	if *prune {
		removals = envsync.Count(changes, envsync.Remove)
	}
	if updates+removals > 0 {
		// Changing or deleting an existing value could redirect what an agent
		// does with it, so it needs the person at the terminal.
		ok, err := a.prompt.Confirm(fmt.Sprintf("Apply %d update(s) and %d removal(s)?", updates, removals))
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("cancelled; nothing was changed")
		}
	}

	if err := applyPlan(st, changes, source, *prune); err != nil {
		return err
	}
	added := envsync.Count(changes, envsync.Add)
	if printed {
		fmt.Fprintln(a.stdout)
	}
	fmt.Fprintf(a.stdout, "%d added, %d updated, %d unchanged", added, updates, envsync.Count(changes, envsync.Unchanged))
	if *prune {
		fmt.Fprintf(a.stdout, ", %d removed", removals)
	}
	fmt.Fprintln(a.stdout, ".")

	if *del {
		if n := envsync.Count(changes, envsync.Skip); n > 0 {
			return fmt.Errorf("not deleting %s because %d entries were skipped", pos[0], n)
		}
		if err := os.Remove(source); err != nil {
			return err
		}
		fmt.Fprintf(a.stdout, "Deleted %s.\n", pos[0])
	}
	return nil
}

func readEnvFile(path string) ([]dotenv.Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entries, err := dotenv.Parse(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return entries, nil
}

func existingSecrets(st *store.Store) (map[string]envsync.Existing, error) {
	secrets, err := st.List()
	if err != nil {
		return nil, err
	}
	values, err := st.Values()
	if err != nil {
		return nil, err
	}
	out := make(map[string]envsync.Existing, len(secrets))
	for _, s := range secrets {
		out[s.Name] = envsync.Existing{Source: s.Source, Value: values[s.Name]}
	}
	return out, nil
}

// printPlan lists every change except unchanged secrets and reports whether
// it printed anything.
func (a *app) printPlan(changes []envsync.Change, prune bool, file string) bool {
	tw := tabwriter.NewWriter(a.stdout, 0, 0, 2, ' ', 0)
	for _, c := range changes {
		switch c.Action {
		case envsync.Add:
			desc := "no description; add one with `keysec edit " + c.Name + " -d ...`"
			if g, ok := detect.Detect(c.Value); ok {
				desc = g.Description
			}
			fmt.Fprintf(tw, "add\t%s\t%s\n", c.Name, desc)
		case envsync.Update:
			fmt.Fprintf(tw, "update\t%s\t%s\n", c.Name, orDefault(c.Reason, "value changed"))
		case envsync.Remove:
			if prune {
				fmt.Fprintf(tw, "remove\t%s\tno longer in %s\n", c.Name, file)
			} else {
				fmt.Fprintf(tw, "keep\t%s\tno longer in %s; use --prune to delete it\n", c.Name, file)
			}
		case envsync.Skip:
			fmt.Fprintf(tw, "skip\t%s\t%s\n", c.Name, c.Reason)
		}
	}
	tw.Flush()
	return envsync.Count(changes, envsync.Unchanged) < len(changes)
}

// applyPlan carries out the changes. New secrets get metadata and a policy
// from their format; updated ones keep theirs.
func applyPlan(st *store.Store, changes []envsync.Change, source string, prune bool) error {
	for _, c := range changes {
		switch c.Action {
		case envsync.Add:
			meta := store.Meta{Source: source}
			policy := store.Policy{AllowRun: true}
			fillFromGuess(c.Value, &meta, &policy, nil)
			if err := st.Put(c.Name, c.Value, meta, policy); err != nil {
				return err
			}
		case envsync.Update:
			s, err := st.Get(c.Name)
			if err != nil {
				return err
			}
			s.Source = source
			// A new value may be a different kind of key, e.g. live instead of test.
			if g, ok := detect.Detect(c.Value); ok {
				s.Provider, s.Mode = g.Provider, g.Mode
			}
			if err := st.Put(c.Name, c.Value, s.Meta, s.Policy); err != nil {
				return err
			}
		case envsync.Remove:
			if prune {
				if err := st.Remove(c.Name); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func orDefault(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}
