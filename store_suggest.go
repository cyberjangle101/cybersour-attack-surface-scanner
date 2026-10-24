package main

import "errors"

// Suggestion is a domain the agent thinks may also belong to you. Nothing is scanned until you accept it.
type Suggestion struct {
	Root, Domain, Via, Detail, FirstSeen, Status string
}

// UpsertSuggestion records a suggestion; a dismissed or added one is never reopened. It reports whether it is new.
func (t *Tx) UpsertSuggestion(root, domain, via, detail, now string) (bool, error) {
	isNew, err := t.insertNew(`INSERT OR IGNORE INTO suggestions(root,domain,via,detail,first_seen,status) VALUES(?,?,?,?,?,'new')`, root, domain, via, detail, now)
	if err != nil || isNew {
		return isNew, err
	}
	_, err = t.tx.Exec(`UPDATE suggestions SET via=?, detail=? WHERE root=? AND domain=? AND status='new'`, via, detail, root, domain)
	return false, err
}

// ListSuggestions returns the suggestions for a root ("" = all) with the given status.
func (s *Store) ListSuggestions(root, status string) ([]Suggestion, error) {
	q, args := `SELECT root,domain,via,detail,first_seen,status FROM suggestions WHERE status=?`, []any{status}
	if root != "" {
		q += ` AND root=?`
		args = append(args, root)
	}
	rows, err := s.db.Query(q+` ORDER BY first_seen DESC, domain`, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Suggestion
	for rows.Next() {
		var g Suggestion
		if err := rows.Scan(&g.Root, &g.Domain, &g.Via, &g.Detail, &g.FirstSeen, &g.Status); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// SetSuggestion marks a suggestion added or dismissed.
func (s *Store) SetSuggestion(root, domain, status string) error {
	if status != "added" && status != "dismissed" && status != "new" {
		return errors.New("bad status")
	}
	res, err := s.db.Exec(`UPDATE suggestions SET status=? WHERE root=? AND domain=?`, status, root, domain)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("no such suggestion")
	}
	return nil
}
