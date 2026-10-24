package main

import (
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // G505: SHA-1 is what STIX/RFC 4122 name-based (v5) UUIDs are defined to use; not a security use
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The integration API: read-only JSON for scripts and SIEM/ticketing tools, plus STIX 2.1 and SARIF 2.1
// exports. It is authenticated only by bearer tokens (never by the browser session cookie), so it cannot
// be driven by a malicious web page, and a token can never do more than the account that owns it.

const tokenPrefix = "easm_"

// newToken makes a 256-bit random API token.
func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return tokenPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// apiFinding is the one shape of a finding used by the API, report.json, SARIF and STIX. Field names match findings.csv.
type apiFinding struct {
	ID        int64  `json:"id"`
	Severity  string `json:"severity"`
	Type      string `json:"type"`
	Title     string `json:"title"`
	Target    string `json:"target"`
	Host      string `json:"host"`
	Detail    string `json:"detail"`
	Source    string `json:"source"`
	Risk      string `json:"risk"`
	Solution  string `json:"solution"`
	Status    string `json:"status"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
	Key       string `json:"key"`

	ScanSeverity  string `json:"scan_severity,omitempty"`
	AcceptReason  string `json:"accept_reason,omitempty"`
	AcceptBy      string `json:"accept_by,omitempty"`
	AcceptUntil   string `json:"accept_until,omitempty"`
	SeverityNote  string `json:"severity_reason,omitempty"`
	SeverityBy    string `json:"severity_by,omitempty"`
	SeverityIsSet bool   `json:"severity_overridden"`
}

func apiFindings(in []Finding) []apiFinding {
	out := make([]apiFinding, 0, len(in))
	for _, f := range in {
		i := describeFinding(f)
		a := apiFinding{ID: f.ID, Severity: f.Severity, Type: f.Kind, Title: i.Title, Target: f.Root, Host: f.Host, Detail: f.Detail,
			Source: i.Source, Risk: i.Risk, Solution: i.Solution, Status: f.Status, FirstSeen: f.FirstSeen, LastSeen: f.LastSeen, Key: f.Key,
			SeverityIsSet: f.SevOverride != ""}
		if f.SevOverride != "" {
			a.ScanSeverity, a.SeverityNote, a.SeverityBy = f.ScanSev, f.SevReason, f.SevBy
		}
		if f.Status == "ack" {
			a.AcceptReason, a.AcceptBy, a.AcceptUntil = f.AckReason, f.AckBy, f.AckUntil
		}
		out = append(out, a)
	}
	return out
}

// ---------------------------------------------------------------- authentication

type apiHandler func(w http.ResponseWriter, r *http.Request, who *apiWho)

type apiWho struct {
	User  *User
	Token *APIToken
	Role  string // the lower of the token's role and the owner's current role
}

func apiError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer realm="easm"`)
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func apiJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// api wraps an endpoint with bearer-token authentication and the minimum role it needs.
func (s *Server) api(need int, h apiHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		if s.throttled(ip) {
			apiError(w, http.StatusTooManyRequests, "too many failed attempts; try again later")
			return
		}
		auth := r.Header.Get("Authorization")
		tok, ok := strings.CutPrefix(auth, "Bearer ")
		tok = strings.TrimSpace(tok)
		if !ok || !strings.HasPrefix(tok, tokenPrefix) || len(tok) > 200 {
			s.recordFail(ip)
			apiError(w, http.StatusUnauthorized, "send the header  Authorization: Bearer <token>")
			return
		}
		t, u, err := s.store.TokenByPlain(tok)
		if err != nil {
			s.recordFail(ip)
			s.log.Warn("API token rejected", "ip", ip, "reason", err.Error())
			apiError(w, http.StatusUnauthorized, "the token is not valid, or has expired or been revoked")
			return
		}
		s.mu.Lock()
		delete(s.fails, ip)
		s.mu.Unlock()
		role := t.Role
		if roleLevel(u.Role) < roleLevel(role) {
			role = u.Role // an account that has been demoted takes its tokens down with it
		}
		if roleLevel(role) < need {
			apiError(w, http.StatusForbidden, "this token's role does not allow that")
			return
		}
		s.store.TouchToken(t.ID)
		h(w, r, &apiWho{User: u, Token: t, Role: role})
	}
}

// ---------------------------------------------------------------- endpoints

func qInt(r *http.Request, name string, def, lo, hi int) int {
	n, err := strconv.Atoi(r.URL.Query().Get(name))
	if err != nil || n < lo {
		return def
	}
	if n > hi {
		return hi
	}
	return n
}

// apiFindingsFor lists findings for ?target=&status=open|ack|all&severity=
func (s *Server) apiFindingsFor(r *http.Request) ([]Finding, error) {
	q := r.URL.Query()
	status := q.Get("status")
	switch status {
	case "", "open":
		status = "open"
	case "all":
		status = ""
	case "ack", "resolved":
	default:
		return nil, fmt.Errorf("status must be open, ack, resolved or all")
	}
	all, err := s.store.ListFindings(q.Get("target"), status)
	if err != nil {
		return nil, err
	}
	if floor := q.Get("severity"); floor != "" {
		if !validSeverity(floor) {
			return nil, fmt.Errorf("severity must be high, medium, low or info")
		}
		keep := all[:0]
		for _, f := range all {
			if sevRank(f.Severity) >= sevRank(floor) {
				keep = append(keep, f)
			}
		}
		all = keep
	}
	sort.SliceStable(all, func(i, j int) bool {
		if a, b := sevRank(all[i].Severity), sevRank(all[j].Severity); a != b {
			return a > b
		}
		return all[i].ID < all[j].ID
	})
	return all, nil
}

func (s *Server) apiFindingsList(w http.ResponseWriter, r *http.Request, _ *apiWho) {
	fs, err := s.apiFindingsFor(r)
	if err != nil {
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	apiJSON(w, map[string]any{"count": len(fs), "findings": apiFindings(fs)})
}

func (s *Server) apiTargets(w http.ResponseWriter, _ *http.Request, _ *apiWho) {
	rep, err := BuildReport(s.store, "", time.Now().Add(-24*time.Hour), 0)
	if err != nil {
		apiError(w, http.StatusInternalServerError, "could not read targets")
		return
	}
	apiJSON(w, map[string]any{"targets": rep.Targets})
}

func (s *Server) apiEvents(w http.ResponseWriter, r *http.Request, _ *apiWho) {
	q := r.URL.Query()
	days := qInt(r, "days", 7, 1, 3650)
	ev, total, err := s.store.ListEvents(EventFilter{Root: q.Get("target"), Kind: q.Get("type"), MinSeverity: q.Get("severity"),
		Since: time.Now().UTC().AddDate(0, 0, -days).Format(time.RFC3339), Limit: qInt(r, "limit", 200, 1, 1000), Offset: qInt(r, "offset", 0, 0, 1<<30)})
	if err != nil {
		apiError(w, http.StatusInternalServerError, "could not read events")
		return
	}
	apiJSON(w, map[string]any{"total": total, "count": len(ev), "events": ev})
}

func (s *Server) apiAssets(w http.ResponseWriter, r *http.Request, _ *apiWho) {
	q := r.URL.Query()
	rows, total, err := s.store.Inventory(q.Get("target"), q.Get("q"), qInt(r, "limit", 500, 1, 5000))
	if err != nil {
		apiError(w, http.StatusInternalServerError, "could not read assets")
		return
	}
	apiJSON(w, map[string]any{"total": total, "count": len(rows), "assets": rows})
}

func (s *Server) apiScan(w http.ResponseWriter, r *http.Request, who *apiWho) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var in struct {
		Target  string `json:"target"`
		Refresh bool   `json:"refresh"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Target == "" {
		apiError(w, http.StatusBadRequest, `send JSON like {"target":"example.com"}`)
		return
	}
	ts, err := s.store.ListTargets()
	if err != nil {
		apiError(w, http.StatusInternalServerError, "could not read targets")
		return
	}
	for _, t := range ts {
		if !strings.EqualFold(t.Domain, in.Target) {
			continue
		}
		ok, err := s.store.RequestScan(t.ID)
		if err == nil && ok && in.Refresh {
			err = s.store.SetRefresh(t.Domain, true)
		}
		if err != nil {
			apiError(w, http.StatusInternalServerError, "could not queue the scan")
			return
		}
		if !ok {
			apiError(w, http.StatusConflict, "a scan is already running, or the target is paused")
			return
		}
		s.eng.Wake()
		s.auditAs(who.User.Username, who.User.Kind, r, "scan.api", t.Domain, "token "+who.Token.Name)
		w.WriteHeader(http.StatusAccepted)
		apiJSON(w, map[string]string{"status": "queued", "target": t.Domain})
		return
	}
	apiError(w, http.StatusNotFound, "no such target")
}

func (s *Server) apiSARIF(w http.ResponseWriter, r *http.Request, _ *apiWho) {
	fs, err := s.apiFindingsFor(r)
	if err != nil {
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/sarif+json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(buildSARIF(apiFindings(fs)))
}

func (s *Server) apiSTIX(w http.ResponseWriter, r *http.Request, _ *apiWho) {
	fs, err := s.apiFindingsFor(r)
	if err != nil {
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/stix+json;version=2.1")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(buildSTIX(apiFindings(fs)))
}

func (s *Server) apiReport(w http.ResponseWriter, r *http.Request, who *apiWho) {
	days := qInt(r, "days", 30, 1, 3650)
	rep, err := BuildReport(s.store, r.URL.Query().Get("target"), time.Now().Add(-time.Duration(days)*24*time.Hour), 20000)
	if err != nil {
		apiError(w, http.StatusInternalServerError, "could not build the report")
		return
	}
	if who != nil && who.User != nil {
		rep.PreparedBy = PreparedBy(&Session{Username: who.User.Username, Role: who.Role}) + " via API"
	}
	apiJSON(w, rep)
}

// ---------------------------------------------------------------- SARIF 2.1.0

var sarifLevel = map[string]string{"high": "error", "medium": "warning", "low": "note", "info": "note"}
var sarifScore = map[string]string{"high": "8.0", "medium": "5.5", "low": "3.0", "info": "1.0"}

func buildSARIF(fs []apiFinding) map[string]any {
	rules := []map[string]any{}
	seen := map[string]bool{}
	results := []map[string]any{}
	for _, f := range fs {
		if !seen[f.Type] {
			seen[f.Type] = true
			rules = append(rules, map[string]any{
				"id": f.Type, "name": f.Type,
				"shortDescription":     map[string]string{"text": f.Title},
				"fullDescription":      map[string]string{"text": f.Risk},
				"help":                 map[string]string{"text": f.Solution},
				"defaultConfiguration": map[string]string{"level": sarifLevel[f.Severity]},
			})
		}
		res := map[string]any{
			"ruleId":  f.Type,
			"level":   sarifLevel[f.Severity],
			"message": map[string]string{"text": f.Title + ": " + f.Detail},
			"locations": []map[string]any{{"logicalLocations": []map[string]string{
				{"name": f.Host, "fullyQualifiedName": f.Host, "kind": "resource"}}}},
			"partialFingerprints": map[string]string{"easmKey/v1": f.Key},
			"properties": map[string]any{"security-severity": sarifScore[f.Severity], "severity": f.Severity, "target": f.Target,
				"first_seen": f.FirstSeen, "last_seen": f.LastSeen, "status": f.Status},
		}
		if f.Status == "ack" {
			res["suppressions"] = []map[string]string{{"kind": "external", "status": "accepted", "justification": f.AcceptReason}}
		}
		results = append(results, res)
	}
	return map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]any{{
			"tool":    map[string]any{"driver": map[string]any{"name": "EASM Agent", "version": version, "rules": rules}},
			"results": results,
		}},
	}
}

// ---------------------------------------------------------------- STIX 2.1

// stixNS is the fixed namespace for the agent's deterministic ids (a random v4 UUID, chosen once).
var stixNS = [16]byte{0x6c, 0x1d, 0x0e, 0x5a, 0x91, 0x32, 0x4b, 0x7f, 0x8a, 0x44, 0x2d, 0xe1, 0x73, 0x0b, 0x59, 0xc6}

// uuid5 makes a name-based UUID (RFC 4122 v5) so repeated exports give the same ids.
func uuid5(name string) string {
	h := sha1.New() //nolint:gosec // see import note // nosemgrep: go.lang.security.audit.crypto.use_of_weak_crypto.use-of-sha1 -- RFC 4122 v5 UUIDs are defined with SHA-1; not a security use
	h.Write(stixNS[:])
	h.Write([]byte(name))
	b := h.Sum(nil)[:16]
	b[6] = b[6]&0x0f | 0x50
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func stixTime(s, fallback string) string {
	for _, v := range []string{s, fallback} {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			return t.UTC().Format("2006-01-02T15:04:05.000Z")
		}
	}
	return time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
}

// buildSTIX describes each affected host as an infrastructure object that "has" a vulnerability object
// (one per finding), with the host name as a domain-name observable.
func buildSTIX(fs []apiFinding) map[string]any {
	now := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	identity := "identity--" + uuid5("identity:easm-agent")
	objs := []map[string]any{{"type": "identity", "spec_version": "2.1", "id": identity, "created": "2026-01-01T00:00:00.000Z", "modified": "2026-01-01T00:00:00.000Z",
		"name": "EASM Agent " + version, "identity_class": "system"}}
	haveHost := map[string]bool{}
	for _, f := range fs {
		infra := "infrastructure--" + uuid5("infra:"+f.Host)
		if !haveHost[f.Host] {
			haveHost[f.Host] = true
			dn := "domain-name--" + uuid5("dn:"+f.Host)
			objs = append(objs,
				map[string]any{"type": "infrastructure", "spec_version": "2.1", "id": infra, "created": stixTime(f.FirstSeen, ""), "modified": now,
					"created_by_ref": identity, "name": f.Host, "infrastructure_types": []string{"unknown"}},
				map[string]any{"type": "domain-name", "spec_version": "2.1", "id": dn, "value": f.Host},
				map[string]any{"type": "relationship", "spec_version": "2.1", "id": "relationship--" + uuid5("rel:consists:"+f.Host), "created": now, "modified": now,
					"created_by_ref": identity, "relationship_type": "consists-of", "source_ref": infra, "target_ref": dn})
		}
		vuln := "vulnerability--" + uuid5("vuln:"+f.Key)
		created := stixTime(f.FirstSeen, "")
		v := map[string]any{"type": "vulnerability", "spec_version": "2.1", "id": vuln, "created": created, "modified": stixTime(f.LastSeen, f.FirstSeen),
			"created_by_ref": identity, "name": f.Title, "description": f.Detail + "\n\nWhy it matters: " + f.Risk + "\n\nWhat to do: " + f.Solution,
			"labels":          []string{"easm", "severity-" + f.Severity},
			"x_easm_severity": f.Severity, "x_easm_status": f.Status, "x_easm_target": f.Target, "x_easm_type": f.Type, "x_easm_host": f.Host}
		if strings.HasPrefix(f.Detail, "CVE-") {
			id := strings.Fields(f.Detail)[0]
			v["external_references"] = []map[string]string{{"source_name": "cve", "external_id": strings.TrimRight(id, ":,;.")}}
		}
		objs = append(objs, v,
			map[string]any{"type": "relationship", "spec_version": "2.1", "id": "relationship--" + uuid5("rel:has:"+f.Key), "created": now, "modified": now,
				"created_by_ref": identity, "relationship_type": "has", "source_ref": infra, "target_ref": vuln})
	}
	return map[string]any{"type": "bundle", "id": "bundle--" + uuid5(fmt.Sprintf("bundle:%d", time.Now().UnixNano())), "objects": objs}
}
