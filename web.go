package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

//go:embed web
var webFS embed.FS

const (
	sessionCookie = "easm_session"
	csrfCookie    = "easm_csrf"
	sessionIdle   = 12 * time.Hour
	maxFormBytes  = 1 << 20
	pageSize      = 100
)

// Flash is a one-shot message shown on the next page.
type Flash struct{ Kind, Text string }

// Session is a signed-in browser session.
type Session struct {
	Kind        string // "local" or "ad"
	UserID      int64
	Username    string
	Role        string
	CSRF        string
	Expires     time.Time
	Flash       *Flash
	Reveal      string   // a new API token, shown once on the account page
	Codes       []string // new recovery codes, shown once
	Need2FA     bool     // must enrol in two-factor before using anything else
	PendingTOTP string   // secret being enrolled, not yet confirmed
}

type failRec struct {
	count   int
	first   time.Time
	last    time.Time
	blocked time.Time
}

// Server is the web interface.
type Server struct {
	adg     adGuard
	pending pendingLogins
	store   *Store
	eng     *Engine
	log     *slog.Logger
	boot    *Bootstrap
	tpl     map[string]*template.Template

	mu       sync.Mutex
	setupMu  sync.Mutex
	setup    setupGate // the one-time code that guards first-administrator setup (setup_code.go)
	sessions map[string]*Session
	fails    map[string]*failRec
	secure   bool
	hmu      sync.RWMutex
	hosts    map[string]bool        // allowed Host headers (loopback binds); nil = no check
	listen   ListenControl          // changes the listen address at run time (nil in tests)
	certs    CertControl            // shows and replaces the web server certificate (nil when a certificate is configured by file, and in tests)
	stop     func()                 // shuts down an interactive run from System health (nil under a service manager and in tests)
	restart  func()                 // after an update: starts the new program and stops this one (nil: restart by hand)
	exePath  func() (string, error) // the program file an update replaces (tests point it at a temp file)

	dummyHash []byte
}

var userRe = regexp.MustCompile(`^[A-Za-z0-9._-]{3,32}$`)

// NewServer builds the web interface: templates, routes, security headers and session handling.
func NewServer(store *Store, eng *Engine, log *slog.Logger, boot *Bootstrap) (*Server, error) {
	s := &Server{store: store, eng: eng, log: log, boot: boot, sessions: map[string]*Session{}, fails: map[string]*failRec{},
		secure: boot.UsesTLS() || boot.SecureCookies}
	h, _ := bcrypt.GenerateFromPassword([]byte("dummy-password-for-timing"), bcrypt.DefaultCost)
	s.dummyHash = h

	if _, _, err := net.SplitHostPort(boot.Listen); err != nil {
		return nil, fmt.Errorf("listen address: %w", err)
	}
	s.hosts = buildAllowedHosts(boot.Listen, boot.AllowedHosts)

	funcs := template.FuncMap{
		"ts": fmtTS, "ago": agoStr, "until": untilStr,
		"sevClass":  func(s string) string { return "sev-" + strings.ToLower(s) },
		"upper":     strings.ToUpper,
		"hasPrefix": strings.HasPrefix,
		"finfo":     describeFinding,
		"roleLabel": roleLabel,
		"tctx": func(f Finding, csrf, next string, admin bool) map[string]any {
			return map[string]any{"F": f, "CSRF": csrf, "Next": next, "Admin": admin}
		},
		"verifyLabel": verifyLabel,
		"trustLabel":  trustLabel,
		"thirdParty":  func(kind string) bool { return thirdPartyKinds[kind] },
		"add":    func(a, b int) int { return a + b },
		"sub":    func(a, b int) int { return a - b },
		"join":   strings.Join,
		"lines":  func(in []string) string { return strings.Join(in, "\n") },
		"asns":   joinInts,
		"hasKey": func(m map[string]int, k string) int { return m[k] },
		// href builds a link from a path and an already-encoded query. html/template would
		// otherwise percent-encode the "=" and "&" inside a query placed after "?". The result is
		// a plain string so html/template still normalizes it and checks the scheme.
		"href": func(path, query string, extra ...string) string {
			if len(extra) > 0 {
				if query != "" {
					query += "&"
				}
				query += strings.Join(extra, "&")
			}
			if query == "" {
				return path
			}
			return path + "?" + query
		},
		"hint":  Hint,
		"donut": donutSVG, "legend": legendHTML, "trend": trendSVG, "hbar": hbarSVG, "catBars": categoryBars, "assetBars": assetBars,
		"tsec": func(t time.Time) string { return t.Local().Format("2006-01-02 15:04:05") },
		"seq": func(n int) []int {
			out := make([]int, n)
			for i := range out {
				out[i] = i + 1
			}
			return out
		},
	}
	s.tpl = map[string]*template.Template{}
	pages := []string{"login", "setup", "dashboard", "guide", "targets", "target_delete", "target", "findings", "evidence", "events", "assets", "asset", "health", "report", "settings", "users", "account", "error", "moved", "audit", "ad", "channels", "login2fa", "twofactor"}
	for _, p := range pages {
		t, err := template.New(p).Funcs(funcs).ParseFS(webFS, "web/templates/layout.html", "web/templates/progress.html", "web/templates/triage.html", "web/templates/targetstable.html", "web/templates/"+p+".html")
		if err != nil {
			return nil, fmt.Errorf("template %s: %w", p, err)
		}
		s.tpl[p] = t
	}
	if _, err := s.prepareSetupCode(); err != nil {
		return nil, err
	}
	return s, nil
}

// ---------------------------------------------------------------- template helpers

// fmtTS formats an RFC3339 timestamp in local time.
func fmtTS(s string) string {
	if s == "" {
		return "—"
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return s
	}
	return t.Local().Format("2006-01-02 15:04")
}

// humanDur formats a duration like "3h 5m".
func humanDur(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "moments"
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

func agoStr(s string) string {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return "never"
	}
	return humanDur(time.Since(t)) + " ago"
}

// untilStr says how long until a timestamp ("in 5m", "overdue").
func untilStr(s string) string {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return "—"
	}
	if d := time.Until(t); d > 0 {
		return "in " + humanDur(d)
	}
	return "due now"
}

// ---------------------------------------------------------------- routing & middleware

// authed is a handler that receives the signed-in session.
type authed func(http.ResponseWriter, *http.Request, *Session)

// Handler returns the routed, hardened HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	staticFS, _ := fs.Sub(webFS, "web/static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", noDirListing(http.FileServer(http.FS(staticFS)))))
	mux.Handle("POST /csp-report", &cspReports{log: s.log})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = fmt.Fprintln(w, "ok") })

	mux.HandleFunc("GET /setup", s.setupForm)
	mux.HandleFunc("POST /setup", s.setupSubmit)
	mux.HandleFunc("GET /login", s.loginForm)
	mux.HandleFunc("POST /login", s.loginSubmit)
	mux.HandleFunc("POST /login/2fa", s.login2FA)
	mux.HandleFunc("POST /logout", s.auth(permView, s.logout))

	mux.HandleFunc("GET /{$}", s.auth(permView, s.dashboard))
	mux.HandleFunc("GET /assets/view", s.auth(permView, s.assetDetail))
	mux.HandleFunc("GET /shots", s.auth(permView, s.shotView))
	mux.HandleFunc("GET /progress.json", s.auth(permView, s.progressJSON))
	mux.HandleFunc("GET /guide", s.auth(permView, s.guideView))
	mux.HandleFunc("POST /guide/dismiss", s.auth(permView, s.guideDismiss))
	mux.HandleFunc("GET /targets", s.auth(permView, s.targetList))
	mux.HandleFunc("POST /targets", s.auth(permAdmin, s.targetAdd))
	mux.HandleFunc("GET /targets/{id}/delete", s.auth(permAdmin, s.targetDeleteConfirm))
	mux.HandleFunc("GET /targets/{id}", s.auth(permView, s.targetView))
	mux.HandleFunc("POST /targets/{id}/edit", s.auth(permAdmin, s.targetEdit))
	mux.HandleFunc("POST /targets/{id}/scan", s.auth(permTriage, s.targetScan))
	mux.HandleFunc("POST /targets/{id}/suggestions/accept", s.auth(permAdmin, s.suggestionAccept))
	mux.HandleFunc("POST /targets/{id}/suggestions/dismiss", s.auth(permTriage, s.suggestionDismiss))
	mux.HandleFunc("POST /targets/{id}/pause", s.auth(permTriage, s.targetPause))
	mux.HandleFunc("POST /targets/{id}/resume", s.auth(permTriage, s.targetResume))
	mux.HandleFunc("POST /targets/{id}/delete", s.auth(permAdmin, s.targetDelete))

	mux.HandleFunc("GET /findings", s.auth(permView, s.findings))
	mux.HandleFunc("POST /findings/{id}/ack", s.auth(permTriage, s.findingAccept))
	mux.HandleFunc("POST /findings/{id}/reopen", s.auth(permTriage, s.findingReopen))
	mux.HandleFunc("POST /findings/{id}/severity", s.auth(permTriage, s.findingSeverity))
	mux.HandleFunc("POST /findings/{id}/verify", s.auth(permAdmin, s.findingVerify))
	mux.HandleFunc("POST /findings/{id}/confirm", s.auth(permTriage, s.findingConfirm))
	mux.HandleFunc("GET /findings/{id}/evidence", s.auth(permView, s.findingEvidence))
	mux.HandleFunc("GET /findings/{id}/evidence.json", s.auth(permView, s.findingEvidenceJSON))
	mux.HandleFunc("GET /events", s.auth(permView, s.events))
	mux.HandleFunc("GET /assets", s.auth(permView, s.assets))
	mux.HandleFunc("GET /assets.csv", s.auth(permView, s.assetsCSV))
	mux.HandleFunc("GET /health", s.auth(permView, s.healthView))
	mux.HandleFunc("POST /health/check", s.auth(permTriage, s.healthCheck))
	mux.HandleFunc("POST /system/stop", s.auth(permAdmin, s.stopAgent))
	mux.HandleFunc("POST /system/key/recovery", s.auth(permAdmin, s.keyRecovery))
	mux.HandleFunc("POST /system/key/windows", s.auth(permAdmin, s.keyWindows))
	mux.HandleFunc("POST /system/update/check", s.auth(permAdmin, s.updateCheck))
	mux.HandleFunc("POST /system/update/install", s.auth(permAdmin, s.updateInstall))

	mux.HandleFunc("GET /report", s.auth(permView, s.report))
	mux.HandleFunc("GET /report/inventory.csv", s.auth(permView, s.reportCSV("inventory")))
	mux.HandleFunc("GET /report/findings.csv", s.auth(permView, s.reportCSV("findings")))
	mux.HandleFunc("GET /report.json", s.auth(permView, s.reportJSON))
	mux.HandleFunc("GET /report.pdf", s.auth(permView, s.reportPDF))

	mux.HandleFunc("GET /settings", s.auth(permAdmin, s.settingsView))
	mux.HandleFunc("POST /settings", s.auth(permAdmin, s.settingsSave))
	mux.HandleFunc("POST /settings/listen", s.auth(permAdmin, s.settingsListen))
	mux.HandleFunc("POST /settings/backup", s.auth(permAdmin, s.backupSave))
	mux.HandleFunc("POST /settings/backup/now", s.auth(permAdmin, s.backupNow))
	mux.HandleFunc("POST /settings/backup/download", s.auth(permAdmin, s.backupDownload))
	mux.HandleFunc("POST /settings/certificate", s.auth(permAdmin, s.certUpload))
	mux.HandleFunc("POST /settings/certificate/remove", s.auth(permAdmin, s.certRemove))
	mux.HandleFunc("POST /settings/test-email", s.auth(permAdmin, s.settingsTestEmail))
	mux.HandleFunc("POST /settings/digest-now", s.auth(permAdmin, s.settingsDigestNow))

	mux.HandleFunc("GET /users", s.auth(permAdmin, s.usersView))
	mux.HandleFunc("POST /users", s.auth(permAdmin, s.userAdd))
	mux.HandleFunc("POST /users/{id}/delete", s.auth(permAdmin, s.userDelete))
	mux.HandleFunc("POST /users/{id}/password", s.auth(permAdmin, s.userSetPassword))
	mux.HandleFunc("GET /settings/ad", s.auth(permAdmin, s.adView))
	mux.HandleFunc("POST /settings/ad", s.auth(permAdmin, s.adSave))
	mux.HandleFunc("POST /settings/ad/test", s.auth(permAdmin, s.adTest))
	mux.HandleFunc("GET /settings/channels", s.auth(permAdmin, s.channelsView))
	mux.HandleFunc("POST /settings/channels", s.auth(permAdmin, s.channelAdd))
	mux.HandleFunc("POST /settings/channels/{id}/test", s.auth(permAdmin, s.channelTest))
	mux.HandleFunc("POST /settings/channels/{id}/toggle", s.auth(permAdmin, s.channelToggle))
	mux.HandleFunc("POST /settings/channels/{id}/delete", s.auth(permAdmin, s.channelDelete))
	mux.HandleFunc("POST /users/ad", s.auth(permAdmin, s.userAddAD))
	mux.HandleFunc("POST /users/{id}/role", s.auth(permAdmin, s.userSetRole))
	mux.HandleFunc("POST /users/{id}/disable", s.auth(permAdmin, s.userDisable))
	mux.HandleFunc("GET /audit", s.auth(permAdmin, s.auditView))
	mux.HandleFunc("GET /audit.csv", s.auth(permAdmin, s.auditCSV))
	mux.HandleFunc("GET /account", s.auth(permView, s.accountView))
	mux.HandleFunc("POST /account/password", s.auth(permView, s.accountPassword))
	mux.HandleFunc("GET /account/2fa", s.auth(permView, s.twoFactorView))
	mux.HandleFunc("POST /account/2fa/enable", s.auth(permView, s.twoFactorEnable))
	mux.HandleFunc("POST /account/2fa/disable", s.auth(permView, s.twoFactorDisable))
	mux.HandleFunc("POST /account/2fa/recovery", s.auth(permView, s.twoFactorRecovery))
	mux.HandleFunc("POST /users/{id}/reset2fa", s.auth(permAdmin, s.userReset2FA))
	mux.HandleFunc("POST /account/tokens", s.auth(permView, s.tokenCreate))
	mux.HandleFunc("POST /account/tokens/{id}/revoke", s.auth(permView, s.tokenRevoke))
	mux.HandleFunc("GET /report/findings.sarif", s.auth(permView, s.reportSARIF))
	mux.HandleFunc("GET /report/findings.stix.json", s.auth(permView, s.reportSTIX))

	mux.HandleFunc("GET /api/v1/targets", s.api(permView, s.apiTargets))
	mux.HandleFunc("GET /api/v1/findings", s.api(permView, s.apiFindingsList))
	mux.HandleFunc("GET /api/v1/events", s.api(permView, s.apiEvents))
	mux.HandleFunc("GET /api/v1/assets", s.api(permView, s.apiAssets))
	mux.HandleFunc("GET /api/v1/report", s.api(permView, s.apiReport))
	mux.HandleFunc("GET /api/v1/export/sarif", s.api(permView, s.apiSARIF))
	mux.HandleFunc("GET /api/v1/export/stix", s.api(permView, s.apiSTIX))
	mux.HandleFunc("POST /api/v1/scan", s.api(permTriage, s.apiScan))

	return s.secureHeaders(s.hostCheck(mux))
}

// secureHeaders wraps h with CSP, framing, content-type and Host-header protections.
func (s *Server) secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		setSecurityHeaders(h, s.secure)
		if !strings.HasPrefix(r.URL.Path, "/static/") {
			h.Set("Cache-Control", "no-store")
		}
		if s.secure {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

// hostCheck defends a loopback-bound UI against DNS-rebinding: requests must carry a known Host header.
func (s *Server) hostCheck(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hmu.RLock()
		hosts := s.hosts
		s.hmu.RUnlock()
		if hosts != nil {
			host := r.Host
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
			host = strings.Trim(strings.ToLower(host), "[]")
			if !hosts[host] {
				http.Error(w, "unrecognised Host header", http.StatusMisdirectedRequest)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func clientIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

func randToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// newSession creates a session and its CSRF token.
func (s *Server) newSession(w http.ResponseWriter, u *User) *Session {
	tok := randToken(32)
	sess := &Session{Kind: u.Kind, UserID: u.ID, Username: u.Username, Role: u.Role, CSRF: randToken(16), Expires: time.Now().Add(sessionIdle)}
	s.mu.Lock()
	// opportunistic cleanup
	for k, v := range s.sessions {
		if time.Now().After(v.Expires) {
			delete(s.sessions, k)
		}
	}
	s.sessions[tok] = sess
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: tok, Path: "/", HttpOnly: true, Secure: s.secure, // nosemgrep: go.lang.security.audit.net.cookie-missing-secure.cookie-missing-secure -- Secure is on whenever the UI is served over TLS; plain-HTTP mode could not send it back
		SameSite: http.SameSiteStrictMode, MaxAge: int(sessionIdle.Seconds())})
	return sess
}

// lookupSession finds a valid, unexpired session from the cookie.
func (s *Server) lookupSession(r *http.Request) *Session {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := s.sessions[c.Value]
	if sess == nil {
		return nil
	}
	if time.Now().After(sess.Expires) {
		delete(s.sessions, c.Value)
		return nil
	}
	sess.Expires = time.Now().Add(sessionIdle)
	return sess
}

// dropSessionsFor ends every session of a user.
func (s *Server) dropSessionsFor(userID int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.sessions {
		if v.UserID == userID {
			delete(s.sessions, k)
		}
	}
}

// auth wraps a handler with login, role and CSRF checks.
func (s *Server) auth(need int, h authed) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if n, err := s.store.CountUsers(); err == nil && n == 0 {
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
			return
		}
		sess := s.lookupSession(r)
		if sess == nil {
			if r.Method == http.MethodGet {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
			} else {
				http.Error(w, "session expired; please sign in again", http.StatusUnauthorized)
			}
			return
		}
		if r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
			if err := r.ParseForm(); err != nil {
				http.Error(w, "bad form", http.StatusBadRequest)
				return
			}
			if subtle.ConstantTimeCompare([]byte(r.PostFormValue("csrf")), []byte(sess.CSRF)) != 1 {
				http.Error(w, "invalid CSRF token; reload the page and try again", http.StatusForbidden)
				return
			}
		}
		if sess.Need2FA && !strings.HasPrefix(r.URL.Path, "/account") && r.URL.Path != "/logout" {
			if r.Method == http.MethodGet {
				http.Redirect(w, r, "/account/2fa", http.StatusSeeOther)
			} else {
				http.Error(w, "set up two-factor sign-in first", http.StatusForbidden)
			}
			return
		}
		if roleLevel(sess.Role) < need {
			title, msg := "Administrator access required", "Only administrators can do this."
			if need == permTriage {
				title, msg = "Analyst access required", "Your account is read-only. Ask an administrator for the analyst role to triage findings."
			}
			s.audit(sess, r, "access.denied", r.Method+" "+r.URL.Path, "role "+sess.Role)
			s.renderError(w, r, sess, http.StatusForbidden, title, msg)
			return
		}
		h(w, r, sess)
	}
}

func (s *Server) flash(sess *Session, kind, text string) {
	s.mu.Lock()
	sess.Flash = &Flash{kind, text}
	s.mu.Unlock()
}

// render executes a page template inside the common layout.
func (s *Server) render(w http.ResponseWriter, _ *http.Request, sess *Session, page string, status int, data map[string]any) {
	if data == nil {
		data = map[string]any{}
	}
	data["Version"] = version
	if sess != nil {
		data["User"] = sess.Username
		data["IsAdmin"] = sess.Role == RoleAdmin
		data["CanTriage"] = roleLevel(sess.Role) >= permTriage
		data["RoleLabel"] = roleLabel(sess.Role)
		data["CSRF"] = sess.CSRF
		s.mu.Lock()
		data["Flash"] = sess.Flash
		sess.Flash = nil
		s.mu.Unlock()
		data["Scanning"] = s.eng.Current()
		if sess.Role == RoleAdmin {
			if u := s.eng.UpdateState(); u.Available && u.Latest != nil {
				data["UpdateBanner"] = u.Latest.Version
			}
		}
	}
	var buf bytes.Buffer
	if err := s.tpl[page].ExecuteTemplate(&buf, "layout", data); err != nil {
		s.log.Error("template render failed", "page", page, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes()) // nosemgrep: no-direct-write-to-responsewriter -- output of html/template (auto-escaped)
}

func (s *Server) renderError(w http.ResponseWriter, r *http.Request, sess *Session, status int, title, msg string) {
	s.render(w, r, sess, "error", status, map[string]any{"Title": title, "Message": msg, "Status": status})
}

func (s *Server) serverError(w http.ResponseWriter, r *http.Request, sess *Session, err error) {
	s.log.Error("request failed", "path", r.URL.Path, "err", err)
	s.renderError(w, r, sess, http.StatusInternalServerError, "Something went wrong", "The error was logged. Please try again.")
}

// safeNext returns next only when it is a plain same-site path ("/findings?x=1");
// anything that a browser could read as another site falls back to def.
func safeNext(next, def string) string {
	// Browsers drop tabs and newlines inside URLs, so "/<TAB>/evil.example" would
	// become "//evil.example" (an off-site redirect), and they treat "\" like "/".
	// Reject every control character and every backslash up front.
	for _, c := range next {
		if c < 0x20 || c == 0x7f || c == '\\' {
			return def
		}
	}
	// "//host" and "/\host" are protocol-relative URLs to another site. The backslash
	// is already refused above; it is repeated here so the check reads (and is
	// recognised by CodeQL) as one complete same-site test.
	if len(next) == 0 || next[0] != '/' || (len(next) > 1 && (next[1] == '/' || next[1] == '\\')) {
		return def
	}
	// Belt and braces: after parsing it must still have no scheme and no host.
	u, err := url.Parse(next)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || !strings.HasPrefix(u.Path, "/") {
		return def
	}
	return next
}

func pathID(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id, err == nil && id > 0
}

// ---------------------------------------------------------------- pre-auth: setup & login

func (s *Server) preCSRF(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(csrfCookie); err == nil && len(c.Value) == 32 {
		return c.Value
	}
	tok := randToken(16)
	http.SetCookie(w, &http.Cookie{Name: csrfCookie, Value: tok, Path: "/", HttpOnly: true, Secure: s.secure, SameSite: http.SameSiteStrictMode}) // nosemgrep: go.lang.security.audit.net.cookie-missing-secure.cookie-missing-secure -- Secure follows TLS, see newSession
	return tok
}

func (s *Server) checkPreCSRF(r *http.Request) bool {
	c, err := r.Cookie(csrfCookie)
	if err != nil {
		return false
	}
	_ = r.ParseForm()
	return subtle.ConstantTimeCompare([]byte(c.Value), []byte(r.PostFormValue("csrf"))) == 1
}

// validatePassword enforces the password length rules.
func validatePassword(pw string) error {
	if len(pw) < 10 {
		return errors.New("password must be at least 10 characters")
	}
	if len(pw) > 72 {
		return errors.New("password must be at most 72 bytes")
	}
	return nil
}

func hashPassword(pw string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(h), err
}

func (s *Server) setupForm(w http.ResponseWriter, r *http.Request) {
	if n, _ := s.store.CountUsers(); n > 0 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.render(w, r, nil, "setup", http.StatusOK, map[string]any{"Title": "Welcome", "PreCSRF": s.preCSRF(w, r)})
}

// setupSubmit creates the first administrator.
func (s *Server) setupSubmit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if !s.checkPreCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	fail := func(msg string) {
		s.render(w, r, nil, "setup", http.StatusBadRequest, map[string]any{"Title": "Welcome", "PreCSRF": s.preCSRF(w, r), "Error": msg, "Username": r.PostFormValue("username")})
	}
	s.setupMu.Lock() // serialise first-user creation
	defer s.setupMu.Unlock()
	if n, _ := s.store.CountUsers(); n > 0 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if !s.setupCodeOK(r.PostFormValue("code")) {
		s.log.Warn("first-administrator setup refused: wrong setup code", "remote", r.RemoteAddr)
		fail("That setup code is not right. It is in " + setupCodeFile + " in the agent's data folder, and it changes every time the agent starts.")
		return
	}
	name, pw := strings.TrimSpace(r.PostFormValue("username")), r.PostFormValue("password")
	if !userRe.MatchString(name) {
		fail("Username must be 3-32 characters: letters, digits, dot, dash or underscore.")
		return
	}
	if err := validatePassword(pw); err != nil {
		fail(strings.ToUpper(err.Error()[:1]) + err.Error()[1:] + ".")
		return
	}
	if pw != r.PostFormValue("confirm") {
		fail("The two passwords do not match.")
		return
	}
	hash, err := hashPassword(pw)
	if err != nil {
		fail("Could not hash the password.")
		return
	}
	id, err := s.store.CreateUser(name, hash, "admin")
	if err != nil {
		fail(err.Error())
		return
	}
	s.finishSetup()
	s.log.Info("first administrator created", "user", name)
	u, _ := s.store.GetUser(id)
	sess := s.newSession(w, u)
	s.flash(sess, "good", "Welcome! Add the first domain you want to monitor below.")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// loginForm shows the sign-in page.
func (s *Server) loginForm(w http.ResponseWriter, r *http.Request) {
	if n, _ := s.store.CountUsers(); n == 0 {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	if s.lookupSession(r) != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.render(w, r, nil, "login", http.StatusOK, map[string]any{"Title": "Sign in", "PreCSRF": s.preCSRF(w, r)})
}

// loginSubmit checks credentials in constant time and starts a session.
func (s *Server) loginSubmit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if !s.checkPreCSRF(r) {
		http.Error(w, "invalid CSRF token; reload the page", http.StatusForbidden)
		return
	}
	ip := clientIP(r)
	again := func(status int, msg string) {
		s.render(w, r, nil, "login", status, map[string]any{"Title": "Sign in", "PreCSRF": s.preCSRF(w, r), "Error": msg, "Username": r.PostFormValue("username")})
	}
	typed := strings.TrimSpace(r.PostFormValue("username"))
	keys := signInKeys(ip, typed)
	if s.throttled(keys) {
		again(http.StatusTooManyRequests, "Too many failed attempts. Try again in a few minutes.")
		return
	}
	u, why := s.authenticate(r, typed, r.PostFormValue("password"))
	if u == nil {
		if !why.neutral {
			s.recordFail(keys)
		}
		s.log.Warn("failed sign-in", "ip", ip)
		s.auditAs(typed, "", r, "login.fail", "", why.audit)
		again(why.status, why.message)
		return
	}
	if u.Kind == kindLocal && u.TOTPOn {
		s.askSecondFactor(w, r, u, "")
		return
	}
	s.finishLogin(w, r, u)
}

// finishLogin starts the session once every required check has passed.
func (s *Server) finishLogin(w http.ResponseWriter, r *http.Request, u *User) {
	ip := clientIP(r)
	s.clearFails(signInKeys(ip, u.Username))
	sess := s.newSession(w, u)
	if st, err := s.store.LoadSettings(); err == nil && st.Require2FA && u.Kind == kindLocal && !u.TOTPOn {
		s.mu.Lock()
		sess.Need2FA = true
		s.mu.Unlock()
	}
	s.store.TouchLogin(u.ID)
	s.auditAs(u.Username, u.Kind, r, "login", "", "")
	s.log.Info("user signed in", "user", u.Username, "ip", ip)
	if sess.Need2FA {
		s.flash(sess, "warn", "Your administrator requires two-factor sign-in. Set it up now to continue.")
		http.Redirect(w, r, "/account/2fa", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// logout ends the session.
func (s *Server) logout(w http.ResponseWriter, r *http.Request, sess *Session) {
	s.audit(sess, r, "logout", "", "")
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.mu.Lock()
		delete(s.sessions, c.Value)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.secure, SameSite: http.SameSiteStrictMode}) // nosemgrep: go.lang.security.audit.net.cookie-missing-secure.cookie-missing-secure -- Secure follows TLS, see newSession
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ---------------------------------------------------------------- dashboard & targets

// TargetRow is one dashboard row.
type TargetRow struct {
	T            *Target
	Hosts        int
	Findings     map[string]int
	FindingTotal int
	MaxSev       string
	State        string
	StateClass   string
	Prog         *ScanProgress
	Subdomain    bool // the monitored name is below a registered domain (e.g. www.example.com)
}

// targetState turns scan status into a label and style.
func targetState(t *Target) (string, string) {
	switch {
	case !t.Enabled:
		return "Paused", "muted"
	case t.LastStatus == "running":
		return "Scanning", "info"
	case t.LastStatus == "error":
		return "Error", "bad"
	case t.LastStatus == "interrupted":
		return "Interrupted", "warn"
	case t.LastStatus == "":
		return "Queued", "muted"
	case !t.Baselined():
		return "Baselining", "warn"
	default:
		return "Monitoring", "good"
	}
}

func maxSeverity(m map[string]int) string {
	for _, s := range []string{"high", "medium", "low", "info"} {
		if m[s] > 0 {
			return s
		}
	}
	return ""
}

// targetRows builds the dashboard rows.
func (s *Server) targetRows() ([]TargetRow, error) {
	targets, err := s.store.ListTargets()
	if err != nil {
		return nil, err
	}
	hosts, finds, err := s.store.TargetCounts()
	if err != nil {
		return nil, err
	}
	rows := make([]TargetRow, 0, len(targets))
	for _, t := range targets {
		r := TargetRow{T: t, Hosts: hosts[t.Domain], Findings: finds[t.Domain]}
		for _, c := range r.Findings {
			r.FindingTotal += c
		}
		r.MaxSev = maxSeverity(r.Findings)
		r.State, r.StateClass = targetState(t)
		r.Prog = s.eng.Progress().Get(t.ID)
		r.Subdomain = isSubdomainScope(t.Domain)
		rows = append(rows, r)
	}
	return rows, nil
}

// targetList shows every monitored domain.
func (s *Server) targetList(w http.ResponseWriter, r *http.Request, sess *Session) {
	rows, err := s.targetRows()
	if err != nil {
		s.serverError(w, r, sess, err)
		return
	}
	refresh := 0
	for _, t := range rows {
		if t.State == "Scanning" || t.State == "Queued" {
			refresh = 15
		}
	}
	s.render(w, r, sess, "targets", http.StatusOK, map[string]any{"Title": "Monitored domains", "Nav": "dashboard", "Rows": rows, "Refresh": refresh})
}

// targetDeleteConfirm shows what deleting a domain removes and asks for the domain name to be typed.
func (s *Server) targetDeleteConfirm(w http.ResponseWriter, r *http.Request, sess *Session) {
	t := s.loadTarget(w, r, sess)
	if t == nil {
		return
	}
	c, err := s.store.CountTargetData(t.Domain)
	if err != nil {
		s.serverError(w, r, sess, err)
		return
	}
	s.render(w, r, sess, "target_delete", http.StatusOK, map[string]any{"Title": "Delete " + t.Domain, "Nav": "dashboard", "T": t, "C": c})
}

// dashboard renders the home page.
func (s *Server) dashboard(w http.ResponseWriter, r *http.Request, sess *Session) {
	stats, err := s.store.Stats()
	if err != nil {
		s.serverError(w, r, sess, err)
		return
	}
	rows, err := s.targetRows()
	if err != nil {
		s.serverError(w, r, sess, err)
		return
	}
	scans, err := s.store.ListScans("", 8)
	if err != nil {
		s.serverError(w, r, sess, err)
		return
	}
	settings, _ := s.store.LoadSettings()
	refresh := 0
	for _, t := range rows {
		if t.State == "Scanning" || t.State == "Queued" {
			refresh = 15 // fallback only; the progress bars update themselves every 2s via /progress.json
		}
	}
	form := map[string]string{}
	if v, ok := s.takeForm(sess); ok {
		form = v
	}
	s.render(w, r, sess, "dashboard", http.StatusOK, map[string]any{
		"Title": "Dashboard", "Nav": "dashboard", "Stats": stats, "Rows": rows, "Scans": scans,
		"Settings": settings, "SMTPOff": !settings.SMTPEnabled, "Refresh": refresh, "Form": form,
		"ShowGuide": s.guideWanted(sess),
	})
}

var formStash sync.Map // session CSRF -> map[string]string: re-fill the add form after a validation error

func (s *Server) stashForm(sess *Session, r *http.Request) {
	formStash.Store(sess.CSRF, map[string]string{
		"domain": r.PostFormValue("domain"), "asns": r.PostFormValue("asns"), "keywords": r.PostFormValue("keywords"),
		"ignore": r.PostFormValue("ignore"), "interval": r.PostFormValue("interval"), "notes": r.PostFormValue("notes"),
	})
}

func (s *Server) takeForm(sess *Session) (map[string]string, bool) {
	v, ok := formStash.LoadAndDelete(sess.CSRF)
	if !ok {
		return nil, false
	}
	return v.(map[string]string), true
}

// targetAdd validates and stores a new domain.
func (s *Server) targetAdd(w http.ResponseWriter, r *http.Request, sess *Session) {
	t, err := TargetFromForm(r.PostFormValue("domain"), r.PostFormValue("asns"), r.PostFormValue("keywords"),
		r.PostFormValue("ignore"), r.PostFormValue("interval"), r.PostFormValue("notes"))
	if err == nil {
		var id int64
		if id, err = s.store.AddTarget(t); err == nil {
			opts := s.firstScanOptions(r, t.Domain)
			s.audit(sess, r, "target.add", t.Domain, strings.Join(opts, ", "))
			s.log.Info("target added", "domain", t.Domain, "by", sess.Username, "first_scan", strings.Join(opts, ", "))
			s.eng.Wake()
			msg := fmt.Sprintf("Now monitoring %s. The first scan (baseline) is starting; no alerts are sent for what already exists.", t.Domain)
			if len(opts) > 0 {
				msg += " First scan: " + strings.Join(opts, ", ") + "."
			}
			s.flash(sess, "good", msg)
			if r.PostFormValue("first_shots") == "1" {
				if st, err := s.store.LoadSettings(); err == nil {
					if _, berr := findBrowser(st.ChromePath); berr != nil {
						s.flash(sess, "warn", "Screenshots need Chrome or Edge on this machine and none was found, so the first scan will run without them. Install one, or set its path under Settings → Active checks.")
					}
				}
			}
			if adv := s.scopeAdvice(t.Domain); adv != "" {
				s.flash(sess, "warn", fmt.Sprintf("Now monitoring %s. Note: %s", t.Domain, adv))
			}
			http.Redirect(w, r, "/targets/"+strconv.FormatInt(id, 10), http.StatusSeeOther) // nosemgrep: go.lang.security.injection.open-redirect.open-redirect -- fixed local path plus a database integer id
			return
		}
	}
	s.stashForm(sess, r)
	s.flash(sess, "bad", err.Error())
	http.Redirect(w, r, "/#add", http.StatusSeeOther)
}

// firstScanOptions applies the "First scan" boxes of the add form as one-shot
// requests for the new domain's first scan and names what was asked for.
// Adding a domain is admin-only, as are active checks.
func (s *Server) firstScanOptions(r *http.Request, domain string) []string {
	var opts []string
	if r.PostFormValue("first_active") == "1" {
		if s.store.SetActiveOnce(domain) == nil {
			opts = append(opts, "active scanning")
		}
	}
	if r.PostFormValue("first_shots") == "1" {
		if s.store.SetShotsOnce(domain) == nil {
			opts = append(opts, "screenshots")
		}
	}
	if r.PostFormValue("first_verify") == "1" {
		if s.store.SetVerifyOnce(domain) == nil {
			opts = append(opts, "confirm open ports")
		}
	}
	return opts
}

// scopeAdvice explains the reduced coverage of a sub-domain target, or returns "" for a normal domain.
func (s *Server) scopeAdvice(domain string) string {
	if !isSubdomainScope(domain) {
		return ""
	}
	parent := registeredDomain(domain)
	existing, _ := s.store.ListTargets()
	for _, t := range existing {
		if t.Domain == parent {
			return fmt.Sprintf("%s is already covered by %s, which is monitored too. Monitoring the sub-domain separately only makes sense if it needs its own schedule, owners or alert rules.", domain, parent)
		}
	}
	return fmt.Sprintf("%s is a sub-domain of %s, so only names below %s are discovered. Other sub-domains, the parent's email records (SPF, DKIM, DMARC) and its look-alike domains are not covered. Add %s as well for full coverage; keep this entry only if %s is all you own.", domain, parent, domain, parent, domain)
}

// loadTarget reads the {id} path value and fetches the target.
func (s *Server) loadTarget(w http.ResponseWriter, r *http.Request, sess *Session) *Target {
	id, ok := pathID(r)
	if !ok {
		s.renderError(w, r, sess, http.StatusNotFound, "Not found", "That target does not exist.")
		return nil
	}
	t, err := s.store.GetTarget(id)
	if errors.Is(err, sql.ErrNoRows) {
		s.renderError(w, r, sess, http.StatusNotFound, "Not found", "That target does not exist (it may have been removed).")
		return nil
	}
	if err != nil {
		s.serverError(w, r, sess, err)
		return nil
	}
	return t
}

// targetView renders one domain's page.
func (s *Server) targetView(w http.ResponseWriter, r *http.Request, sess *Session) {
	t := s.loadTarget(w, r, sess)
	if t == nil {
		return
	}
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	inv, invTotal, err := s.store.Inventory(t.Domain, q, 500)
	if err != nil {
		s.serverError(w, r, sess, err)
		return
	}
	certs, certTotal, err := s.store.ListCerts(t.Domain, 25)
	if err != nil {
		s.serverError(w, r, sess, err)
		return
	}
	finds, err := s.store.ListFindings(t.Domain, "")
	if err != nil {
		s.serverError(w, r, sess, err)
		return
	}
	var active []Finding
	resolved := 0
	for _, f := range finds {
		if f.Status == "resolved" {
			resolved++
		} else {
			active = append(active, f)
		}
	}
	sugg, err := s.store.ListSuggestions(t.Domain, "new")
	if err != nil {
		s.serverError(w, r, sess, err)
		return
	}
	evs, _, err := s.store.ListEvents(EventFilter{Root: t.Domain, Limit: 30})
	if err != nil {
		s.serverError(w, r, sess, err)
		return
	}
	scans, err := s.store.ListScans(t.Domain, 15)
	if err != nil {
		s.serverError(w, r, sess, err)
		return
	}
	settings, _ := s.store.LoadSettings()
	state, class := targetState(t)
	refresh := 0
	if state == "Scanning" || state == "Queued" {
		refresh = 15
	}
	s.render(w, r, sess, "target", http.StatusOK, map[string]any{
		"Title": t.Domain, "Nav": "dashboard", "T": t, "Prog": s.eng.Progress().Get(t.ID), "State": state, "StateClass": class, "Refresh": refresh,
		"Inventory": inv, "InvTotal": invTotal, "Q": q, "Certs": certs, "CertTotal": certTotal,
		"Findings": active, "Suggestions": sugg, "ResolvedCount": resolved, "Events": evs, "Scans": scans, "DefaultInterval": settings.IntervalMinutes,
	})
}

func (s *Server) backToTarget(w http.ResponseWriter, r *http.Request, id int64) {
	http.Redirect(w, r, "/targets/"+strconv.FormatInt(id, 10), http.StatusSeeOther)
}

// targetEdit saves edited domain options.
func (s *Server) targetEdit(w http.ResponseWriter, r *http.Request, sess *Session) {
	t := s.loadTarget(w, r, sess)
	if t == nil {
		return
	}
	nt, err := TargetFromForm(t.Domain, r.PostFormValue("asns"), r.PostFormValue("keywords"), r.PostFormValue("ignore"),
		r.PostFormValue("interval"), r.PostFormValue("notes"))
	if err != nil {
		s.flash(sess, "bad", err.Error())
		s.backToTarget(w, r, t.ID)
		return
	}
	nt.ID = t.ID
	if err := s.store.UpdateTarget(nt); err != nil {
		s.serverError(w, r, sess, err)
		return
	}
	s.flash(sess, "good", "Saved. Changes apply from the next scan.")
	s.backToTarget(w, r, t.ID)
}

// targetScan queues an immediate scan.
func (s *Server) targetScan(w http.ResponseWriter, r *http.Request, sess *Session) {
	t := s.loadTarget(w, r, sess)
	if t == nil {
		return
	}
	refresh := r.PostFormValue("refresh") == "1"
	active := r.PostFormValue("active") == "1"
	if active && sess.Role != RoleAdmin { // active probing is governed by the admin-only Settings
		s.renderError(w, r, sess, http.StatusForbidden, "Not allowed", "Only an administrator can start a scan with active checks.")
		return
	}
	if active && t.Enabled && s.eng.Scanning(t.ID) {
		// A scan is already under way without active checks: stop it and start again
		// with them, rather than refusing (the passive scan would otherwise carry on).
		if err := s.store.SetActiveOnce(t.Domain); err != nil {
			s.serverError(w, r, sess, err)
			return
		}
		s.eng.StopScan(t.ID, errScanRestarted)
		s.audit(sess, r, "scan.active", t.Domain, "running scan restarted with active checks")
		s.flash(sess, "good", "The running scan was stopped and is starting again with active checks: the agent will connect to this domain's servers for this scan only.")
		s.backToTarget(w, r, t.ID)
		return
	}
	ok, err := s.store.RequestScan(t.ID)
	if err == nil && ok && refresh {
		err = s.store.SetRefresh(t.Domain, true)
	}
	if err == nil && ok && active {
		err = s.store.SetActiveOnce(t.Domain)
	}
	switch {
	case err != nil:
		s.serverError(w, r, sess, err)
		return
	case !ok:
		s.flash(sess, "warn", "A scan is already running, or the target is paused.")
	default:
		s.eng.Wake()
		if active {
			s.audit(sess, r, "scan.active", t.Domain, "active checks for this scan")
			s.flash(sess, "good", "Scan queued with active checks: the agent will connect to this domain's servers for this scan only.")
		} else if refresh {
			s.audit(sess, r, "scan.refresh", t.Domain, "exposure data cache bypassed")
			s.flash(sess, "good", "Scan queued. Saved exposure answers will be ignored so everything is asked again.")
		} else {
			s.flash(sess, "good", "Scan queued; it will start in a moment.")
		}
	}
	s.backToTarget(w, r, t.ID)
}

// targetPause stops scheduled scans and the scan in flight, if any.
func (s *Server) targetPause(w http.ResponseWriter, r *http.Request, sess *Session) {
	if t := s.loadTarget(w, r, sess); t != nil {
		if err := s.store.SetTargetEnabled(t.ID, false); err != nil {
			s.serverError(w, r, sess, err)
			return
		}
		if s.eng.StopScan(t.ID, errScanPaused) {
			s.flash(sess, "good", "Monitoring paused and the running scan was stopped. Existing data is kept; the stopped scan saved nothing.")
		} else {
			s.flash(sess, "good", "Monitoring paused. Existing data is kept.")
		}
		s.backToTarget(w, r, t.ID)
	}
}

// targetResume restarts scheduled scans.
func (s *Server) targetResume(w http.ResponseWriter, r *http.Request, sess *Session) {
	if t := s.loadTarget(w, r, sess); t != nil {
		if err := s.store.SetTargetEnabled(t.ID, true); err != nil {
			s.serverError(w, r, sess, err)
			return
		}
		s.eng.Wake()
		s.flash(sess, "good", "Monitoring resumed; a scan is starting.")
		s.backToTarget(w, r, t.ID)
	}
}

// targetDelete removes a domain and its data.
func (s *Server) targetDelete(w http.ResponseWriter, r *http.Request, sess *Session) {
	t := s.loadTarget(w, r, sess)
	if t == nil {
		return
	}
	if strings.TrimSpace(strings.ToLower(r.PostFormValue("confirm"))) != t.Domain {
		s.flash(sess, "bad", "Type the domain name exactly to confirm deletion.")
		s.backToTarget(w, r, t.ID)
		return
	}
	if t.LastStatus == "running" {
		s.flash(sess, "warn", "A scan is running for this target; try again when it finishes.")
		s.backToTarget(w, r, t.ID)
		return
	}
	if err := s.store.DeleteTarget(t.ID); err != nil {
		s.serverError(w, r, sess, err)
		return
	}
	s.audit(sess, r, "target.delete", t.Domain, "all stored data for this domain was removed")
	s.log.Info("target deleted", "domain", t.Domain, "by", sess.Username)
	s.flash(sess, "good", "Removed "+t.Domain+" and all of its stored data.")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// ---------------------------------------------------------------- findings & events

// targetNames lists monitored domain names.
func (s *Server) targetNames() ([]string, error) {
	ts, err := s.store.ListTargets()
	if err != nil {
		return nil, err
	}
	out := make([]string, len(ts))
	for i, t := range ts {
		out[i] = t.Domain
	}
	return out, nil
}

func validRoot(names []string, v string) string {
	for _, n := range names {
		if n == v {
			return v
		}
	}
	return ""
}

// findings renders the Findings page.
func (s *Server) findings(w http.ResponseWriter, r *http.Request, sess *Session) {
	names, err := s.targetNames()
	if err != nil {
		s.serverError(w, r, sess, err)
		return
	}
	q := r.URL.Query()
	root, status, sev := validRoot(names, q.Get("target")), q.Get("status"), q.Get("severity")
	if status != "open" && status != "ack" && status != "resolved" && status != "all" {
		status = "open"
	}
	filterStatus := status
	if status == "all" {
		filterStatus = ""
	}
	list, err := s.store.ListFindings(root, filterStatus)
	if err != nil {
		s.serverError(w, r, sess, err)
		return
	}
	if _, ok := severityRank[sev]; ok && sev != "" {
		var f []Finding
		for _, x := range list {
			if sevRank(x.Severity) >= sevRank(sev) {
				f = append(f, x)
			}
		}
		list = f
	} else {
		sev = ""
	}
	trust := q.Get("trust")
	if trust == "trusted" || trust == "unconfirmed" {
		var f []Finding
		for _, x := range list {
			if (x.Trust == trustUnconfirmed || x.Trust == trustDisputed) == (trust == "unconfirmed") {
				f = append(f, x)
			}
		}
		list = f
	} else {
		trust = ""
	}
	grouped := q.Get("group") == "host"
	perHost := map[string]int{}
	for _, f := range list {
		perHost[f.Host]++
	}
	if grouped { // hosts with the worst finding first, then by name; inside a host, worst first
		worst := map[string]int{}
		for _, f := range list {
			if r := sevRank(f.Severity); r > worst[f.Host] {
				worst[f.Host] = r
			}
		}
		sort.SliceStable(list, func(i, j int) bool {
			a, b := list[i], list[j]
			if worst[a.Host] != worst[b.Host] {
				return worst[a.Host] > worst[b.Host]
			}
			if a.Host != b.Host {
				return a.Host < b.Host
			}
			return sevRank(a.Severity) > sevRank(b.Severity)
		})
	}
	s.render(w, r, sess, "findings", http.StatusOK, map[string]any{
		"Title": "Findings", "Nav": "findings", "Findings": list, "Targets": names, "Target": root, "Status": status, "Severity": sev, "Trust": trust,
		"Next": r.URL.RequestURI(), "Grouped": grouped, "PerHost": perHost,
	})
}

var eventKinds = []string{"subdomain", "cert", "dns-a", "dns-aaaa", "dns-cname", "dns-ns", "dns-mx", "dns-txt",
	"dangling-cname", "asn-unexpected", "private-ip", "email-auth", "dns-removed", "host-gone", "service-removed", "finding-resolved", "web-service", "related-domain", "lookalike-domain", "leaked-credentials", "repo-exposure", "cloud-service"}

// events renders the change log.
func (s *Server) events(w http.ResponseWriter, r *http.Request, sess *Session) {
	names, err := s.targetNames()
	if err != nil {
		s.serverError(w, r, sess, err)
		return
	}
	q := r.URL.Query()
	f := EventFilter{Root: validRoot(names, q.Get("target")), Limit: pageSize}
	for _, k := range eventKinds {
		if q.Get("kind") == k {
			f.Kind = k
		}
	}
	if _, ok := severityRank[q.Get("severity")]; ok {
		f.MinSeverity = q.Get("severity")
	}
	f.IncludeBaseline = q.Get("baseline") == "1"
	page, _ := strconv.Atoi(q.Get("page"))
	if page < 1 {
		page = 1
	}
	f.Offset = (page - 1) * pageSize
	evs, total, err := s.store.ListEvents(f)
	if err != nil {
		s.serverError(w, r, sess, err)
		return
	}
	pages := (total + pageSize - 1) / pageSize
	base := url.Values{}
	for _, k := range []string{"target", "kind", "severity", "baseline"} {
		if v := q.Get(k); v != "" {
			base.Set(k, v)
		}
	}
	s.render(w, r, sess, "events", http.StatusOK, map[string]any{
		"Title": "Events", "Nav": "events", "Events": evs, "Total": total, "Page": page, "Pages": pages,
		"Targets": names, "Kinds": eventKinds, "F": f, "BaseQuery": base.Encode(),
	})
}

// ---------------------------------------------------------------- reports

// errUnknownTarget is a report asked for a domain that is not monitored. Falling back to
// "All targets" would hand back far more than was asked for, under the wrong title.
var errUnknownTarget = errors.New("unknown domain: not a monitored target")

// reportParams reads the report period and scope from the query.
func (s *Server) reportParams(r *http.Request) (root string, days int, names []string, err error) {
	names, err = s.targetNames()
	if err != nil {
		return
	}
	asked := r.URL.Query().Get("target")
	root = validRoot(names, asked)
	if asked != "" && root == "" {
		err = errUnknownTarget
		return
	}
	days, _ = strconv.Atoi(r.URL.Query().Get("days"))
	switch days {
	case 1, 7, 30, 90, 365:
	default:
		days = 7
	}
	return
}

// reportError answers a failed reportParams: 404 for an unknown domain, 500 otherwise.
func (s *Server) reportError(w http.ResponseWriter, r *http.Request, sess *Session, err error) {
	if errors.Is(err, errUnknownTarget) {
		s.renderError(w, r, sess, http.StatusNotFound, "Unknown domain",
			"No monitored domain has that name. Pick one from the list, or leave it empty for a report on all domains.")
		return
	}
	s.serverError(w, r, sess, err)
}

// reportOpts reads the severity filter from the query string.
func reportOpts(r *http.Request) ReportOpts { return ParseSeverityFilter(r.URL.Query()["sev"]) }

// reportQuery is the query string that reproduces the current report selection.
func reportQuery(root string, days int, o ReportOpts) string {
	q := "target=" + url.QueryEscape(root) + "&days=" + strconv.Itoa(days)
	if sq := o.Query(); sq != "" {
		q += "&" + sq
	}
	return q
}

// report renders the report page.
func (s *Server) report(w http.ResponseWriter, r *http.Request, sess *Session) {
	root, days, names, err := s.reportParams(r)
	if err != nil {
		s.reportError(w, r, sess, err)
		return
	}
	opts := reportOpts(r)
	rep, err := BuildReportOpts(s.store, root, time.Now().Add(-time.Duration(days)*24*time.Hour), 300, opts)
	if err != nil {
		s.serverError(w, r, sess, err)
		return
	}
	rep.Days, rep.PreparedBy = days, PreparedBy(sess)
	s.render(w, r, sess, "report", http.StatusOK, map[string]any{
		"Title": "Report", "Nav": "report", "R": rep, "Targets": names, "Target": root, "Days": days,
		"Query": reportQuery(root, days, opts),
	})
}

// reportPDF sends the report as a PDF file.
func (s *Server) reportPDF(w http.ResponseWriter, r *http.Request, sess *Session) {
	root, days, _, err := s.reportParams(r)
	if err != nil {
		s.reportError(w, r, sess, err)
		return
	}
	rep, err := BuildReportOpts(s.store, root, time.Now().Add(-time.Duration(days)*24*time.Hour), 200, reportOpts(r))
	if err != nil {
		s.serverError(w, r, sess, err)
		return
	}
	rep.Days, rep.PreparedBy = days, PreparedBy(sess)
	pdf, err := RenderReportPDF(rep, version)
	if err != nil {
		s.serverError(w, r, sess, err)
		return
	}
	scope := "all"
	if root != "" {
		scope = root
	}
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", `attachment; filename="easm-report-`+scope+`-`+time.Now().Format("20060102")+`.pdf"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(pdf) // nosemgrep: no-direct-write-to-responsewriter -- a PDF document generated by the server, not HTML
}

// reportCSV exports the report as CSV.
func (s *Server) reportCSV(kind string) authed {
	return func(w http.ResponseWriter, r *http.Request, sess *Session) {
		root, days, _, err := s.reportParams(r)
		if err != nil {
			s.reportError(w, r, sess, err)
			return
		}
		rep, err := BuildReportOpts(s.store, root, time.Now().Add(-time.Duration(days)*24*time.Hour), 200000, reportOpts(r))
		if err != nil {
			s.serverError(w, r, sess, err)
			return
		}
		name := "easm-" + kind + "-" + time.Now().Format("20060102") + ".csv"
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
		if kind == "findings" {
			_ = WriteFindingsCSV(w, rep)
		} else {
			_ = WriteInventoryCSV(w, rep)
		}
	}
}

// reportJSON exports the report as JSON.
func (s *Server) reportJSON(w http.ResponseWriter, r *http.Request, sess *Session) {
	root, days, _, err := s.reportParams(r)
	if err != nil {
		s.reportError(w, r, sess, err)
		return
	}
	rep, err := BuildReportOpts(s.store, root, time.Now().Add(-time.Duration(days)*24*time.Hour), 200000, reportOpts(r))
	if err != nil {
		s.serverError(w, r, sess, err)
		return
	}
	rep.PreparedBy = PreparedBy(sess)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="easm-report-`+time.Now().Format("20060102")+`.json"`)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(rep)
}

// ---------------------------------------------------------------- settings

func formInt(r *http.Request, name, label string) (int, error) {
	v := strings.TrimSpace(r.PostFormValue(name))
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s must be a whole number", label)
	}
	return n, nil
}

var apiKeyRe = regexp.MustCompile(`^[A-Za-z0-9._~+/=-]{8,200}$`)

// parseSettingsForm reads and validates the Settings form.
func parseSettingsForm(r *http.Request, cur Settings) (Settings, error) {
	s := cur
	var err error
	ints := []struct {
		dst   *int
		name  string
		label string
	}{
		{&s.IntervalMinutes, "interval_minutes", "Default scan interval"},
		{&s.JitterMinutes, "jitter_minutes", "Jitter"},
		{&s.TargetTimeoutMinutes, "target_timeout_minutes", "Per-target timeout"},
		{&s.ConcurrentScans, "concurrent_scans", "Concurrent domain scans"},
		{&s.EventRetentionDays, "event_retention_days", "Event retention"},
		{&s.AlertMinEvents, "alert_min_events", "Alert threshold"},
		{&s.AlertMaxRows, "alert_max_rows", "Max rows per email"},
		{&s.RemovalMisses, "removal_misses", "Scans before something counts as removed"},
		{&s.ActiveMaxHosts, "active_max_hosts", "Active checks: hosts per scan"},
		{&s.ActiveTimeoutSeconds, "active_timeout_seconds", "Active checks: timeout"},
		{&s.ActiveConcurrency, "active_concurrency", "Active checks: parallel probes"},
		{&s.ScreenshotMax, "screenshot_max", "Screenshots per scan"},
		{&s.LookalikeMax, "lookalike_max", "Look-alike variations per scan"},
		{&s.DigestHour, "digest_hour", "Digest hour"},
		{&s.CrtShTimeoutSeconds, "crtsh_timeout_seconds", "crt.sh timeout"},
		{&s.CrtShMaxAttempts, "crtsh_max_attempts", "crt.sh attempts"},
		{&s.DNSWorkers, "dns_workers", "DNS workers"},
		{&s.DNSQPS, "dns_qps", "DNS queries per second"},
		{&s.DNSTimeoutSeconds, "dns_timeout_seconds", "DNS timeout"},
		{&s.DNSRetries, "dns_retries", "DNS retries"},
		{&s.SMTPPort, "smtp_port", "SMTP port"},
		{&s.EnrichMaxIPs, "enrich_max_ips", "Max IPs looked up per scan"},
	}
	for _, f := range ints {
		if *f.dst, err = formInt(r, f.name, f.label); err != nil {
			return cur, err
		}
	}
	on := func(n string) bool { return r.PostFormValue(n) == "on" }
	str := func(n string) string { return strings.TrimSpace(r.PostFormValue(n)) }
	s.AlertImmediateSeverity, s.DigestFrequency = str("alert_immediate_severity"), str("digest_frequency")
	s.PublicURL, s.OrgName, s.UpdateCheck = str("public_url"), r.PostFormValue("org_name"), on("update_check")
	s.SMTPHost, s.SMTPSecurity, s.SMTPUsername = str("smtp_host"), str("smtp_security"), str("smtp_username")
	s.SMTPFrom, s.SMTPSubjectPrefix = str("smtp_from"), r.PostFormValue("smtp_subject_prefix")
	s.DNSResolvers = splitList(r.PostFormValue("dns_resolvers"), true)
	s.SMTPTo = splitList(r.PostFormValue("smtp_to"), true)
	s.AlertBaselineSummary, s.AlertCerts, s.AlertTXT = on("alert_baseline_summary"), on("alert_certs"), on("alert_txt")
	s.AlertRemovals = on("alert_removals")
	s.Require2FA = on("require_2fa")
	s.ActiveChecks, s.ActiveForeign, s.ActivePaths, s.ActiveBuckets = on("active_checks"), on("active_foreign"), on("active_paths"), on("active_buckets")
	s.Screenshots, s.ChromePath = on("screenshots"), strings.TrimSpace(r.PostFormValue("chrome_path"))
	s.CrtShEnabled, s.HackerTargetEnabled, s.OTXEnabled, s.AnubisEnabled = on("crtsh_enabled"), on("hackertarget_enabled"), on("otx_enabled"), on("anubis_enabled")
	s.ASNEnabled, s.ASNBGPViewFallback = on("asn_enabled"), on("asn_bgpview_fallback")
	s.SMTPEnabled, s.SMTPInsecureSkipVerify = on("smtp_enabled"), on("smtp_insecure_skip_verify")
	s.InternetDBEnabled, s.RDAPEnabled = on("internetdb_enabled"), on("rdap_enabled")
	s.ShodanEnabled, s.ShodanDomainLookup = on("shodan_enabled"), on("shodan_domain_lookup")
	s.CensysEnabled, s.CensysOrgID, s.VirusTotalEnabled = on("censys_enabled"), str("censys_org_id"), on("virustotal_enabled")
	s.HIBPEnabled, s.GitHubEnabled = on("hibp_enabled"), on("github_enabled")
	s.LookalikeEnabled, s.RelatedEnabled, s.ReverseIPEnabled = on("lookalike_enabled"), on("related_enabled"), on("reverseip_enabled")
	if err := s.Normalize(); err != nil {
		return cur, err
	}
	return s, nil
}

// settingsView renders the Settings page.
func (s *Server) settingsView(w http.ResponseWriter, r *http.Request, sess *Session) {
	st, err := s.store.LoadSettings()
	if err != nil {
		s.serverError(w, r, sess, err)
		return
	}
	s.render(w, r, sess, "settings", http.StatusOK, map[string]any{
		"Title": "Settings", "Nav": "settings", "S": st, "HasPassword": s.eng.HasSMTPPassword(),
		"HasShodan": s.eng.HasSecret(secretShodan), "HasCensys": s.eng.HasSecret(secretCensys), "HasVT": s.eng.HasSecret(secretVT), "HasHIBP": s.eng.HasSecret(secretHIBP), "HasGitHub": s.eng.HasSecret(secretGitHub),
		"Resolvers": strings.Join(st.DNSResolvers, "\n"), "Recipients": strings.Join(st.SMTPTo, "\n"),
		"Listen": s.listenView(), "Cert": s.certView(), "Backup": s.backupView(),
	})
}

// listenView describes the web server's listen address for the Settings page.
func (s *Server) listenView() map[string]any {
	if s.listen == nil {
		return nil
	}
	host, port := splitListen(s.listen.Address())
	return map[string]any{"Host": host, "Port": port, "Locked": s.listen.Locked(), "Choices": ListenChoices(),
		"Scheme": map[bool]string{true: "https", false: "http"}[s.boot.UsesTLS()]}
}

// settingsListen changes the address and port the web interface listens on.
// The new address is bound before anything is switched, so a mistake (a busy
// port, an address this computer does not have) leaves the old one working.
func (s *Server) settingsListen(w http.ResponseWriter, r *http.Request, sess *Session) {
	back := func(kind, msg string) {
		s.flash(sess, kind, msg)
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
	}
	if s.listen == nil || s.listen.Locked() {
		back("bad", "The listen address is fixed by the command line or the config file. Change it there.")
		return
	}
	addr, err := ResolveListen(r.PostFormValue("host"), r.PostFormValue("port"))
	if err != nil {
		back("bad", "Listen address not changed: "+err.Error()+".")
		return
	}
	if addr == s.listen.Address() {
		back("good", "Already listening on "+addr+".")
		return
	}
	url, err := s.listen.Change(addr)
	if err != nil {
		back("bad", "Could not listen on "+addr+": "+err.Error()+". Nothing was changed.")
		return
	}
	s.log.Info("listen address changed", "address", addr, "by", sess.Username)
	s.render(w, r, sess, "moved", http.StatusOK, map[string]any{"Title": "Listen address changed", "Nav": "settings", "URL": url, "Addr": addr})
}

// setListen updates the values that depend on the listen address (the accepted Host headers).
func (s *Server) setListen(addr string) {
	s.hmu.Lock()
	s.hosts = buildAllowedHosts(addr, s.boot.AllowedHosts)
	s.hmu.Unlock()
}

// settingsSave validates and stores settings and API keys.
func (s *Server) settingsSave(w http.ResponseWriter, r *http.Request, sess *Session) {
	cur, err := s.store.LoadSettings()
	if err != nil {
		s.serverError(w, r, sess, err)
		return
	}
	next, err := parseSettingsForm(r, cur)
	if err != nil {
		s.flash(sess, "bad", err.Error())
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	// API keys: validate everything before anything is written.
	type keyField struct {
		secret, field, label string
		enabled              bool
	}
	var writes []keyField
	for _, k := range []keyField{
		{secretShodan, "shodan_key", "Shodan", next.ShodanEnabled},
		{secretCensys, "censys_token", "Censys", next.CensysEnabled},
		{secretVT, "virustotal_key", "VirusTotal", next.VirusTotalEnabled},
		{secretHIBP, "hibp_key", "Have I Been Pwned", next.HIBPEnabled},
		{secretGitHub, "github_token", "GitHub", next.GitHubEnabled},
	} {
		val, wipe := strings.TrimSpace(r.PostFormValue(k.field)), r.PostFormValue(k.field+"_clear") == "on"
		if val != "" && !apiKeyRe.MatchString(val) {
			s.flash(sess, "bad", k.label+" key looks wrong: it should be one token of letters, digits and - . _ ~ + / = only.")
			http.Redirect(w, r, "/settings", http.StatusSeeOther)
			return
		}
		have := s.eng.HasSecret(k.secret) && !wipe
		if k.enabled && val == "" && !have {
			s.flash(sess, "bad", k.label+" is enabled but no API key is saved. Paste a key or untick it.")
			http.Redirect(w, r, "/settings", http.StatusSeeOther)
			return
		}
		switch {
		case val != "":
			k.field = val
			writes = append(writes, k)
		case wipe:
			k.field = ""
			writes = append(writes, k)
		}
	}
	if err := s.store.SaveSettings(next); err != nil {
		s.serverError(w, r, sess, err)
		return
	}
	s.audit(sess, r, "settings.save", "settings", "")
	if next.Require2FA {
		s.markNeed2FA()
	}
	for _, k := range writes {
		if err = s.eng.SetSecret(k.secret, k.field); err != nil {
			s.serverError(w, r, sess, err)
			return
		}
	}
	switch pw := r.PostFormValue("smtp_password"); {
	case r.PostFormValue("smtp_password_clear") == "on":
		err = s.eng.SetSMTPPassword("")
	case pw != "":
		err = s.eng.SetSMTPPassword(pw)
	}
	if err != nil {
		s.serverError(w, r, sess, err)
		return
	}
	s.log.Info("settings changed", "by", sess.Username)
	s.flash(sess, "good", "Settings saved. They apply from the next scan.")
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

// settingsTestEmail sends a test message to verify SMTP.
func (s *Server) settingsTestEmail(w http.ResponseWriter, r *http.Request, sess *Session) {
	ctx, cancel := context.WithTimeout(r.Context(), 100*time.Second)
	defer cancel()
	if err := s.eng.SendTestEmail(ctx); err != nil {
		s.flash(sess, "bad", "Test email failed: "+err.Error())
	} else {
		s.flash(sess, "good", "Test email sent. Check the recipients' inboxes (and spam folders).")
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

// settingsDigestNow sends the digest email immediately.
func (s *Server) settingsDigestNow(w http.ResponseWriter, r *http.Request, sess *Session) {
	ctx, cancel := context.WithTimeout(r.Context(), 100*time.Second)
	defer cancel()
	if err := s.eng.SendDigest(ctx, 7*24*time.Hour); err != nil {
		s.flash(sess, "bad", "Report email failed: "+err.Error())
	} else {
		s.flash(sess, "good", "Report email sent (covers the last 7 days).")
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

// ---------------------------------------------------------------- users & account

func (s *Server) usersView(w http.ResponseWriter, r *http.Request, sess *Session) {
	users, err := s.store.ListUsers()
	if err != nil {
		s.serverError(w, r, sess, err)
		return
	}
	s.render(w, r, sess, "users", http.StatusOK, map[string]any{"Title": "Users", "Nav": "users", "Users": users, "Me": sess.UserID})
}

// userAdd creates an account.
func (s *Server) userAdd(w http.ResponseWriter, r *http.Request, sess *Session) {
	name, pw, role := strings.TrimSpace(r.PostFormValue("username")), r.PostFormValue("password"), r.PostFormValue("role")
	var err error
	switch {
	case !userRe.MatchString(name):
		err = errors.New("username must be 3-32 characters: letters, digits, dot, dash or underscore")
	case !validRole(role):
		err = errors.New("choose a role")
	default:
		err = validatePassword(pw)
	}
	if err == nil {
		var hash string
		if hash, err = hashPassword(pw); err == nil {
			_, err = s.store.CreateUser(name, hash, role)
		}
	}
	if err != nil {
		s.flash(sess, "bad", err.Error())
	} else {
		s.audit(sess, r, "user.create", name, "role "+role)
		s.log.Info("user created", "user", name, "role", role, "by", sess.Username)
		s.flash(sess, "good", "User "+name+" created.")
	}
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

// userDelete removes an account (never the last administrator).
func (s *Server) userDelete(w http.ResponseWriter, r *http.Request, sess *Session) {
	id, ok := pathID(r)
	if !ok {
		s.renderError(w, r, sess, http.StatusNotFound, "Not found", "")
		return
	}
	u, err := s.store.GetUser(id)
	switch {
	case err != nil:
		s.flash(sess, "bad", "User not found.")
	case u.ID == sess.UserID:
		s.flash(sess, "bad", "You cannot delete your own account.")
	default:
		if n, _ := s.store.CountAdmins(); u.Role == "admin" && u.Kind != kindADGroup && n <= 1 {
			s.flash(sess, "bad", "You cannot delete the last administrator.")
		} else if err := s.store.DeleteUser(id); err != nil {
			s.serverError(w, r, sess, err)
			return
		} else {
			s.dropSessionsFor(id)
			s.audit(sess, r, "user.delete", u.Username, "role "+u.Role)
			s.log.Info("user deleted", "user", u.Username, "by", sess.Username)
			s.flash(sess, "good", "User "+u.Username+" deleted.")
		}
	}
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

// userSetPassword lets an administrator reset a password.
func (s *Server) userSetPassword(w http.ResponseWriter, r *http.Request, sess *Session) {
	id, ok := pathID(r)
	if !ok {
		s.renderError(w, r, sess, http.StatusNotFound, "Not found", "")
		return
	}
	pw := r.PostFormValue("password")
	if tu, e := s.store.GetUser(id); e == nil && isAD(tu.Kind) {
		s.flash(sess, "bad", tu.Username+" signs in with a directory password; change it in Active Directory.")
	} else if err := validatePassword(pw); err != nil {
		s.flash(sess, "bad", err.Error())
	} else if hash, err := hashPassword(pw); err != nil {
		s.serverError(w, r, sess, err)
		return
	} else if err := s.store.SetPassword(id, hash); err != nil {
		s.serverError(w, r, sess, err)
		return
	} else {
		if id != sess.UserID {
			s.dropSessionsFor(id)
		}
		s.audit(sess, r, "user.password", strconv.FormatInt(id, 10), "reset by administrator")
		s.flash(sess, "good", "Password updated.")
	}
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}

func (s *Server) accountView(w http.ResponseWriter, r *http.Request, sess *Session) {
	s.mu.Lock()
	reveal := sess.Reveal
	sess.Reveal = ""
	s.mu.Unlock()
	toks, _ := s.store.ListTokens(0)
	var mine, others []APIToken
	for _, t := range toks {
		switch {
		case t.OwnerID == sess.UserID:
			mine = append(mine, t)
		case roleLevel(sess.Role) >= permAdmin:
			others = append(others, t)
		}
	}
	roles := []string{RoleViewer}
	if roleLevel(sess.Role) >= permTriage {
		roles = append(roles, RoleAnalyst)
	}
	if roleLevel(sess.Role) >= permAdmin {
		roles = append(roles, RoleAdmin)
	}
	s.render(w, r, sess, "account", http.StatusOK, map[string]any{"Title": "My account", "Nav": "account", "Role": sess.Role, "Directory": isAD(sess.Kind),
		"Reveal": reveal, "Tokens": mine, "OtherTokens": others, "TokenRoles": roles})
}

// accountPassword lets a user change their own password.
func (s *Server) accountPassword(w http.ResponseWriter, r *http.Request, sess *Session) {
	u, err := s.store.GetUser(sess.UserID)
	if err != nil {
		s.serverError(w, r, sess, err)
		return
	}
	newPw := r.PostFormValue("password")
	switch {
	case isAD(u.Kind):
		s.flash(sess, "bad", "Your password is managed in Active Directory.")
	case bcrypt.CompareHashAndPassword([]byte(u.Hash), []byte(r.PostFormValue("current"))) != nil:
		s.flash(sess, "bad", "Your current password is incorrect.")
	case newPw != r.PostFormValue("confirm"):
		s.flash(sess, "bad", "The two new passwords do not match.")
	default:
		if err := validatePassword(newPw); err != nil {
			s.flash(sess, "bad", err.Error())
		} else if hash, err := hashPassword(newPw); err != nil {
			s.serverError(w, r, sess, err)
			return
		} else if err := s.store.SetPassword(u.ID, hash); err != nil {
			s.serverError(w, r, sess, err)
			return
		} else {
			s.flash(sess, "good", "Password changed.")
		}
	}
	http.Redirect(w, r, "/account", http.StatusSeeOther)
}

// progressJSON feeds the live progress bars (viewers may read it; it carries no secrets).
func (s *Server) progressJSON(w http.ResponseWriter, _ *http.Request, _ *Session) {
	type item struct {
		ID      int64  `json:"id"`
		Domain  string `json:"domain"`
		Stage   string `json:"stage"`
		Detail  string `json:"detail"`
		Percent int    `json:"percent"`
		Elapsed int    `json:"elapsed"`
		Idle    int    `json:"idle"`
		Active  bool   `json:"active"`
	}
	out := []item{}
	for _, p := range s.eng.Progress().Snapshot() {
		out = append(out, item{p.ID, p.Domain, p.Stage, p.Detail, p.Percent, p.Elapsed, p.IdleSecs, p.Active})
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(out)
}

// noDirListing stops the static file server from listing directories: only
// named files are served, so the asset folder cannot be browsed.
func noDirListing(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "" || strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}
