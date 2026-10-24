package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// loginFailure describes why a sign-in did not succeed: what the person sees, what is audited.
type loginFailure struct {
	status  int
	message string
	audit   string
	neutral bool // not the person's fault (directory down): do not count towards throttling
}

var badLogin = loginFailure{status: http.StatusUnauthorized, message: "Invalid username or password."}

// adGuard limits password guesses per directory account, so the agent cannot be used to lock
// somebody out of the domain by guessing, and cannot be used to guess quickly either.
type adGuard struct {
	mu sync.Mutex
	m  map[string]*failRec
}

const adGuardMax = 10000

func (g *adGuard) blocked(name string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	f := g.m[name]
	return f != nil && time.Now().Before(f.blocked)
}

func (g *adGuard) fail(name string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.m == nil || len(g.m) > adGuardMax {
		g.m = map[string]*failRec{}
	}
	f := g.m[name]
	if f == nil || time.Since(f.first) > failSpan {
		f = &failRec{first: time.Now()}
		g.m[name] = f
	}
	f.count++
	if f.count >= maxFails {
		f.blocked = time.Now().Add(blockSpan)
	}
}

func (g *adGuard) ok(name string) {
	g.mu.Lock()
	delete(g.m, name)
	g.mu.Unlock()
}

// authenticate checks a username and password against the local accounts, then the directory.
// A local account always wins over a directory account of the same name.
func (s *Server) authenticate(r *http.Request, typed, password string) (*User, loginFailure) {
	u, err := s.store.GetUserByName(typed)
	if err == nil && u.Kind == kindLocal {
		hash := []byte(u.Hash)
		if bcrypt.CompareHashAndPassword(hash, []byte(password)) != nil || u.Disabled {
			return nil, badLogin
		}
		return u, loginFailure{}
	}
	cfg, cerr := s.store.LoadAD()
	if cerr != nil || !cfg.Enabled {
		_ = bcrypt.CompareHashAndPassword(s.dummyHash, []byte(password)) // equalise timing for unknown users
		return nil, badLogin
	}
	return s.adSignIn(r, cfg, typed, password)
}

// adSignIn authenticates against the directory and maps the result onto an account.
func (s *Server) adSignIn(r *http.Request, cfg ADConfig, typed, password string) (*User, loginFailure) {
	key := strings.ToLower(typed)
	if s.adg.blocked(key) {
		return nil, loginFailure{status: http.StatusTooManyRequests, message: "Too many failed attempts for this account. Try again in a few minutes.", audit: "blocked"}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
	defer cancel()
	d := &directory{cfg: cfg, bindPW: s.eng.Secret(secretADBind)}
	id, err := d.Authenticate(ctx, typed, password)
	switch {
	case errors.Is(err, errADCredentials):
		s.adg.fail(key)
		return nil, loginFailure{status: http.StatusUnauthorized, message: badLogin.message, audit: "directory: bad credentials"}
	case err != nil:
		s.log.Error("directory sign-in failed", "err", err)
		return nil, loginFailure{status: http.StatusServiceUnavailable, neutral: true, audit: "directory unavailable",
			message: "The directory could not be reached. Try again shortly, or ask an administrator."}
	}
	s.adg.ok(key)
	name := strings.ToLower(id.Sam)
	u, err := s.store.FindUserFold(name)
	switch {
	case err == nil && u.Kind == kindLocal:
		s.log.Warn("directory account has the same name as a local account; local account wins", "name", name)
		return nil, loginFailure{status: http.StatusUnauthorized, message: badLogin.message, audit: "name clash with a local account"}
	case err == nil && u.Disabled:
		return nil, loginFailure{status: http.StatusForbidden, message: "This account is disabled.", audit: "account disabled"}
	case err == nil && u.Kind == kindAD:
		return u, loginFailure{} // explicit user: role is whatever the administrator set
	case err == nil: // kindADGroup: the role follows current group membership
		if id.Role == "" {
			return nil, notAuthorised
		}
		if id.Role != u.Role {
			if e := s.store.SetUserRole(u.ID, id.Role); e != nil {
				s.log.Error("could not update role from directory groups", "err", e)
			} else {
				s.auditAs(u.Username, kindADGroup, r, "user.role", u.Username, u.Role+" -> "+id.Role+" (directory group)")
				u.Role = id.Role
			}
		}
		return u, loginFailure{}
	}
	// first sign-in of somebody who is not yet known
	if id.Role == "" {
		return nil, notAuthorised
	}
	if _, e := s.store.CreateUserKind(name, "", id.Role, kindADGroup); e != nil {
		s.log.Error("could not create the account for a directory user", "err", e)
		return nil, loginFailure{status: http.StatusInternalServerError, message: "Could not create your account. See the log.", neutral: true}
	}
	s.auditAs(name, kindADGroup, r, "user.create", name, "role "+id.Role+" from directory group "+strings.Join(id.Groups, ", "))
	u, err = s.store.GetUserByName(name)
	if err != nil {
		return nil, badLogin
	}
	return u, loginFailure{}
}

var notAuthorised = loginFailure{status: http.StatusForbidden, audit: "authenticated but in no mapped group",
	message: "Your directory sign-in is correct, but this account has not been given access. Ask an administrator to add you or one of your groups."}

// ---------------------------------------------------------------- settings page

// adView renders the directory settings page.
func (s *Server) adView(w http.ResponseWriter, r *http.Request, sess *Session) {
	cfg, err := s.store.LoadAD()
	if err != nil {
		s.flash(sess, "bad", err.Error())
	}
	rows := append([]ADGroup(nil), cfg.Groups...)
	for len(rows) < len(cfg.Groups)+3 || len(rows) < 4 {
		rows = append(rows, ADGroup{Role: RoleViewer})
	}
	s.render(w, r, sess, "ad", http.StatusOK, map[string]any{"Title": "Directory sign-in", "Nav": "settings", "C": cfg,
		"Servers": strings.Join(cfg.Servers, "\n"), "Rows": rows, "HasBind": s.eng.HasSecret(secretADBind), "DefaultFilter": DefaultADFilter})
}

// adForm reads the directory settings form. The bind password is returned separately.
func adForm(r *http.Request) (c ADConfig, pw string, wipe bool) {
	_ = r.ParseForm()
	c = ADConfig{
		Enabled:    r.PostFormValue("enabled") == "on",
		Security:   r.PostFormValue("security"),
		SkipVerify: r.PostFormValue("skip_verify") == "on",
		CAPEM:      r.PostFormValue("ca_pem"),
		BindDN:     r.PostFormValue("bind_dn"),
		BaseDN:     r.PostFormValue("base_dn"),
		UserFilter: r.PostFormValue("user_filter"),
		Domain:     r.PostFormValue("domain"),
	}
	c.Servers = append(c.Servers, strings.FieldsFunc(r.PostFormValue("servers"), func(r rune) bool { return r == '\n' || r == ',' || r == '\r' })...)
	for i := 0; i < 20; i++ {
		g := r.PostFormValue(fmt.Sprintf("group_%d", i))
		if strings.TrimSpace(g) != "" {
			c.Groups = append(c.Groups, ADGroup{Group: g, Role: r.PostFormValue(fmt.Sprintf("role_%d", i))})
		}
	}
	return c, r.PostFormValue("bind_password"), r.PostFormValue("bind_password_clear") == "on"
}

// adSave validates and stores the directory settings.
func (s *Server) adSave(w http.ResponseWriter, r *http.Request, sess *Session) {
	c, pw, wipe := adForm(r)
	back := func() { http.Redirect(w, r, "/settings/ad", http.StatusSeeOther) }
	if err := c.Validate(); err != nil {
		s.flash(sess, "bad", err.Error())
		back()
		return
	}
	if c.Enabled && pw == "" && !s.eng.HasSecret(secretADBind) {
		s.flash(sess, "bad", "Enter the service account password.")
		back()
		return
	}
	if err := s.store.SaveAD(c); err != nil {
		s.serverError(w, r, sess, err)
		return
	}
	switch {
	case wipe:
		_ = s.eng.SetSecret(secretADBind, "")
	case pw != "":
		if err := s.eng.SetSecret(secretADBind, pw); err != nil {
			s.serverError(w, r, sess, err)
			return
		}
	}
	s.audit(sess, r, "settings.directory", "active directory", fmt.Sprintf("enabled=%v servers=%d groups=%d", c.Enabled, len(c.Servers), len(c.Groups)))
	s.flash(sess, "good", "Directory settings saved.")
	back()
}

// adTest tries the saved settings: connection, then (optionally) a full sign-in without creating a session.
func (s *Server) adTest(w http.ResponseWriter, r *http.Request, sess *Session) {
	cfg, err := s.store.LoadAD()
	if err == nil && (len(cfg.Servers) == 0 || cfg.BaseDN == "") {
		err = errors.New("save the server, bind account and base DN first")
	}
	if err != nil {
		s.flash(sess, "bad", err.Error())
		http.Redirect(w, r, "/settings/ad", http.StatusSeeOther)
		return
	}
	d := &directory{cfg: cfg, bindPW: s.eng.Secret(secretADBind)}
	if err := d.Ping(); err != nil {
		s.flash(sess, "bad", "Connection test failed: "+err.Error())
		http.Redirect(w, r, "/settings/ad", http.StatusSeeOther)
		return
	}
	user := strings.TrimSpace(r.PostFormValue("test_user"))
	if user == "" {
		s.flash(sess, "good", "Connected and signed in with the service account. To test a person, enter their name and password and press Test again.")
		http.Redirect(w, r, "/settings/ad", http.StatusSeeOther)
		return
	}
	id, err := d.Authenticate(r.Context(), user, r.PostFormValue("test_password"))
	switch {
	case errors.Is(err, errADCredentials):
		s.flash(sess, "bad", "The directory connection works, but that username or password was not accepted (or the account is disabled).")
	case err != nil:
		s.flash(sess, "bad", "Test failed: "+err.Error())
	case id.Role == "":
		s.flash(sess, "warn", fmt.Sprintf("%s signed in correctly but is in none of the mapped groups. They can sign in only if added as an explicit AD user.", id.Sam))
	default:
		s.flash(sess, "good", fmt.Sprintf("%s signed in correctly and would get the %s role (groups: %s).", id.Sam, roleLabel(id.Role), strings.Join(id.Groups, "; ")))
	}
	s.audit(sess, r, "directory.test", user, "")
	http.Redirect(w, r, "/settings/ad", http.StatusSeeOther)
}

// userAddAD authorises an individual directory user.
func (s *Server) userAddAD(w http.ResponseWriter, r *http.Request, sess *Session) {
	name, role := strings.TrimSpace(r.PostFormValue("username")), r.PostFormValue("role")
	var warn string
	cfg, err := s.store.LoadAD()
	switch {
	case err != nil:
	case !validRole(role):
		err = errors.New("choose a role")
	case !cfg.Enabled:
		err = errors.New("turn on directory sign-in first (Settings, Directory sign-in)")
	}
	if err == nil {
		d := &directory{cfg: cfg, bindPW: s.eng.Secret(secretADBind)}
		id, e := d.Lookup(name)
		switch {
		case errors.Is(e, errADCredentials):
			err = fmt.Errorf("%q was not found in the directory", name)
		case e != nil:
			warn = " The directory could not be checked just now, so the name was not verified."
			name = strings.ToLower(strings.TrimSpace(name))
		default:
			name = strings.ToLower(id.Sam)
		}
	}
	if err == nil && !userRe.MatchString(name) {
		err = errors.New("that account name has characters this application does not accept")
	}
	if err == nil {
		if _, e := s.store.FindUserFold(name); e == nil {
			err = fmt.Errorf("a user named %s already exists", name)
		}
	}
	if err == nil {
		_, err = s.store.CreateUserKind(name, "", role, kindAD)
	}
	if err != nil {
		s.flash(sess, "bad", err.Error())
	} else {
		s.audit(sess, r, "user.create", name, "role "+role+" (directory user)")
		s.flash(sess, "good", "Directory user "+name+" added as "+roleLabel(role)+"."+warn)
	}
	http.Redirect(w, r, "/users", http.StatusSeeOther)
}
