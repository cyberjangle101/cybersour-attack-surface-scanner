package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// DispatchChannels sends new events to the non-email alert channels.
func (s *Scanner) DispatchChannels(ctx context.Context) {
	newChannelSender(s.store, s.log, func() string { return s.cfg.PublicURL }).DispatchAll(ctx)
}

type channelRow struct {
	*Channel
	KindLabel string
	Target    string
}

func kindLabel(k string) string {
	for _, c := range channelKinds {
		if c.ID == k {
			return c.Label
		}
	}
	return k
}

func channelTarget(c *Channel) string {
	switch c.Kind {
	case chSyslog:
		return c.Cfg.Proto + "://" + c.Cfg.Addr
	case chJira:
		return redactURL(c.Cfg.URL) + " project " + c.Cfg.Project
	}
	return redactURL(c.Cfg.URL)
}

func (s *Server) channelsView(w http.ResponseWriter, r *http.Request, sess *Session) {
	list, err := s.store.ListChannels()
	if err != nil {
		s.flash(sess, "bad", err.Error())
	}
	rows := make([]channelRow, 0, len(list))
	for _, c := range list {
		rows = append(rows, channelRow{c, kindLabel(c.Kind), channelTarget(c)})
	}
	s.render(w, r, sess, "channels", http.StatusOK, map[string]any{"Title": "Alert channels", "Nav": "settings", "Rows": rows, "Kinds": channelKinds})
}

func (s *Server) channelAdd(w http.ResponseWriter, r *http.Request, sess *Session) {
	f := r.PostFormValue
	c := &Channel{Name: f("name"), Kind: f("kind"), MinSev: f("min_sev"), Cfg: ChannelCfg{
		URL: f("url"), Secret: f("secret"), HeaderName: f("header_name"), HeaderValue: f("header_value"),
		Addr: f("addr"), Proto: f("proto"), Format: f("format"), Project: f("project"), IssueType: f("issue_type"),
		User: strings.TrimSpace(f("user")), Token: f("token"),
	}}
	id, err := s.store.AddChannel(c)
	if err != nil {
		s.flash(sess, "bad", err.Error())
	} else {
		s.audit(sess, r, "channel.add", c.Name, c.Kind)
		s.flash(sess, "good", "Channel added. It will send changes found from now on. Use Test to check it works.")
		_ = id
	}
	http.Redirect(w, r, "/settings/channels", http.StatusSeeOther)
}

func (s *Server) channelFromPath(w http.ResponseWriter, r *http.Request) *Channel {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err == nil {
		var c *Channel
		if c, err = s.store.GetChannel(id); err == nil {
			return c
		}
	}
	http.Redirect(w, r, "/settings/channels", http.StatusSeeOther)
	return nil
}

func (s *Server) channelTest(w http.ResponseWriter, r *http.Request, sess *Session) {
	c := s.channelFromPath(w, r)
	if c == nil {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	cs := newChannelSender(s.store, s.log, func() string { st, _ := s.store.LoadSettings(); return st.PublicURL })
	if err := cs.SendTest(ctx, c); err != nil {
		s.flash(sess, "bad", "Test failed: "+err.Error())
	} else {
		s.flash(sess, "good", "Test message sent to "+c.Name+".")
	}
	s.audit(sess, r, "channel.test", c.Name, "")
	http.Redirect(w, r, "/settings/channels", http.StatusSeeOther)
}

func (s *Server) channelToggle(w http.ResponseWriter, r *http.Request, sess *Session) {
	if c := s.channelFromPath(w, r); c != nil {
		if err := s.store.SetChannelEnabled(c.ID, !c.Enabled); err != nil {
			s.serverError(w, r, sess, err)
			return
		}
		s.audit(sess, r, "channel.toggle", c.Name, strconv.FormatBool(!c.Enabled))
		http.Redirect(w, r, "/settings/channels", http.StatusSeeOther)
	}
}

func (s *Server) channelDelete(w http.ResponseWriter, r *http.Request, sess *Session) {
	if c := s.channelFromPath(w, r); c != nil {
		if err := s.store.DeleteChannel(c.ID); err != nil {
			s.serverError(w, r, sess, err)
			return
		}
		s.audit(sess, r, "channel.delete", c.Name, "")
		s.flash(sess, "good", "Channel removed.")
		http.Redirect(w, r, "/settings/channels", http.StatusSeeOther)
	}
}

// tokenCreate makes an API token for the signed-in user.
func (s *Server) tokenCreate(w http.ResponseWriter, r *http.Request, sess *Session) {
	back := func() { http.Redirect(w, r, "/account", http.StatusSeeOther) }
	name, role := strings.TrimSpace(r.PostFormValue("name")), r.PostFormValue("role")
	if name == "" || !validRole(role) || roleLevel(role) > roleLevel(sess.Role) {
		s.flash(sess, "bad", "Give the token a name and a role no higher than your own.")
		back()
		return
	}
	expires := ""
	if d := strings.TrimSpace(r.PostFormValue("days")); d != "" {
		n, err := strconv.Atoi(d)
		if err != nil || n < 1 || n > 3650 {
			s.flash(sess, "bad", "Days must be a whole number from 1 to 3650, or blank.")
			back()
			return
		}
		expires = time.Now().UTC().AddDate(0, 0, n).Format("2006-01-02")
	}
	plain, err := newToken()
	if err == nil {
		_, err = s.store.CreateToken(sess.UserID, name, role, plain, expires)
	}
	if err != nil {
		s.serverError(w, r, sess, err)
		return
	}
	s.mu.Lock()
	sess.Reveal = plain
	s.mu.Unlock()
	s.audit(sess, r, "token.create", name, "role "+role)
	back()
}

// tokenRevoke disables a token. Administrators may revoke anyone's.
func (s *Server) tokenRevoke(w http.ResponseWriter, r *http.Request, sess *Session) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	owner := sess.UserID
	if roleLevel(sess.Role) >= permAdmin {
		owner = 0
	}
	if err := s.store.RevokeToken(id, owner); err != nil {
		s.flash(sess, "bad", "That token was not found.")
	} else {
		s.audit(sess, r, "token.revoke", strconv.FormatInt(id, 10), "")
		s.flash(sess, "good", "Token revoked.")
	}
	http.Redirect(w, r, "/account", http.StatusSeeOther)
}

func (s *Server) reportFindings(r *http.Request) ([]apiFinding, error) {
	root, _, _, err := s.reportParams(r)
	if err != nil {
		return nil, err
	}
	fs, err := s.store.ListFindings(root, "open")
	return apiFindings(fs), err
}

func (s *Server) reportSARIF(w http.ResponseWriter, r *http.Request, sess *Session) {
	fs, err := s.reportFindings(r)
	if err != nil {
		s.reportError(w, r, sess, err)
		return
	}
	w.Header().Set("Content-Type", "application/sarif+json")
	w.Header().Set("Content-Disposition", `attachment; filename="easm-findings.sarif"`)
	_ = json.NewEncoder(w).Encode(buildSARIF(fs))
}

func (s *Server) reportSTIX(w http.ResponseWriter, r *http.Request, sess *Session) {
	fs, err := s.reportFindings(r)
	if err != nil {
		s.reportError(w, r, sess, err)
		return
	}
	w.Header().Set("Content-Type", "application/stix+json;version=2.1")
	w.Header().Set("Content-Disposition", `attachment; filename="easm-findings.stix.json"`)
	_ = json.NewEncoder(w).Encode(buildSTIX(fs))
}

// suggestionAccept starts monitoring a suggested domain.
func (s *Server) suggestionAccept(w http.ResponseWriter, r *http.Request, sess *Session) {
	t := s.loadTarget(w, r, sess)
	if t == nil {
		return
	}
	dom := r.PostFormValue("domain")
	nt, err := TargetFromForm(dom, "", "", "", "", "Suggested from "+t.Domain)
	if err == nil {
		if _, err = s.store.AddTarget(nt); err == nil {
			err = s.store.SetSuggestion(t.Domain, dom, "added")
		}
	}
	if err != nil {
		s.flash(sess, "bad", err.Error())
	} else {
		s.audit(sess, r, "target.add", nt.Domain, "from a suggestion on "+t.Domain)
		s.eng.Wake()
		s.flash(sess, "good", "Now monitoring "+nt.Domain+". Its first scan sets the baseline.")
	}
	s.backToTarget(w, r, t.ID)
}

// suggestionDismiss hides a suggestion for good.
func (s *Server) suggestionDismiss(w http.ResponseWriter, r *http.Request, sess *Session) {
	t := s.loadTarget(w, r, sess)
	if t == nil {
		return
	}
	dom := r.PostFormValue("domain")
	if err := s.store.SetSuggestion(t.Domain, dom, "dismissed"); err != nil {
		s.flash(sess, "bad", err.Error())
	} else {
		s.audit(sess, r, "suggestion.dismiss", dom, t.Domain)
	}
	s.backToTarget(w, r, t.ID)
}
