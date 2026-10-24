package main

import "net/http"

// The first-run guide is shown on the dashboard to each user until they hide it.
// The page itself (/guide) is always available from the menu.

func guideKey(sess *Session) string { return "guide_hidden:" + sess.Username }

func (s *Server) guideWanted(sess *Session) bool {
	v, ok, _ := s.store.getMeta(guideKey(sess))
	return !ok || v != "1"
}

func (s *Server) guideView(w http.ResponseWriter, r *http.Request, sess *Session) {
	s.render(w, r, sess, "guide", http.StatusOK, map[string]any{"Title": "Quick guide", "Nav": "guide", "Dismissable": s.guideWanted(sess)})
}

func (s *Server) guideDismiss(w http.ResponseWriter, r *http.Request, sess *Session) {
	_ = s.store.setMeta(guideKey(sess), "1")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
