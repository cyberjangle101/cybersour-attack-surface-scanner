package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
)

// Wider discovery: look-alike domains, other domains that share certificates or addresses with the target,
// leaked accounts, and public code that names the target. Each part is optional; a part that fails
// never fails the scan, and never resolves a finding it could not check.

type lookalikeHit struct {
	Domain, Kind string
	MX, Web      bool
}

type extraData struct {
	lookChecked map[string]bool // look-alike names whose registration was determined this scan
	lookHits    []lookalikeHit
	lookRan     bool

	suggest []Suggestion

	leaks   map[string]int // breach name -> number of accounts (nil when not checked)
	leakErr bool

	repos   []repoHit
	repoErr bool
}

type repoHit struct {
	Repo, Term string
	Files      []string
	URL        string
}

// gatherExtra runs the optional discovery parts.
func (s *Scanner) gatherExtra(ctx context.Context, t *Target, disc *Discovery, results map[string]*HostResult, wildcard map[string]struct{}) *extraData {
	d := &extraData{}
	cfg := s.cfg
	root := t.Domain
	if cfg.Discover.Lookalikes {
		s.prog("Looking for look-alike domains", 86, "checking variations of the name")
		s.lookalikes(ctx, t, results, d)
	}
	if cfg.Discover.Related || cfg.Discover.ReverseIP {
		d.suggest = s.relatedDomains(ctx, t, disc, results, wildcard)
	}
	if cfg.Intel.HIBP.Enabled && s.enr != nil {
		s.prog("Leaked accounts", 88, "Have I Been Pwned")
		m, err := s.enr.HIBPBreaches(ctx, root)
		s.health.Record("hibp", "scan", err == nil, 0, err)
		switch {
		case err == nil:
			d.leaks = map[string]int{}
			for _, breaches := range m {
				for _, b := range breaches {
					d.leaks[b]++
				}
			}
		case errors.Is(err, errNoData):
			d.leaks = map[string]int{} // checked, nothing found
		default:
			d.leakErr = true
			s.log.Warn("leaked-account check failed", "domain", root, "err", err)
		}
	}
	if cfg.Intel.GitHub.Enabled && s.enr != nil {
		s.prog("Public code", 90, "GitHub code search")
		hits, err := s.enr.GitHubExposure(ctx, root)
		s.health.Record("github", "scan", err == nil, 0, err)
		if err != nil {
			d.repoErr = true
			s.log.Warn("code exposure check failed", "domain", root, "err", err)
		}
		d.repos = hits
	}
	return d
}

// ---------------------------------------------------------------- look-alikes

func (s *Scanner) lookalikes(ctx context.Context, t *Target, results map[string]*HostResult, d *extraData) {
	root := t.Domain
	cands := genLookalikes(root, s.cfg.Discover.LookalikeMax)
	if len(cands) == 0 {
		s.log.Info("look-alike check skipped: the target is not a registrable domain", "domain", root)
		return
	}
	own := map[string]bool{}
	if ts, err := s.store.ListTargets(); err == nil {
		for _, o := range ts {
			own[o.Domain] = true
		}
	}
	me := lookOwner{root: root, ns: map[string]bool{}, ips: map[string]bool{}}
	if hr := results[root]; hr != nil {
		for _, n := range hr.Records["NS"] {
			me.ns[cleanName(n)] = true
		}
	}
	for _, h := range []string{root, "www." + root} {
		if hr := results[h]; hr != nil {
			for _, ip := range append(append([]string(nil), hr.Records["A"]...), hr.Records["AAAA"]...) {
				if c, ok := s.feeds.Cloud(ip); !ok || !c.CDN { // a CDN edge is shared by thousands of sites
					me.ips[ip] = true
				}
			}
		}
	}
	d.lookChecked = map[string]bool{}
	var mu sync.Mutex
	jobs := make(chan lookalike)
	var wg sync.WaitGroup
	workers := min(max(s.cfg.DNS.Workers, 1), 16)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for c := range jobs {
				hit, known := s.checkLookalike(ctx, c, me)
				mu.Lock()
				if known {
					d.lookChecked[c.Domain] = true
				}
				if hit != nil && !own[c.Domain] {
					d.lookHits = append(d.lookHits, *hit)
				}
				mu.Unlock()
			}
		}()
	}
feed:
	for _, c := range cands {
		select {
		case jobs <- c:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()
	// Only a full pass counts: after an interruption nothing may be treated as "not registered".
	d.lookRan = ctx.Err() == nil && !s.res.Unreachable()
	if !d.lookRan {
		d.lookChecked = nil
	}
	sort.Slice(d.lookHits, func(i, j int) bool { return d.lookHits[i].Domain < d.lookHits[j].Domain })
}

// lookOwner is the target's own DNS, used to recognise variations it registered itself.
type lookOwner struct {
	root string
	ns   map[string]bool // the target's name servers
	ips  map[string]bool // addresses of the root and www, CDN edges left out
}

// checkLookalike reports whether a variation is registered by someone else and usable against the
// target (it accepts email or has a web address). known=false means DNS could not tell.
// Not reported, though known: unregistered names, the target's own (defensive) registrations,
// names parked or for sale, and names with neither mail nor web, which cannot be used as they stand.
func (s *Scanner) checkLookalike(ctx context.Context, c lookalike, me lookOwner) (hit *lookalikeHit, known bool) {
	in, err := s.res.query(ctx, c.Domain, dns.TypeNS)
	if err != nil {
		return nil, false
	}
	if in.Rcode == dns.RcodeNameError {
		return nil, true
	}
	ns := collectRRs(in, c.Domain, dns.TypeNS)
	if len(ns) == 0 {
		return nil, true
	}
	same := true
	for _, n := range ns {
		n = cleanName(n)
		if dns.IsSubDomain(me.root, n) {
			return nil, true // its name servers are under the target's domain
		}
		if isParkingNS(n) {
			return nil, true // parked or for sale
		}
		if !me.ns[n] {
			same = false
		}
	}
	if same {
		return nil, true // served by the target's own name servers: a defensive registration
	}
	h := &lookalikeHit{Domain: c.Domain, Kind: c.Kind}
	if mx, err := s.res.query(ctx, c.Domain, dns.TypeMX); err == nil {
		for _, m := range collectRRs(mx, c.Domain, dns.TypeMX) {
			_, host, _ := strings.Cut(m, " ") // "10 mx.example.net"
			if host = strings.TrimSpace(host); host == "" || host == "." {
				continue // null MX (RFC 7505): it explicitly accepts no email
			}
			if dns.IsSubDomain(me.root, host) {
				return nil, true // its mail goes to the target's own servers
			}
			h.MX = true
		}
	}
	for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
		if a, err := s.res.query(ctx, c.Domain, qt); err == nil {
			for _, ip := range collectRRs(a, c.Domain, qt) {
				if me.ips[ip] {
					return nil, true // it points at the target's own web server (typically a redirect)
				}
				h.Web = true
			}
		}
	}
	if !h.MX && !h.Web {
		return nil, true // registered but neither mail nor web: nothing to act on yet
	}
	return h, true
}

func (h lookalikeHit) severity() string {
	if h.MX {
		return "medium"
	}
	return "low"
}

func (h lookalikeHit) detail(root string) string {
	use := "It has a web address."
	switch {
	case h.MX && h.Web:
		use = "It has a web address and accepts email."
	case h.MX:
		use = "It accepts email."
	}
	return fmt.Sprintf("%s is registered and looks like %s (%s). %s It is not served by your name servers. Nothing here shows who owns it or that it is malicious.", h.Domain, root, h.Kind, use)
}

// ---------------------------------------------------------------- related domains

// sharedHosting lists services whose certificates and addresses are shared by thousands of unrelated customers.
var sharedHosting = map[string]bool{"cloudflaressl.com": true, "cloudflare.com": true, "amazonaws.com": true, "azurewebsites.net": true, "herokuapp.com": true,
	"googleusercontent.com": true, "fastly.net": true, "akamaiedge.net": true, "wixsite.com": true, "wordpress.com": true, "github.io": true, "netlify.app": true,
	"vercel.app": true, "pages.dev": true, "workers.dev": true, "blogspot.com": true, "squarespace.com": true, "shopify.com": true, "myshopify.com": true, "sectigo.com": true,
	"letsencrypt.org": true, "digicert.com": true, "azureedge.net": true, "cloudfront.net": true, "trafficmanager.net": true, "windows.net": true, "office.com": true, "microsoft.com": true}

func registrable(host string) string {
	e, err := publicsuffix.EffectiveTLDPlusOne(strings.ToLower(strings.TrimSuffix(host, ".")))
	if err != nil {
		return ""
	}
	return e
}

func (s *Scanner) relatedDomains(ctx context.Context, t *Target, disc *Discovery, results map[string]*HostResult, wildcard map[string]struct{}) []Suggestion {
	root := t.Domain
	mine := registrable(root)
	if mine == "" {
		return nil
	}
	own := map[string]bool{mine: true}
	if ts, err := s.store.ListTargets(); err == nil {
		for _, o := range ts {
			own[registrable(o.Domain)] = true
		}
	}
	found := map[string]Suggestion{}
	add := func(dom, via, detail string) {
		if dom == "" || own[dom] || sharedHosting[dom] || t.ignored(dom) {
			return
		}
		if _, ok := found[dom]; !ok {
			found[dom] = Suggestion{Root: root, Domain: dom, Via: via, Detail: detail}
		}
	}
	if s.cfg.Discover.Related && disc != nil {
		keys := make([]string, 0, len(disc.Certs))
		for k := range disc.Certs {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			c := disc.Certs[k]
			doms := map[string]string{}
			for _, n := range c.Others {
				if r := registrable(n); r != "" && !own[r] && !sharedHosting[r] {
					doms[r] = n
				}
			}
			if len(doms) == 0 || len(doms) > 8 { // a certificate naming many unrelated domains belongs to a hosting service
				continue
			}
			for r, n := range doms {
				add(r, "certificate", fmt.Sprintf("Named on a certificate that also covers %s (issued by %s).", firstOr(c.Names, root), c.Issuer))
				_ = n
			}
		}
	}
	if s.cfg.Discover.ReverseIP && s.enr != nil {
		hr := results[root]
		var ips []string
		if hr != nil {
			for _, ip := range hr.Records["A"] {
				if _, w := wildcard[ip]; !w && publicIP(ip) {
					ips = append(ips, ip)
				}
			}
		}
		sort.Strings(ips)
		for i, ip := range ips {
			if i == 3 || ctx.Err() != nil {
				break
			}
			names, err := s.enr.ReverseIP(ctx, ip)
			s.health.Record("hackertarget", "scan", err == nil, 0, err)
			if err != nil || len(names) > 25 { // many tenants: shared hosting, not a signal
				continue
			}
			for _, n := range names {
				add(registrable(n), "address", fmt.Sprintf("Hosted on %s, the same address as %s.", ip, root))
			}
		}
	}
	out := make([]Suggestion, 0, len(found))
	for _, g := range found {
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	if len(out) > 50 {
		out = out[:50]
	}
	return out
}

func firstOr(l []string, def string) string {
	if len(l) > 0 {
		return l[0]
	}
	return def
}

func newGet(ctx context.Context, u, ua string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, errors.New("bad request")
	}
	req.Header.Set("User-Agent", ua)
	return req, nil
}

// ---------------------------------------------------------------- Enricher parts

func (e *Enricher) hibpHeaders() map[string]string {
	return map[string]string{"hibp-api-key": e.cfg.HIBP.Key}
}

// HIBPBreaches asks Have I Been Pwned which accounts at the domain are in which breaches.
// The domain must be verified in the HIBP dashboard of the key's owner. errNoData means none.
func (e *Enricher) HIBPBreaches(ctx context.Context, root string) (map[string][]string, error) {
	var m map[string][]string
	if err := e.getJSON(ctx, e.urls.hibp+"breacheddomain/"+url.PathEscape(root), e.hibpHeaders(), &m); err != nil {
		return nil, err
	}
	return m, nil
}

func (e *Enricher) hibpPing(ctx context.Context) error {
	err := e.getJSON(ctx, e.urls.hibp+"subscription/status", e.hibpHeaders(), nil)
	return err
}

func (e *Enricher) githubHeaders() map[string]string {
	return map[string]string{"Authorization": "Bearer " + e.cfg.GitHub.Key, "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
}

func (e *Enricher) githubPing(ctx context.Context) error {
	err := e.getJSON(ctx, e.urls.github+"rate_limit", e.githubHeaders(), nil)
	return err
}

var githubTerms = []string{"password", "secret", "token", "apikey"}

// GitHubExposure searches public code for the domain next to secret-like words and groups the hits by repository.
// The code-search limit is 10 requests a minute, so the searches are spaced out.
func (e *Enricher) GitHubExposure(ctx context.Context, root string) ([]repoHit, error) {
	byRepo := map[string]*repoHit{}
	var firstErr error
	for i, term := range githubTerms {
		if i > 0 {
			select {
			case <-time.After(e.githubGap()):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		var r struct {
			Items []struct {
				Path    string `json:"path"`
				HTMLURL string `json:"html_url"`
				Repo    struct {
					FullName string `json:"full_name"`
					Private  bool   `json:"private"`
				} `json:"repository"`
			} `json:"items"`
		}
		q := url.Values{"q": {`"` + root + `" ` + term}, "per_page": {"30"}}.Encode()
		if err := e.getJSON(ctx, e.urls.github+"search/code?"+q, e.githubHeaders(), &r); err != nil {
			if errors.Is(err, errNoData) {
				continue
			}
			if firstErr == nil {
				firstErr = err
			}
			var ea errAuth
			if errors.As(err, &ea) {
				break // a bad token or the rate limit: the remaining searches would fail the same way
			}
			continue
		}
		for _, it := range r.Items {
			if it.Repo.FullName == "" || it.Repo.Private {
				continue
			}
			h := byRepo[it.Repo.FullName]
			if h == nil {
				h = &repoHit{Repo: it.Repo.FullName, Term: term, URL: it.HTMLURL}
				byRepo[it.Repo.FullName] = h
			}
			if len(h.Files) < 5 && !containsStr(h.Files, it.Path) {
				h.Files = append(h.Files, it.Path)
			}
		}
	}
	out := make([]repoHit, 0, len(byRepo))
	for _, h := range byRepo {
		out = append(out, *h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Repo < out[j].Repo })
	return out, firstErr
}

func (e *Enricher) githubGap() time.Duration {
	if e.gapOverride > 0 {
		return e.gapOverride
	}
	return 7 * time.Second
}

func containsStr(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// ReverseIP lists the host names HackerTarget knows on an address.
func (e *Enricher) ReverseIP(ctx context.Context, ip string) ([]string, error) {
	req, err := newGet(ctx, e.urls.reverseip+"?q="+url.QueryEscape(ip), e.ua)
	if err != nil {
		return nil, err
	}
	resp, err := e.hc.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var out []string
	buf := make([]byte, 1<<20)
	n, _ := resp.Body.Read(buf)
	for _, l := range strings.Split(string(buf[:n]), "\n") {
		l = strings.ToLower(strings.TrimSpace(l))
		if l == "" || strings.Contains(l, " ") { // error messages contain spaces
			if strings.Contains(l, "api count exceeded") || strings.Contains(l, "error") {
				return nil, errors.New("HackerTarget refused the request: " + clip(l, 80))
			}
			continue
		}
		out = append(out, l)
	}
	return out, nil
}

// ---------------------------------------------------------------- persisting

func (s *Scanner) applyExtra(tx *Tx, t *Target, d *extraData, now string, emit emitFn, raise raiseFn) error {
	if d == nil {
		return nil
	}
	root := t.Domain
	for _, h := range d.lookHits {
		raise("lookalike:"+root+":"+h.Domain, "lookalike-domain", h.severity(), h.Domain, h.detail(root), "")
	}
	for br, n := range d.leaks {
		sev := "medium"
		if n >= 5 {
			sev = "high"
		}
		raise("leak:"+root+":"+br, "leaked-credentials", sev, root,
			fmt.Sprintf("%d account(s) at %s appear in the %q breach. Open your Have I Been Pwned domain dashboard to see which.", n, root, br), "Have I Been Pwned")
	}
	for _, r := range d.repos {
		detail := fmt.Sprintf("The public repository github.com/%s mentions %s near the word %q (%s). Check whether it holds real secrets: %s", r.Repo, root, r.Term, strings.Join(r.Files, ", "), r.URL)
		raise("repo:"+root+":"+r.Repo, "repo-exposure", "medium", root, detail, "GitHub code search")
	}
	for _, g := range d.suggest {
		isNew, err := tx.UpsertSuggestion(root, g.Domain, g.Via, g.Detail, now)
		if err != nil {
			return err
		}
		if isNew {
			emit("related-domain", "info", g.Domain, fmt.Sprintf("%s may also belong to you: %s", g.Domain, g.Detail), true)
		}
	}
	return nil
}

// reliableFor says whether a finding of an extra kind may be closed because this scan no longer reproduced it.
func (d *extraData) reliableFor(kind, key string) bool {
	if d == nil {
		return false
	}
	if kind == "lookalike-domain" {
		p := strings.SplitN(key, ":", 3)
		return d.lookRan && len(p) == 3 && d.lookChecked[p[2]] // checked, and not registered any more
	}
	return false // breaches and public code do not "go away" in a way a search can prove
}
