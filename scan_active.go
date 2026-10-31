package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// activeData is what the active checks produced during one scan.
type activeData struct {
	enabled bool
	results []*WebResult
	buckets map[string][]BucketResult // host -> results
	shots   map[string][]byte         // "host:port" -> PNG
	scopes  map[string]bool           // things that were checked successfully; only these may resolve findings
}

func webScope(host string, port int) string { return "web|" + host + "|" + strconv.Itoa(port) }

// activeScope maps a finding key back to what has to have been checked for it to be resolvable.
func activeScope(key string) string {
	p := strings.Split(key, ":")
	switch {
	case len(p) >= 4 && p[0] == "web":
		return "web|" + p[2] + "|" + p[3]
	case len(p) >= 4 && p[0] == "bucket":
		return "bucket|" + p[2] + "|" + p[3]
	}
	return ""
}

func (a *activeData) reliableFor(key string) bool {
	if a == nil || !a.enabled {
		return false
	}
	sc := activeScope(key)
	return sc != "" && a.scopes[sc]
}

func schemeFor(port int) string {
	switch port {
	case 443, 8443, 9443:
		return "https"
	}
	return "http"
}

// activePlan chooses what to probe: for each host, one address and the ports to try.
type probeJob struct {
	host, ip string
	port     int
}

func (s *Scanner) gatherActive(ctx context.Context, t *Target, hosts []string, results map[string]*HostResult, wildcard map[string]struct{}, asns map[string]*ASNInfo) *activeData {
	cfg := s.cfg.Active
	d := &activeData{enabled: cfg.Enabled, buckets: map[string][]BucketResult{}, shots: map[string][]byte{}, scopes: map[string]bool{}}
	if !cfg.Enabled {
		return d
	}
	pr := s.prober
	if pr == nil {
		pr = NewProber(cfg)
	}
	var jobs []probeJob
	var buckets []struct{ host, provider, name string }
	skippedForeign := 0
	for _, h := range hosts {
		hr := results[h]
		if hr == nil || hr.NX {
			continue
		}
		if cfg.Buckets {
			for _, b := range bucketsFor(h, hr.Records["CNAME"]) {
				buckets = append(buckets, struct{ host, provider, name string }{h, b.Provider, b.Name})
			}
		}
		ip := ""
	pick:
		for _, rt := range []string{"A", "AAAA"} {
			for _, v := range hr.Records[rt] {
				if _, w := wildcard[v]; w || !pr.allow(net.ParseIP(v)) {
					continue
				}
				// Only probe what is the organisation's own, unless told otherwise.
				if t.hasOwnershipRules() && !cfg.Foreign {
					if info := asns[v]; info == nil || !t.owns(info) {
						continue
					}
				}
				ip = v
				break pick
			}
		}
		if ip == "" {
			if len(hr.Records["A"])+len(hr.Records["AAAA"]) > 0 {
				skippedForeign++
			}
			continue
		}
		ports := []int{80, 443}
		ports = append(ports, s.store.webPortsFor(ip)...)
		for _, p := range ports {
			jobs = append(jobs, probeJob{h, ip, p})
		}
		if len(jobs)/2 >= cfg.MaxHosts {
			s.log.Warn("active checks capped for this scan; the rest follow on later scans", "cap", cfg.MaxHosts)
			break
		}
	}
	if skippedForeign > 0 {
		s.log.Info("active checks skipped hosts outside the expected ownership", "hosts", skippedForeign)
	}
	s.prog("Checking web services", 80, fmt.Sprintf("%d probes", len(jobs)))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, cfg.Concurrency)
	for _, j := range jobs {
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(j probeJob) {
			defer wg.Done()
			defer func() { <-sem }()
			wr := pr.probeWeb(ctx, j.host, j.ip, j.port, schemeFor(j.port))
			wr.Takeover = s.unclaimedService(results[j.host], wr.rootBody)
			wr.rootBody = nil
			if wr.Reached && j.port == 443 && (j.host == t.Domain || j.host == "www."+t.Domain) {
				wr.SecTxt = pr.securityTxt(ctx, j.host, j.ip) // the organisation's main site should say how to report a vulnerability
			}
			mu.Lock()
			if wr.Reached {
				d.results = append(d.results, wr)
				d.scopes[webScope(j.host, j.port)] = true
			}
			mu.Unlock()
		}(j)
	}
	for _, b := range buckets {
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(host, provider, name string) {
			defer wg.Done()
			defer func() { <-sem }()
			br := pr.checkBucket(ctx, provider, name)
			mu.Lock()
			d.buckets[host] = append(d.buckets[host], br)
			if br.Checked {
				d.scopes["bucket|"+host+"|"+name] = true
			}
			mu.Unlock()
		}(b.host, b.provider, b.name)
	}
	wg.Wait()
	sort.Slice(d.results, func(i, j int) bool {
		if d.results[i].Host != d.results[j].Host {
			return d.results[i].Host < d.results[j].Host
		}
		return d.results[i].Port < d.results[j].Port
	})
	if cfg.Shots && ctx.Err() == nil {
		s.takeShots(ctx, d, cfg)
	}
	return d
}

// takeShots renders pages for the services that answered, within the per-scan cap.
func (s *Scanner) takeShots(ctx context.Context, d *activeData, cfg ActiveCfg) {
	browser, err := findBrowser(cfg.ChromePath)
	if err != nil {
		s.log.Warn("screenshots skipped", "reason", err)
		return
	}
	n := 0
	for _, wr := range d.results {
		if n >= cfg.MaxShots || ctx.Err() != nil {
			break
		}
		if wr.Status < 200 || wr.Status >= 400 {
			continue
		}
		s.prog("Taking screenshots", 86, wr.Host)
		png, err := takeShot(ctx, browser, wr.Scheme, wr.Host, wr.IP, wr.Port, 40*time.Second)
		if err != nil {
			s.log.Warn("screenshot failed", "host", wr.Host, "port", wr.Port, "err", err)
			continue
		}
		d.shots[fmt.Sprintf("%s:%d", wr.Host, wr.Port)] = png
		n++
	}
}

// applyActive stores web services, raises findings, and emits events inside the scan transaction.
func (s *Scanner) applyActive(tx *Tx, root string, d *activeData, now string, emit emitFn, raise raiseFn) error {
	if d == nil || !d.enabled {
		return nil
	}
	byKey := map[string]*WebResult{}
	for _, wr := range d.results {
		byKey[fmt.Sprintf("%s:%d", wr.Host, wr.Port)] = wr
	}
	for _, wr := range d.results {
		isNew, err := tx.UpsertWeb(root, wr, now)
		if err != nil {
			return err
		}
		if isNew {
			emit("web-service", "info", wr.Host, fmt.Sprintf("%s answers (HTTP %d%s)", wr.URL(), wr.Status, titleNote(wr.Title)), true)
		}
		if png, ok := d.shots[fmt.Sprintf("%s:%d", wr.Host, wr.Port)]; ok {
			if err := tx.PutShot(wr.Host, wr.Port, png, now); err != nil {
				return err
			}
		}
		where := fmt.Sprintf("%s:%d", wr.Host, wr.Port)
		k := func(kind string, extra ...string) string {
			return strings.Join(append([]string{"web", kind, wr.Host, strconv.Itoa(wr.Port)}, extra...), ":")
		}
		if ti := wr.TLS; ti != nil {
			switch ti.Problem {
			case "expired":
				raise(k("tls-expired"), "tls-expired", "high", wr.Host, fmt.Sprintf("The certificate on %s expired on %s.", where, ti.NotAfter.UTC().Format("2006-01-02")), "")
			case "hostname":
				raise(k("tls-hostname"), "tls-hostname", "medium", wr.Host, fmt.Sprintf("%s: %s.", where, ti.ProblemText), "")
			case "untrusted", "selfsigned", "invalid":
				raise(k("tls-untrusted"), "tls-untrusted", "medium", wr.Host, fmt.Sprintf("%s: %s.", where, ti.ProblemText), "")
			default:
				if ti.DaysLeft <= 30 {
					sev := "medium"
					if ti.DaysLeft <= 7 {
						sev = "high"
					}
					raise(k("tls-expiring"), "tls-expiring", sev, wr.Host, fmt.Sprintf("The certificate on %s expires in %d day(s), on %s.", where, ti.DaysLeft, ti.NotAfter.UTC().Format("2006-01-02")), "")
				}
			}
			if len(ti.Legacy) > 0 {
				raise(k("tls-legacy"), "tls-legacy", "medium", wr.Host, fmt.Sprintf("%s still accepts %s.", where, strings.Join(ti.Legacy, " and ")), "")
			}
			if ti.WeakKey != "" {
				raise(k("tls-weak-key"), "tls-weak-key", "medium", wr.Host, fmt.Sprintf("The certificate on %s uses %s.", where, ti.WeakKey), "")
			}
			if ti.WeakSig != "" {
				raise(k("tls-weak-signature"), "tls-weak-signature", "medium", wr.Host, fmt.Sprintf("The certificate on %s is signed with %s.", where, ti.WeakSig), "")
			}
			if wr.Status >= 200 && wr.Status < 300 && !wr.HSTS && ti.Problem == "" {
				raise(k("hsts-missing"), "hsts-missing", "low", wr.Host, fmt.Sprintf("%s does not send Strict-Transport-Security, so browsers may still try plain HTTP first.", wr.URL()), "")
			}
		}
		for _, ph := range wr.Portals {
			at := strings.TrimSuffix(wr.URL(), "/") + ph.Path
			raise(k("login-portal", portalSlug(ph.Name)), "login-portal", ph.Severity, wr.Host,
				fmt.Sprintf("%s login is public at %s (%s): %s.", ph.Name, at, strings.ToLower(ph.Category), portalWhy(ph.Category)), "")
		}
		if wr.Takeover != "" {
			raise(k("subdomain-takeover"), "subdomain-takeover", "high", wr.Host, fmt.Sprintf("%s shows the page %s gives for a name nobody has claimed. "+
				"Anyone can create that resource and serve their own content from %s.", wr.URL(), wr.Takeover, wr.Host), "")
		}
		if wr.SecTxt == "missing" {
			raise(k("no-security-txt"), "no-security-txt", "low", wr.Host, fmt.Sprintf("%s has no /.well-known/security.txt telling researchers how to report a vulnerability.", wr.URL()), "")
		}
		if wr.DefaultPg != "" && wr.Status == 200 {
			raise(k("default-page"), "default-page", "low", wr.Host, fmt.Sprintf("%s shows the %s: the service was installed and never set up.", wr.URL(), wr.DefaultPg), "")
		}
		for _, h := range wr.Hits {
			raise(k("exposed-path", h.Path), "exposed-path", h.Severity, wr.Host, fmt.Sprintf("%s%s: %s.", strings.TrimSuffix(wr.URL(), "/"), h.Path, h.Why), "")
		}
		if wr.Scheme == "http" && wr.Port == 80 {
			if sec := byKey[fmt.Sprintf("%s:443", wr.Host)]; sec != nil && sec.Status < 500 && !redirectsToHTTPS(wr) {
				raise(k("no-https-redirect"), "no-https-redirect", "low", wr.Host,
					fmt.Sprintf("%s answers over plain HTTP (status %d) instead of sending visitors to the HTTPS site.", wr.URL(), wr.Status), "")
			}
		}
	}
	for host, list := range d.buckets {
		for _, b := range list {
			key := "bucket:%s:" + host + ":" + b.Name
			switch {
			case b.Public:
				raise(fmt.Sprintf(key, "public"), "bucket-public", "high", host, fmt.Sprintf("The %s storage bucket %q behind %s can be listed by anyone on the internet.", bucketProvider(b.Provider), b.Name, host), "")
			case b.Missing:
				raise(fmt.Sprintf(key, "takeover"), "bucket-takeover", "high", host, fmt.Sprintf("%s points at the %s bucket %q, which does not exist. Anyone can create it and publish content under your name.", host, bucketProvider(b.Provider), b.Name), "")
			}
		}
	}
	return nil
}

// unclaimedService reports a host whose CNAME points at a claimable service (per the
// can-i-take-over-xyz fingerprints) that answers with its "nothing here" page: a
// takeover the NXDOMAIN check cannot see, because the name still resolves.
func (s *Scanner) unclaimedService(hr *HostResult, body []byte) string {
	if hr == nil || len(body) == 0 || !s.cfg.Intel.Takeover {
		return ""
	}
	for _, target := range hr.Records["CNAME"] {
		tp, ok := s.feeds.TakeoverFor(target)
		if ok && tp.Fingerprint != "" && bytes.Contains(body, []byte(tp.Fingerprint)) {
			return tp.Service + " (via " + strings.TrimSuffix(target, ".") + ")"
		}
	}
	return ""
}

func titleNote(t string) string {
	if t == "" {
		return ""
	}
	return ", \"" + t + "\""
}

func bucketProvider(p string) string {
	switch p {
	case "s3":
		return "Amazon S3"
	case "gcs":
		return "Google Cloud Storage"
	}
	return p
}

func redirectsToHTTPS(w *WebResult) bool {
	return w.Status >= 300 && w.Status < 400 && strings.HasPrefix(strings.ToLower(w.Location), "https://")
}
