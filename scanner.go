package main

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Scanner performs one scan of one target. A fresh Scanner is built for every
// scan from the current GUI settings, so changes apply without a restart.
type Scanner struct {
	cfg    *Config
	log    *slog.Logger
	store  *Store
	disc   *Discoverer
	res    *Resolver
	asn    *ASNResolver
	mailer *Mailer
	enr    *Enricher
	health *HealthBoard

	prober    *Prober // nil = the default (safe) prober; tests substitute one
	force     bool    // this scan ignores cached exposure intelligence
	stats     scanStats
	newEvents int

	progress func(stage string, pct int, detail string) // optional live progress sink
	onActive func()                                     // optional: told when this scan runs the active checks
}

// prog reports progress; pct is clamped by the board so the bar never goes backwards.
func (s *Scanner) prog(stage string, pct int, detail string) {
	if s.progress != nil {
		s.progress(stage, pct, detail)
	}
}

// SetProgress wires the live progress callback and the per-stage hooks.
func (s *Scanner) SetProgress(f func(stage string, pct int, detail string)) {
	s.progress = f
	s.disc.progress = func(done, total int, pending []string) {
		d := "all sources answered"
		if len(pending) > 0 {
			d = "waiting for " + strings.Join(pending, ", ")
		}
		s.prog("Discovering subdomains", 2+28*done/max(total, 1), d)
	}
	s.asn.progress = func(done, total int) {
		s.prog("Mapping IPs to owners", 65+10*done/max(total, 1), fmt.Sprintf("%d of %d addresses", done, total))
	}
}

var recordTypes = []string{"A", "AAAA", "CNAME", "NS", "MX", "TXT"}

var recordSeverity = map[string]string{"A": "info", "AAAA": "info", "CNAME": "low", "NS": "medium", "MX": "low", "TXT": "info"}

// NewScanner creates a scanner whose components are built from one scan's configuration.
func NewScanner(cfg *Config, log *slog.Logger, store *Store, res *Resolver) *Scanner {
	s := &Scanner{
		cfg: cfg, log: log, store: store, res: res,
		disc:   NewDiscoverer(cfg, log),
		asn:    NewASNResolver(cfg.ASN, res, store, log),
		mailer: NewMailer(cfg.SMTP),
		enr:    NewEnricher(cfg.Intel, log, cfg.Sources.UserAgent),
	}
	s.disc.enr = s.enr
	return s
}

// SetHealth makes every component of this scanner report connector outcomes to h.
func (s *Scanner) SetHealth(h *HealthBoard) {
	s.health = h
	s.disc.health, s.res.health, s.asn.health, s.enr.health = h, h, h, h
	s.mailer.WithHealth(h)
}

type scanStats struct {
	Hosts, Subdomains, Records, Certs, Findings, Resolved, Services, Removed int
}

// resolveAll resolves every host with a bounded worker pool and reports progress.
func (s *Scanner) resolveAll(ctx context.Context, hosts []string) map[string]*HostResult {
	out := make(map[string]*HostResult, len(hosts))
	var doneH atomic.Int64
	var mu sync.Mutex
	var wg sync.WaitGroup
	jobs := make(chan string)
	for i := 0; i < s.cfg.DNS.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for h := range jobs {
				hr := s.res.ResolveHost(ctx, h)
				n := int(doneH.Add(1))
				if n%10 == 0 || n == len(hosts) {
					s.prog("Resolving DNS", 31+34*n/max(len(hosts), 1), fmt.Sprintf("%d of %d hosts", n, len(hosts)))
				}
				mu.Lock()
				out[h] = hr
				mu.Unlock()
			}
		}()
	}
feed:
	for _, h := range hosts {
		select {
		case jobs <- h:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()
	return out
}

// collectIPs returns the sorted unique non-wildcard addresses among the resolved hosts.
func collectIPs(hosts []string, results map[string]*HostResult, wildcard map[string]struct{}) []string {
	set := map[string]struct{}{}
	for _, h := range hosts {
		hr := results[h]
		if hr == nil {
			continue
		}
		for _, rt := range []string{"A", "AAAA"} {
			for _, ip := range hr.Records[rt] {
				if _, w := wildcard[ip]; !w {
					set[ip] = struct{}{}
				}
			}
		}
	}
	out := make([]string, 0, len(set))
	for ip := range set {
		out = append(out, ip)
	}
	sort.Strings(out)
	return out
}

func joinSources(m map[string]struct{}) string {
	var s []string
	for k := range m {
		s = append(s, k)
	}
	sort.Strings(s)
	return strings.Join(s, ",")
}

// scanTarget runs discovery, resolution, ASN mapping and the delta diff for one
// target. Results are persisted in a single transaction: a failed or cancelled
// scan changes nothing.
func (s *Scanner) scanTarget(ctx context.Context, t *Target) error {
	root := t.Domain
	log := s.log.With("domain", root)
	start := time.Now()
	s.stats, s.newEvents = scanStats{}, 0
	s.force = s.store.TakeRefresh(root)
	if s.force {
		log.Info("refresh requested: saved exposure answers will be ignored")
	}
	if s.store.TakeActiveOnce(root) && !s.cfg.Active.Enabled {
		s.cfg.Active.Enabled = true // this scan only: the config is rebuilt for every scan
		log.Info("active checks requested for this scan")
	}
	if s.store.TakeShotsOnce(root) {
		s.cfg.Active.Enabled, s.cfg.Active.Shots = true, true // this scan only
		log.Info("screenshots requested for this scan")
	}
	if s.cfg.Active.Enabled && s.onActive != nil {
		s.onActive()
	}

	baselineAt, baselined, err := s.store.getMeta("baselined:" + root)
	_ = baselineAt
	if err != nil {
		return fmt.Errorf("baseline lookup: %w", err)
	}
	log.Info("scan started", "baseline_mode", !baselined)

	// 1. Passive discovery
	s.prog("Discovering subdomains", 2, "contacting passive sources")
	disc := s.disc.Discover(ctx, root)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if !disc.AnyOK {
		return fmt.Errorf("all discovery sources failed; nothing stored, will retry soon")
	}
	if _, ok := disc.Hosts[root]; !ok {
		disc.Hosts[root] = map[string]struct{}{"root": {}}
	}
	hosts := make([]string, 0, len(disc.Hosts))
	for h := range disc.Hosts {
		if h != root && t.ignored(h) {
			continue
		}
		hosts = append(hosts, h)
	}
	// Hosts seen at an earlier scan are checked again even when the passive sources no longer
	// list them: that is how a disappearance is told apart from a source having a bad day.
	fromStore := map[string]bool{}
	if known, kerr := s.store.KnownHosts(root, 20000); kerr != nil {
		log.Warn("could not list previously seen hosts", "err", kerr)
	} else {
		have := make(map[string]bool, len(hosts))
		for _, h := range hosts {
			have[h] = true
		}
		for _, h := range known {
			if !have[h] && (h == root || !t.ignored(h)) {
				hosts = append(hosts, h)
				fromStore[h] = true
			}
		}
	}
	sort.Strings(hosts)

	// 2. DNS resolution (bounded worker pool + global QPS limiter)
	s.prog("Checking for wildcard DNS", 30, fmt.Sprintf("%d hosts found", len(hosts)))
	wildcard := s.res.WildcardIPs(ctx, root)
	if len(wildcard) > 0 {
		log.Warn("wildcard DNS detected; wildcard-synthesised addresses will be ignored", "ips", len(wildcard))
	}
	log.Info("resolving hosts", "hosts", len(hosts), "workers", s.cfg.DNS.Workers, "qps", s.cfg.DNS.QPS)
	results := s.resolveAll(ctx, hosts)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if s.res.Unreachable() {
		return fmt.Errorf("no DNS resolver is reachable from this machine (check firewall / DNS settings); nothing stored, will retry")
	}
	live, failed := 0, 0
	for _, hr := range results {
		if !hr.NX {
			live++
		}
		if len(hr.Failed) > 0 {
			failed++
		}
	}
	log.Info("resolution finished", "resolved", len(results), "exist", live, "with_lookup_errors", failed)

	// 3. ASN / ownership mapping
	ips := collectIPs(hosts, results, wildcard)
	s.prog("Mapping IPs to owners", 65, fmt.Sprintf("%d addresses", len(ips)))
	asns := s.asn.LookupMany(ctx, ips)
	asnComplete := !s.cfg.ASN.Enabled || len(asns) == len(ips)

	// 4. Email-auth posture (only when the underlying lookups succeeded)
	s.prog("Checking email and DNS settings", 70, "SPF, DMARC, DKIM, MTA-STS, CAA, DNSSEC")
	mail := s.emailPosture(ctx, root, hosts, results)
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// 4b. Exposure intelligence + registration data (optional third-party lookups)
	s.prog("Exposure intelligence", 76, "Shodan / InternetDB / RDAP lookups")
	intel := s.gatherIntel(ctx, t, hosts, results, wildcard, ips)
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// 4c. Active checks (opt-in): look at the web services themselves
	act := s.gatherActive(ctx, t, hosts, results, wildcard, asns)
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// 4d. Wider discovery (optional): look-alikes, related domains, leaked accounts, public code
	ext := s.gatherExtra(ctx, t, disc, results, wildcard)
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// 4e. Cloud / SaaS inventory, from the DNS answers already collected (no extra traffic)
	cloud := detectCloud(root, hosts, results)
	prevCloud := loadCloudInventory(s.store, root)

	// 5. Persist + diff atomically
	s.prog("Saving results", 92, "comparing with previous scan")
	tx, err := s.store.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	now := nowUTC()
	silent := !baselined // inventory deltas are recorded but not alerted during baseline
	st := &s.stats
	st.Hosts = len(hosts)
	var perr error
	check := func(err error) {
		if err != nil && perr == nil {
			perr = err
		}
	}
	emit := func(kind, sev, host, detail string, inventory bool) {
		quiet := inventory && silent
		if !quiet {
			s.newEvents++
		}
		check(tx.AddEvent(Event{TS: now, Root: root, Kind: kind, Severity: sev, Host: host, Detail: detail,
			NoAlert: removalKinds[kind] && !s.cfg.Alerts.Removals}, quiet))
	}
	seen := map[string]bool{}
	raise := func(key, kind, sev, host, detail, source string) {
		seen[key] = true
		isNew, err := tx.UpsertFinding(root, key, kind, sev, host, detail, source, now)
		check(err)
		if isNew {
			st.Findings++
			emit(kind, sev, host, detail, false) // findings are never silenced by baseline mode
		}
	}

	for _, h := range hosts {
		if fromStore[h] {
			continue // not mentioned by any source this time; its records are checked below
		}
		srcs := joinSources(disc.Hosts[h])
		isNew, err := tx.AddSubdomain(root, h, srcs, now)
		check(err)
		if isNew {
			st.Subdomains++
			if h != root {
				emit("subdomain", "info", h, "discovered via "+srcs, true)
			}
		}
	}

	certKeys := make([]string, 0, len(disc.Certs))
	for k := range disc.Certs {
		certKeys = append(certKeys, k)
	}
	sort.Strings(certKeys)
	for _, k := range certKeys {
		c := disc.Certs[k]
		isNew, err := tx.AddCert(root, c, now)
		check(err)
		if isNew {
			st.Certs++
			if s.cfg.Alerts.Certs {
				name := c.CommonName
				if name == "" && len(c.Names) > 0 {
					name = c.Names[0]
				}
				emit("cert", "info", name, fmt.Sprintf("issuer: %s | SANs: %s | valid %s → %s",
					truncate(c.Issuer, 80), truncate(strings.Join(c.Names, ", "), 200), c.NotBefore, c.NotAfter), true)
			}
		}
	}

	for _, h := range hosts {
		hr := results[h]
		if hr == nil {
			continue
		}
		var removed []Missing
		for _, rt := range recordTypes {
			present := map[string]bool{}
			for _, v := range hr.Records[rt] {
				present[v] = true
				if rt == "A" || rt == "AAAA" {
					if _, w := wildcard[v]; w {
						continue
					}
				}
				state, err := tx.SeeRecord(root, h, rt, v, now)
				check(err)
				if state == recSame {
					continue
				}
				st.Records++
				if rt == "TXT" && !s.cfg.Alerts.TXT {
					continue
				}
				detail := rt + " " + v
				if info := asns[v]; info != nil && (rt == "A" || rt == "AAAA") {
					detail += "  (" + info.String() + ")"
				}
				if state == recReturned {
					detail = "returned: " + detail
				}
				emit("dns-"+strings.ToLower(rt), recordSeverity[rt], h, detail, true)
			}
			// Only a lookup that really worked can show that something is gone.
			if hr.NX || !hr.Failed[rt] {
				gone, err := tx.MissRecords(h, rt, present, s.cfg.Alerts.RemovalMisses, now)
				check(err)
				removed = append(removed, gone...)
			}
		}
		if len(removed) > 0 {
			live, err := tx.HostHasLiveRecords(h)
			check(err)
			if hr.NX && !live && h != root {
				if changed, err := tx.MarkHostGone(root, h, now); err != nil {
					check(err)
				} else if changed {
					emit("host-gone", "info", h, fmt.Sprintf("%s no longer exists in DNS (%d record(s) removed: %s)", h, len(removed), describeMissing(removed)), true)
				}
			} else {
				for _, m := range removed {
					if m.Type == "TXT" && !s.cfg.Alerts.TXT {
						continue
					}
					emit("dns-removed", recordSeverity[m.Type], h, m.Type+" "+m.Value+" removed", true)
				}
			}
			st.Removed += len(removed)
		}

		// Dangling CNAME => potential subdomain takeover.
		if hr.Dangling != "" {
			sev := "low"
			detail := fmt.Sprintf("%s has a published CNAME record pointing to %s, but %s does not exist (NXDOMAIN). "+
				"Tools like nslookup also report NXDOMAIN for %s itself because they follow the alias to the missing target; "+
				"the alias record is real and still published", h, hr.Dangling, hr.Dangling, h)
			if p := takeoverProvider(hr.Dangling); p != "" {
				sev = "high"
				detail += fmt.Sprintf(". The target is on %q, a platform where anyone can claim an unused name, so this is a takeover risk", p)
			} else {
				detail += ". No known claim-able platform was recognised, so this is mainly a stale record unless the target domain has lapsed and could be registered by someone else"
			}
			raise("dangle:"+h+":"+hr.Dangling, "dangling-cname", sev, h, detail, "")
		}

		for _, rt := range []string{"A", "AAAA"} {
			for _, ip := range hr.Records[rt] {
				if _, w := wildcard[ip]; w {
					continue
				}
				info := asns[ip]
				if info == nil {
					continue
				}
				if info.Private {
					raise("priv:"+h+":"+ip, "private-ip", "low", h,
						fmt.Sprintf("%s record %s is a non-public address published in public DNS", rt, ip), "")
					continue
				}
				if t.hasOwnershipRules() && !t.owns(info) {
					raise("asn:"+root+":"+ip, "asn-unexpected", "high", h,
						fmt.Sprintf("%s %s is announced by %s — outside the expected ownership for %s", rt, ip, info.String(), root), "")
				}
			}
		}
	}

	check(s.applyCloud(tx, root, cloud, prevCloud, emit, raise))

	check(s.applyIntel(tx, t, intel, asns, now, emit, raise, seen))
	check(s.applyActive(tx, root, act, now, emit, raise))
	check(s.applyExtra(tx, t, ext, now, emit, raise))

	for _, is := range mail.issues {
		raise("email:"+is.Host+":"+is.Code, "email-auth", is.Severity, is.Host, is.Detail, "")
	}

	// Auto-resolve findings that no longer reproduce, but only when this scan could
	// actually observe the thing (a DNS timeout must not "fix" a finding).
	open, err := tx.OpenFindings(root)
	check(err)
	for _, f := range open {
		if seen[f.Key] {
			continue
		}
		reliable := false
		switch f.Kind {
		case "email-auth":
			reliable = mail.reliable(f.Host, f.Key[strings.LastIndex(f.Key, ":")+1:])
		case "exposed-service", "known-vuln", "ip-flagged", "eol-software", "domain-expiry":
			reliable = intel.reliableFor(f.Kind, f.Key, failed == 0)
		case "tls-expired", "tls-expiring", "tls-hostname", "tls-untrusted", "tls-legacy", "default-page", "exposed-path", "no-https-redirect", "bucket-public", "bucket-takeover":
			reliable = act.reliableFor(f.Key)
			if hr := results[f.Host]; !reliable && act != nil && act.enabled && hr != nil && hr.NX && len(hr.Failed) == 0 {
				reliable = true // the host no longer exists, so what was wrong with it is gone too
			}
		case "lookalike-domain", "leaked-credentials", "repo-exposure":
			reliable = ext.reliableFor(f.Kind, f.Key)
		default:
			if hr := results[f.Host]; hr != nil {
				reliable = hr.NX || len(hr.Failed) == 0
				if f.Kind == "asn-unexpected" || f.Kind == "private-ip" {
					reliable = reliable && asnComplete
				}
			}
		}
		if reliable {
			check(tx.ResolveFinding(f.ID, now))
			st.Resolved++
			emit("finding-resolved", "info", f.Host, fmt.Sprintf("%s no longer present: %s", f.Kind, truncate(f.Detail, 200)), true)
		}
	}

	baselineDone := false
	if !baselined && disc.Complete {
		check(tx.SetBaselined(root, now))
		baselineDone = true
	}
	if perr != nil {
		return fmt.Errorf("persist: %w", perr)
	}
	if err := tx.Commit(); err != nil {
		return err
	}

	log.Info("scan complete", "hosts", st.Hosts, "new_subdomains", st.Subdomains, "new_records", st.Records,
		"new_certs", st.Certs, "new_findings", st.Findings, "resolved_findings", st.Resolved, "baseline_mode", silent,
		"duration", time.Since(start).Round(time.Second).String())
	if silent && !baselineDone {
		log.Warn("baseline NOT finalised: crt.sh did not succeed this scan; staying in silent baseline mode")
	}
	if baselineDone {
		log.Info("baseline established; subsequent scans alert on deltas only")
		s.sendBaselineSummary(ctx, root)
	}
	return nil
}

// removalKinds are the event kinds that report something disappearing.
var removalKinds = map[string]bool{"dns-removed": true, "host-gone": true, "service-removed": true, "finding-resolved": true}

// describeMissing lists removed records briefly.
func describeMissing(ms []Missing) string {
	var parts []string
	for i, m := range ms {
		if i == 6 {
			parts = append(parts, fmt.Sprintf("and %d more", len(ms)-6))
			break
		}
		parts = append(parts, m.Type+" "+truncate(m.Value, 60))
	}
	return strings.Join(parts, ", ")
}
