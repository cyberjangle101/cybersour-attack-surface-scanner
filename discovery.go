package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand" // nosemgrep: go.lang.security.audit.crypto.math_random.math-random-used -- retry jitter only, not security-sensitive
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxBody = 512 << 20 // 512 MiB hard ceiling on any passive-source response

// CertInfo describes one certificate found in Certificate Transparency logs.
type CertInfo struct {
	Key        string // serial|issuer_ca_id — collapses precert/final-cert duplicates
	CommonName string
	Names      []string
	Issuer     string
	NotBefore  string
	NotAfter   string
	CrtShID    int64
	Others     []string // other names on the certificate that are outside the target (for related-domain suggestions)
}

// Discovery is the combined output of all passive sources for one domain.
type Discovery struct {
	Hosts    map[string]map[string]struct{} // host -> set of sources
	Certs    map[string]CertInfo
	OK       map[string]bool
	AnyOK    bool
	Complete bool // safe to treat the baseline as fully captured
}

// sourceURLs holds the base URLs of the passive sources (overridable in tests).
type sourceURLs struct{ crtsh, hackertarget, otx, anubis string }

// Discoverer queries the passive subdomain sources (crt.sh, HackerTarget, OTX, Anubis and the optional keyed ones) and merges the results.
type Discoverer struct {
	cfg  *Config
	log  *slog.Logger
	hc   *http.Client
	urls sourceURLs // overridable in tests

	health *HealthBoard
	enr    *Enricher // optional keyed sources (Shodan DNS, VirusTotal)

	progress func(done, total int, pending []string) // optional
}

// NewDiscoverer creates a Discoverer with sensible HTTP timeouts.
func NewDiscoverer(cfg *Config, log *slog.Logger) *Discoverer {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSHandshakeTimeout = 20 * time.Second
	return &Discoverer{cfg: cfg, log: log, hc: &http.Client{Transport: tr}, urls: sourceURLs{
		crtsh:        "https://crt.sh/",
		hackertarget: "https://api.hackertarget.com/hostsearch/",
		otx:          "https://otx.alienvault.com/api/v1/indicators/domain/",
		anubis:       "https://jonlu.ca/anubis/subdomains/", // jldc.me now 301-redirects here
	}}
}

// permanentError marks a failure that must not be retried (e.g. an exhausted quota).
type permanentError struct{ error }

// permanent wraps err so retry gives up immediately.
func permanent(err error) error { return permanentError{err} }

// Unwrap exposes the underlying error.
func (p permanentError) Unwrap() error { return p.error }

// retry runs fn with exponential backoff + jitter. fn returns (retryable, err).
func retry(ctx context.Context, log *slog.Logger, name string, attempts int, base, ceiling time.Duration, fn func(context.Context) (bool, error)) error {
	var err error
	for i := 0; i < attempts; i++ {
		var again bool
		again, err = fn(ctx)
		if err == nil {
			return nil
		}
		if !again || i == attempts-1 || ctx.Err() != nil {
			return err
		}
		backoff := base << min(i, 20) // capped shift: no overflow
		if backoff > ceiling || backoff <= 0 {
			backoff = ceiling
		}
		backoff += time.Duration(rand.Int63n(int64(backoff/2) + 1)) //nolint:gosec // G404: retry jitter, not security-sensitive
		log.Warn("source request failed, will retry", "source", name, "attempt", i+1, "of", attempts,
			"backoff", backoff.Round(time.Second).String(), "err", err)
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return err
}

// reqOpts adds per-source request headers, and a check that turns a refusal (a bot-challenge
// page, a "please authenticate" body) into a clear error that is not retried.
type reqOpts struct {
	header  map[string]string
	refused func(status int, body []byte) error
}

// getWithRetry GETs u and passes the body to handle, retrying transient failures (timeouts, 429, 5xx, truncated bodies) with exponential backoff and jitter.
func (d *Discoverer) getWithRetry(ctx context.Context, name, u string, opts *reqOpts, attempts int, base, ceiling, timeout time.Duration, handle func(io.Reader) error) error {
	return retry(ctx, d.log, name, attempts, base, ceiling, func(ctx context.Context) (bool, error) {
		cctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		req, err := http.NewRequestWithContext(cctx, http.MethodGet, u, nil)
		if err != nil {
			return false, err
		}
		req.Header.Set("User-Agent", d.cfg.Sources.UserAgent)
		req.Header.Set("Accept", "application/json, text/plain, */*")
		if opts != nil {
			for k, v := range opts.header {
				req.Header.Set(k, v)
			}
		}
		resp, err := d.hc.Do(req)
		if err != nil {
			return ctx.Err() == nil, err // timeouts / resets are retryable
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK && opts != nil && opts.refused != nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
			if err := opts.refused(resp.StatusCode, body); err != nil {
				return false, err
			}
		}
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
			return true, fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		if resp.StatusCode != http.StatusOK {
			return false, fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		if err := handle(io.LimitReader(resp.Body, maxBody)); err != nil {
			var pe permanentError
			return !errors.As(err, &pe), err // truncated/garbled bodies are retryable
		}
		return false, nil
	})
}

type srcResult struct {
	name  string
	hosts []string
	certs []CertInfo
	err   error
	took  time.Duration
}

type sourceFn func(ctx context.Context, root string) ([]string, []CertInfo, error)

func hostsOnly(f func(context.Context, string) ([]string, error)) sourceFn {
	return func(ctx context.Context, root string) ([]string, []CertInfo, error) {
		h, err := f(ctx, root)
		return h, nil, err
	}
}

// Discover runs every enabled source in parallel and merges hosts and certificates. AnyOK tells whether at least one source worked; Complete whether crt.sh (the authoritative one) did.
func (d *Discoverer) Discover(ctx context.Context, root string) *Discovery {
	out := &Discovery{Hosts: map[string]map[string]struct{}{}, Certs: map[string]CertInfo{}, OK: map[string]bool{}}
	type job struct {
		name string
		fn   sourceFn
	}
	var jobs []job
	sc := d.cfg.Sources
	if sc.CrtSh.Enabled {
		jobs = append(jobs, job{"crtsh", d.fetchCrtSh})
	}
	if sc.HackerTarget.Enabled {
		jobs = append(jobs, job{"hackertarget", hostsOnly(d.fetchHackerTarget)})
	}
	if sc.OTX.Enabled {
		jobs = append(jobs, job{"otx", hostsOnly(d.fetchOTX)})
	}
	if sc.Anubis.Enabled {
		jobs = append(jobs, job{"anubis", hostsOnly(d.fetchAnubis)})
	}

	if d.enr != nil {
		in := d.cfg.Intel
		if in.Shodan.Enabled && in.Shodan.DomainLookup {
			jobs = append(jobs, job{"shodan-dns", hostsOnly(d.enr.ShodanSubdomains)})
		}
		if in.VirusTotal.Enabled {
			jobs = append(jobs, job{"virustotal", hostsOnly(d.enr.VirusTotalSubdomains)})
		}
	}

	pending := map[string]bool{}
	for _, j := range jobs {
		pending[j.name] = true
	}
	report := func(done int) {
		if d.progress == nil {
			return
		}
		var p []string
		for _, j := range jobs {
			if pending[j.name] {
				p = append(p, j.name)
			}
		}
		d.progress(done, len(jobs), p)
	}
	report(0)

	ch := make(chan srcResult, len(jobs))
	for _, j := range jobs {
		go func(j job) {
			start := time.Now()
			h, c, err := j.fn(ctx, root)
			ch <- srcResult{name: j.name, hosts: h, certs: c, err: err, took: time.Since(start)}
		}(j)
	}
	for n := range jobs {
		r := <-ch
		delete(pending, r.name)
		report(n + 1)
		d.health.Record(r.name, "scan", r.err == nil, r.took, r.err)
		if r.err != nil {
			// A failing source (e.g. crt.sh timing out) must never take the daemon down.
			d.log.Warn("discovery source failed", "domain", root, "source", r.name, "err", r.err, "took", r.took.Round(time.Millisecond).String())
			continue
		}
		out.OK[r.name] = true
		out.AnyOK = true
		added := 0
		for _, h := range r.hosts {
			h = normalizeHost(h)
			if h == "" || !inScope(h, root) {
				continue
			}
			if out.Hosts[h] == nil {
				out.Hosts[h] = map[string]struct{}{}
			}
			out.Hosts[h][r.name] = struct{}{}
			added++
		}
		for _, c := range r.certs {
			out.Certs[c.Key] = c
		}
		d.log.Info("discovery source finished", "domain", root, "source", r.name, "hosts", added, "certs", len(r.certs), "took", r.took.Round(time.Millisecond).String())
	}
	if sc.CrtSh.Enabled {
		out.Complete = out.OK["crtsh"]
	} else {
		out.Complete = out.AnyOK
	}
	return out
}

// ---- crt.sh ----

// crtRow is one row of crt.sh's JSON output.
type crtRow struct {
	ID           int64  `json:"id"`
	IssuerCAID   int64  `json:"issuer_ca_id"`
	IssuerName   string `json:"issuer_name"`
	CommonName   string `json:"common_name"`
	NameValue    string `json:"name_value"`
	NotBefore    string `json:"not_before"`
	NotAfter     string `json:"not_after"`
	SerialNumber string `json:"serial_number"`
}

// fetchCrtSh downloads and parses crt.sh results for root.
func (d *Discoverer) fetchCrtSh(ctx context.Context, root string) ([]string, []CertInfo, error) {
	cfg := d.cfg.Sources.CrtSh
	u := d.urls.crtsh + "?q=" + url.QueryEscape("%."+root) + "&output=json"
	var hosts []string
	var certs []CertInfo
	err := d.getWithRetry(ctx, "crtsh", u, nil, cfg.MaxAttempts, cfg.BaseBackoff, cfg.MaxBackoff, cfg.Timeout, func(r io.Reader) (err error) {
		// Reset per attempt: a failed attempt may have produced a partial list.
		hosts, certs, err = parseCrtSh(r, root)
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	return hosts, certs, nil
}

// parseCrtSh streams crt.sh's JSON array (big domains return hundreds of MB), keeping only
// names inside root and collapsing precert/final-cert duplicates. It is a pure function so it
// can be fuzzed.
func parseCrtSh(r io.Reader, root string) ([]string, []CertInfo, error) {
	var hosts []string
	var certs []CertInfo
	seenCert := map[string]bool{}
	dec := json.NewDecoder(r)
	tok, err := dec.Token()
	if err == io.EOF {
		return nil, nil, nil // empty body: no certificates logged
	}
	if err != nil {
		return nil, nil, fmt.Errorf("decode: %w", err)
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '[' {
		return nil, nil, fmt.Errorf("unexpected JSON start %v", tok)
	}
	for dec.More() {
		var row crtRow
		if err := dec.Decode(&row); err != nil {
			return nil, nil, fmt.Errorf("decode row: %w", err)
		}
		var names, others []string
		for _, n := range strings.Split(row.NameValue+"\n"+row.CommonName, "\n") {
			n = strings.ToLower(strings.TrimSpace(n))
			h := normalizeHost(strings.TrimPrefix(n, "*."))
			if h != "" && !inScope(h, root) {
				others = append(others, h)
			}
			h = normalizeHost(n)
			if h == "" || !inScope(h, root) {
				continue
			}
			hosts = append(hosts, h)
			names = append(names, strings.TrimSuffix(n, "."))
		}
		if len(names) == 0 {
			continue
		}
		key := fmt.Sprintf("%s|%d", strings.ToLower(row.SerialNumber), row.IssuerCAID)
		if seenCert[key] {
			continue
		}
		seenCert[key] = true
		certs = append(certs, CertInfo{
			Key: key, CommonName: row.CommonName, Names: dedupe(names), Issuer: row.IssuerName,
			NotBefore: row.NotBefore, NotAfter: row.NotAfter, CrtShID: row.ID, Others: dedupe(others),
		})
	}
	if _, err := dec.Token(); err != nil {
		return nil, nil, fmt.Errorf("truncated response: %w", err)
	}
	return hosts, certs, nil
}

// dedupe removes duplicates while keeping the first-seen order.
func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// ---- HackerTarget (free tier: ~50 queries/day/IP — fine for a handful of roots) ----

func (d *Discoverer) fetchHackerTarget(ctx context.Context, root string) ([]string, error) {
	return d.fetchHosts(ctx, "hackertarget", d.urls.hackertarget+"?q="+url.QueryEscape(root), nil, parseHackerTarget)
}

// fetchHosts runs the common "GET, parse into host names, retry on transient failure" flow
// shared by the simple free sources.
func (d *Discoverer) fetchHosts(ctx context.Context, name, u string, opts *reqOpts, parse func(io.Reader) ([]string, error)) ([]string, error) {
	var hosts []string
	err := d.getWithRetry(ctx, name, u, opts, 3, 5*time.Second, time.Minute, 60*time.Second, func(r io.Reader) (err error) {
		hosts, err = parse(r)
		return err
	})
	return hosts, err
}

// parseHackerTarget reads "host,ip" lines; quota and error messages are permanent failures.
func parseHackerTarget(r io.Reader) ([]string, error) {
	var hosts []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		low := strings.ToLower(line)
		switch {
		case line == "":
			continue
		case strings.HasPrefix(low, "error"), strings.Contains(low, "api count exceeded"):
			return nil, permanent(errors.New(line))
		case strings.HasPrefix(low, "no records"):
			continue
		}
		hosts = append(hosts, strings.SplitN(line, ",", 2)[0])
	}
	return hosts, sc.Err()
}

// ---- AlienVault OTX passive DNS (free API key) ----

func (d *Discoverer) fetchOTX(ctx context.Context, root string) ([]string, error) {
	opts := &reqOpts{header: map[string]string{"X-OTX-API-KEY": d.cfg.Sources.OTX.Key}, refused: otxRefused}
	return d.fetchHosts(ctx, "otx", d.urls.otx+url.PathEscape(root)+"/passive_dns", opts, parseOTX)
}

// otxRefused spots OTX turning a caller away for lack of a valid key. Anonymous callers get
// a 429 on the very first request, so retrying (or calling it rate limiting) is pointless.
func otxRefused(status int, body []byte) error {
	if status != http.StatusTooManyRequests && status != http.StatusUnauthorized && status != http.StatusForbidden {
		return nil
	}
	if !bytes.Contains(bytes.ToLower(body), []byte("authenticat")) {
		return nil
	}
	return fmt.Errorf("OTX turned the request away (HTTP status %d): it needs a valid free OTX API key, saved in Settings", status)
}

// parseOTX extracts host names from an AlienVault OTX passive-DNS response.
func parseOTX(r io.Reader) ([]string, error) {
	var p struct {
		PassiveDNS []struct {
			Hostname string `json:"hostname"`
		} `json:"passive_dns"`
	}
	if err := json.NewDecoder(r).Decode(&p); err != nil {
		return nil, err
	}
	var hosts []string
	for _, e := range p.PassiveDNS {
		hosts = append(hosts, e.Hostname)
	}
	return hosts, nil
}

// ---- Anubis (jonlu.ca, formerly jldc.me) free subdomain dataset ----

func (d *Discoverer) fetchAnubis(ctx context.Context, root string) ([]string, error) {
	return d.fetchHosts(ctx, "anubis", d.urls.anubis+url.PathEscape(root), &reqOpts{refused: anubisRefused}, parseAnubis)
}

// anubisRefused spots the Cloudflare bot-challenge page jonlu.ca serves to every non-browser
// client. Solving it is not an option, so the error says the source is unusable instead.
func anubisRefused(status int, body []byte) error {
	if status != http.StatusForbidden && status != http.StatusServiceUnavailable {
		return nil
	}
	if !bytes.Contains(body, []byte("Cloudflare")) && !bytes.Contains(body, []byte("cf-chl")) {
		return nil
	}
	return errors.New("anubis (jonlu.ca) answers automated clients with a Cloudflare bot challenge, so it cannot be used: untick it in Settings")
}

func parseAnubis(r io.Reader) ([]string, error) {
	var hosts []string
	err := json.NewDecoder(r).Decode(&hosts)
	return hosts, err
}
