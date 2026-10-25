package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// RunHealthChecks actively probes every enabled connector once and records the
// results. Connectors with strict free-tier quotas are only tested for network
// reachability so that pressing the button never burns a daily allowance.
func (e *Engine) RunHealthChecks(ctx context.Context) {
	cfg, st, err := e.config()
	if err != nil {
		e.log.Error("health check: settings unreadable", "err", err)
		return
	}
	enr := NewEnricher(cfg.Intel, e.log, cfg.Sources.UserAgent)
	enr.health, enr.via = e.health, "check"
	if e.intelURLs != nil {
		enr.urls = *e.intelURLs()
	}

	var wg sync.WaitGroup
	run := func(id string, timeout time.Duration, fn func(context.Context) error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			t0 := time.Now()
			err := fn(cctx)
			if id != "" { // probes that record themselves pass ""
				e.health.Record(id, "check", err == nil, time.Since(t0), err)
			}
		}()
	}
	reach := func(host string) func(context.Context) error {
		return func(ctx context.Context) error {
			d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second}, Config: &tls.Config{MinVersion: tls.VersionTLS12}}
			c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, "443"))
			if err != nil {
				return err
			}
			return c.Close()
		}
	}
	if e.reachFn != nil {
		reach = e.reachFn
	}
	sources := []struct {
		id, host string
		on       bool
	}{
		{"crtsh", "crt.sh", st.CrtShEnabled}, {"hackertarget", "api.hackertarget.com", st.HackerTargetEnabled},
		{"otx", "otx.alienvault.com", st.OTXEnabled}, {"anubis", "jonlu.ca", st.AnubisEnabled},
	}
	for _, s := range sources {
		if s.on {
			run(s.id, 20*time.Second, reach(s.host))
		}
	}

	// DNS: one query per configured resolver, plus a Team Cymru origin lookup through them.
	for _, addr := range cfg.DNS.Resolvers {
		addr := addr
		run("", 15*time.Second, func(ctx context.Context) error {
			r := NewResolver(ctx, DNSCfg{Resolvers: []string{addr}, QPS: 20, Timeout: 5 * time.Second, Retries: 0})
			r.health, r.via = e.health, "check"
			_, err := r.query(ctx, "example.com", dns.TypeA)
			return err
		})
	}
	if st.ASNEnabled {
		run("asn-cymru", 20*time.Second, func(ctx context.Context) error {
			r := NewResolver(ctx, cfg.DNS)
			_, _, err := r.TXT(ctx, cymruOriginName(net.ParseIP("1.1.1.1")))
			return err
		})
		if st.ASNBGPViewFallback {
			run("asn-ripestat", 25*time.Second, func(ctx context.Context) error {
				a := NewASNResolver(cfg.ASN, nil, e.store, e.log)
				_, err := a.ripestat(ctx, "1.1.1.1")
				return err
			})
		}
	}

	if cfg.Intel.InternetDB {
		run("internetdb", 20*time.Second, func(ctx context.Context) error { _, err := enr.internetDB(ctx, "1.1.1.1"); return err })
	}
	if cfg.Intel.Shodan.Enabled {
		run("shodan", 20*time.Second, func(ctx context.Context) error {
			note, err := enr.shodanInfo(ctx)
			if err == nil {
				e.health.SetNote("shodan", note)
			}
			return err
		})
	}
	if cfg.Intel.Censys.Enabled {
		run("censys", 20*time.Second, func(ctx context.Context) error { _, err := enr.censysHost(ctx, "1.1.1.1"); return err })
	}
	if cfg.Intel.VirusTotal.Enabled {
		run("virustotal", 20*time.Second, func(ctx context.Context) error { return enr.virusTotalPing(ctx) })
	}
	if cfg.Intel.HIBP.Enabled {
		run("hibp", 20*time.Second, func(ctx context.Context) error { return enr.hibpPing(ctx) })
	}
	if cfg.Intel.GitHub.Enabled {
		run("github", 20*time.Second, func(ctx context.Context) error { return enr.githubPing(ctx) })
	}
	if cfg.Intel.RDAP {
		run("", 25*time.Second, func(ctx context.Context) error {
			_, err := enr.RDAPDomain(ctx, "example.com")
			return err
		})
	}
	if cfg.SMTP.Enabled && cfg.SMTP.Host != "" {
		run("", 2*cfg.SMTP.Timeout, func(ctx context.Context) error {
			return NewMailer(cfg.SMTP).WithHealth(e.health).Probe(ctx)
		})
	}
	wg.Wait()
	e.saveHealth()
}

// SystemInfo is the non-connector half of the Health page.
type SystemInfo struct {
	Version, Uptime, DBSize, Scanning, NextScan, DataDir string
	DBOK                                                 bool
	DBError                                              string
	Targets, Hosts                                       int
}

// SystemInfo is the agent half of the System health page (version, uptime, database, scheduler).
func (e *Engine) SystemInfo() SystemInfo {
	si := SystemInfo{Version: version, Uptime: time.Since(e.started).Round(time.Second).String(), Scanning: e.Current(), DataDir: e.dataDir}
	size, err := e.store.Ping()
	si.DBOK = err == nil
	if err != nil {
		si.DBError = err.Error()
	}
	si.DBSize = humanBytes(size)
	if n, err := e.store.NextScanTime(); err == nil {
		si.NextScan = n
	}
	if stt, err := e.store.Stats(); err == nil {
		si.Targets, si.Hosts = stt.Targets, stt.Hosts
	}
	return si
}

// humanBytes formats a size like 12.3 MB.
func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

var _ = errors.New
