package main

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Confirming an exposed-service finding with a direct connection.
//
// Exposed-service findings come from third-party data (Shodan, InternetDB, Censys),
// which can be days old. "Confirm via active scan" connects to the one address and
// port the finding names, the way `Test-NetConnection -Port` or `nc -v` would,
// and reads whatever the service announces first (its banner). It is done in Go
// rather than by running PowerShell or netcat so no shell is ever started from the
// web interface and it works the same on Windows and Linux.

// Outcomes of a service check.
const (
	verifyOpen     = "open"     // the TCP connection was accepted
	verifyClosed   = "closed"   // the host answered and refused the port
	verifyFiltered = "filtered" // no answer in time: a firewall drops it, or the host is down
)

const (
	verifyDialTimeout   = 5 * time.Second
	verifyBannerTimeout = 3 * time.Second
	verifyBannerMax     = 200
)

// dialService is the connection seam (tests point it at local listeners).
var dialService = func(ctx context.Context, addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: verifyDialTimeout}
	return d.DialContext(ctx, "tcp", addr)
}

// ServiceCheck is the result of one confirmation attempt.
type ServiceCheck struct {
	State     string
	Banner    string
	LatencyMs int64
	Error     string
}

// checkService connects to ip:port and reads the service's opening banner, if it sends one.
// It never writes to the service.
func checkService(ctx context.Context, ip string, port int) ServiceCheck {
	t0 := time.Now()
	conn, err := dialService(ctx, net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		var ne net.Error
		switch {
		case errors.Is(err, syscall.ECONNREFUSED) || strings.Contains(strings.ToLower(err.Error()), "refused"):
			return ServiceCheck{State: verifyClosed, LatencyMs: time.Since(t0).Milliseconds(), Error: "connection refused"}
		case errors.As(err, &ne) && ne.Timeout(), errors.Is(err, context.DeadlineExceeded):
			return ServiceCheck{State: verifyFiltered, LatencyMs: time.Since(t0).Milliseconds(), Error: "no answer within " + verifyDialTimeout.String()}
		default:
			return ServiceCheck{State: verifyFiltered, LatencyMs: time.Since(t0).Milliseconds(), Error: err.Error()}
		}
	}
	defer func() { _ = conn.Close() }()
	res := ServiceCheck{State: verifyOpen, LatencyMs: time.Since(t0).Milliseconds()}
	_ = conn.SetReadDeadline(time.Now().Add(verifyBannerTimeout))
	buf := make([]byte, 512)
	n, _ := conn.Read(buf) // many services (HTTP, SMB, RDP) wait for the client and send nothing: that is fine
	res.Banner = cleanBanner(buf[:n])
	return res
}

// cleanBanner keeps a short, printable, single-line form of a service banner, so
// nothing a remote service sends can break the page or the audit log.
func cleanBanner(b []byte) string {
	var sb strings.Builder
	space := false
	for _, c := range b {
		switch {
		case c == '\r' || c == '\n' || c == '\t' || c == ' ':
			space = sb.Len() > 0
		case c >= 0x21 && c <= 0x7e:
			if space {
				sb.WriteByte(' ')
				space = false
			}
			sb.WriteByte(c)
		default:
			space = sb.Len() > 0 // binary protocols: drop the bytes
		}
		if sb.Len() >= verifyBannerMax {
			break
		}
	}
	return strings.TrimSpace(sb.String())
}

// serviceTarget extracts the address and port an exposed-service finding names (key "svc:<ip>:<port>").
func serviceTarget(f *Finding) (ip string, port int, ok bool) {
	if f.Kind != "exposed-service" || !strings.HasPrefix(f.Key, "svc:") {
		return "", 0, false
	}
	rest := strings.TrimPrefix(f.Key, "svc:")
	i := strings.LastIndexByte(rest, ':')
	if i <= 0 {
		return "", 0, false
	}
	ip, ps := rest[:i], rest[i+1:]
	p, err := strconv.Atoi(ps)
	if err != nil || p < 1 || p > 65535 || net.ParseIP(ip) == nil {
		return "", 0, false
	}
	return ip, p, true
}

// maxAutoConfirm caps how many ports one "Confirm open ports" run connects to.
const maxAutoConfirm = 100

// recheckAfter is how long an automatic check's result stands before an
// unconfirmed finding is checked again.
const recheckAfter = 7 * 24 * time.Hour

// Why confirmOpenPorts runs.
const (
	confirmFirstScan = "first scan"    // the "Confirm open ports" box when the domain was added: every open port
	confirmAuto      = "corroboration" // after a scan with active checks on: unconfirmed ports only
)

// confirmOpenPorts runs checkService on open exposed-service findings of a
// domain. On the first scan (the "Confirm open ports" box) it checks them all;
// after later scans with active checks on, only those no second source has
// confirmed, so a port reported by Shodan alone is tested before it is trusted.
// Addresses outside the expected ownership are skipped unless foreign is allowed,
// as for a manual check.
func (e *Engine) confirmOpenPorts(ctx context.Context, t *Target, foreign bool, why string) {
	fs, err := e.store.ListFindings(t.Domain, "open")
	if err != nil {
		e.log.Warn("confirm open ports: cannot list findings", "domain", t.Domain, "err", err)
		return
	}
	done, skipped, nowTrusted := 0, 0, 0
	for i := range fs {
		f := &fs[i]
		ip, port, ok := serviceTarget(f)
		if !ok {
			continue
		}
		if why == confirmAuto && (f.Trust == trustTrusted || recentlyChecked(f.VerifyAt)) {
			continue
		}
		if ctx.Err() != nil || done >= maxAutoConfirm {
			break
		}
		if strings.Contains(f.Detail, "outside the expected ownership") && !foreign {
			skipped++
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		res := checkService(cctx, ip, port)
		cancel()
		level, err := e.store.RecordVerification(f, res.State, res.Banner, why)
		if err != nil {
			e.log.Warn("confirm open ports: cannot store result", "err", err)
			continue
		}
		if level == trustTrusted {
			nowTrusted++
		}
		detail := res.State
		if res.Banner != "" {
			detail += "; banner: " + res.Banner
		}
		how := " (Confirm open ports, first scan of " + t.Domain + ")"
		if why == confirmAuto {
			how = " (automatic check of an unconfirmed port after a scan of " + t.Domain + ")"
		}
		_ = e.store.Audit("system", "system", "finding.verify", net.JoinHostPort(ip, strconv.Itoa(port)), detail+how, "")
		done++
	}
	e.log.Info("open ports checked", "domain", t.Domain, "why", why, "checked", done, "trusted", nowTrusted, "skipped_outside_ownership", skipped)
}

// recentlyChecked reports whether an active check ran within recheckAfter.
func recentlyChecked(at string) bool {
	t, err := time.Parse(time.RFC3339, at)
	return err == nil && time.Since(t) < recheckAfter
}

// verifyLabel words a stored check result for the findings table.
func verifyLabel(state string) string {
	switch state {
	case verifyOpen:
		return "Verified open by active scan"
	case verifyClosed:
		return "Active scan: port closed"
	case verifyFiltered:
		return "Active scan: no response"
	}
	return ""
}
