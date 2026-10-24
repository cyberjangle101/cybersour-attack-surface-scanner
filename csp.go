package main

import (
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// contentSecurityPolicy returns the Content-Security-Policy sent with every
// response. The interface needs nothing from other origins and no inline code,
// so every resource type is either limited to this site or switched off, and
// the directives that have no fallback to default-src are all set explicitly.
func contentSecurityPolicy(upgradeInsecure bool) string {
	d := []string{
		"default-src 'none'",                 // anything not listed below is blocked
		"script-src 'self'",                  // only /static/app.js; no inline scripts, no eval
		"style-src 'self'",                   // only /static/app.css; no inline styles
		"img-src 'self' data:",               // data: is used by small inline icons
		"font-src 'none'",                    // system fonts only
		"connect-src 'self'",                 // the progress poll talks to this site only
		"media-src 'none'",                   // no audio or video
		"object-src 'none'",                  // no plug-ins
		"frame-src 'none'",                   // never embeds other pages
		"child-src 'none'",                   // no frames or workers from anywhere
		"worker-src 'none'",                  // no web workers
		"manifest-src 'none'",                // not an installable web app
		"form-action 'self'",                 // forms can only post back to this site
		"frame-ancestors 'none'",             // no other site may frame this one (clickjacking)
		"base-uri 'none'",                    // <base> cannot redirect relative links
		"require-trusted-types-for 'script'", // blocks DOM-based script injection sinks
		"report-uri /csp-report",             // violations are logged by this agent
		"report-to csp",
	}
	if upgradeInsecure {
		d = append(d, "upgrade-insecure-requests")
	}
	return strings.Join(d, "; ")
}

// permissionsPolicy switches off every browser feature the interface does not use.
const permissionsPolicy = "accelerometer=(), autoplay=(), camera=(), clipboard-read=(), display-capture=(), " +
	"fullscreen=(), geolocation=(), gyroscope=(), hid=(), magnetometer=(), microphone=(), midi=(), " +
	"payment=(), publickey-credentials-get=(), serial=(), usb=(), xr-spatial-tracking=()"

// setSecurityHeaders adds the browser-hardening headers to a response.
func setSecurityHeaders(h http.Header, tls bool) {
	h.Set("Content-Security-Policy", contentSecurityPolicy(tls))
	h.Set("Reporting-Endpoints", `csp="/csp-report"`)
	h.Set("Permissions-Policy", permissionsPolicy)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY") // older browsers that ignore frame-ancestors
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Cross-Origin-Embedder-Policy", "require-corp")
	h.Set("X-Permitted-Cross-Domain-Policies", "none")
	h.Set("Origin-Agent-Cluster", "?1")
}

// cspReports logs policy violations that browsers report, so a blocked
// resource (or an injection attempt) is visible in the agent's log.
type cspReports struct {
	log  interface{ Warn(string, ...any) }
	mu   sync.Mutex
	last time.Time
}

// maxCSPReport is the largest report body that is read; browsers send well under 2 KB.
const maxCSPReport = 8 << 10

// ServeHTTP accepts a report (no sign-in is possible for browser-initiated
// reports), logs it at most once every 5 seconds, and answers 204.
func (c *cspReports) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, maxCSPReport))
	w.WriteHeader(http.StatusNoContent)
	c.mu.Lock()
	now := time.Now()
	ok := now.Sub(c.last) > 5*time.Second
	if ok {
		c.last = now
	}
	c.mu.Unlock()
	if ok && c.log != nil {
		report := strings.Map(func(r rune) rune {
			if r < 0x20 || r == 0x7f {
				return ' '
			}
			return r
		}, string(body))
		c.log.Warn("content security policy violation reported by the browser", "report", report)
	}
}
