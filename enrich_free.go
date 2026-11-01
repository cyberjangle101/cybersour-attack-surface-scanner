package main

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Free, keyless intelligence: SANS Internet Storm Center and FIRST EPSS.

// iscHost asks the SANS Internet Storm Center whether an address has been reported
// attacking its DShield sensors, and which threat feeds list it. It is an independent
// source for "address flagged as malicious", so it can corroborate Shodan's tags.
func (e *Enricher) iscHost(ctx context.Context, ip string) (*IPIntel, error) {
	var r struct {
		IP struct {
			Count       flexInt `json:"count"`
			Attacks     flexInt `json:"attacks"` // distinct DShield sensors it reached
			MaxDate     string  `json:"maxdate"`
			ASName      string  `json:"asname"`
			ThreatFeeds map[string]struct {
				LastSeen string `json:"lastseen"`
			} `json:"threatfeeds"`
		} `json:"ip"`
	}
	raw, err := e.getJSONRaw(ctx, e.urls.isc+url.PathEscape(ip)+"?json", nil, &r)
	if err != nil {
		if errors.Is(err, errNoData) {
			return &IPIntel{IP: ip, Source: "isc"}, nil
		}
		return nil, err
	}
	in := &IPIntel{IP: ip, Source: "isc", Org: truncate(r.IP.ASName, 80), Raw: raw}
	now := time.Now()
	flagged := false
	// Reports are always kept as evidence, but only flag the address when they are recent and
	// numerous: shared infrastructure (CDN, mail and VPN egress, recycled cloud addresses)
	// collects a few stray reports over the years, while a compromised host scanning the
	// internet reaches many sensors within days.
	if n := max(int(r.IP.Count), int(r.IP.Attacks)); n > 0 {
		in.Tags = append(in.Tags, "isc-reports:"+strconv.Itoa(n))
		if r.IP.MaxDate != "" {
			in.Tags = append(in.Tags, "isc-last:"+truncate(r.IP.MaxDate, 10))
		}
		flagged = iscRecentDate(r.IP.MaxDate, now) && int(r.IP.Attacks) >= iscMinTargets
	}
	feeds := make([]string, 0, len(r.IP.ThreatFeeds))
	for name, f := range r.IP.ThreatFeeds {
		n := truncate(strings.ToLower(name), 40)
		feeds = append(feeds, "isc-feed:"+n)
		if label, bad := iscCompromisedFeeds[n]; bad && iscRecentDate(f.LastSeen, now) {
			feeds = append(feeds, "isc-listed:"+label)
			flagged = true
		}
	}
	sort.Strings(feeds)
	in.Tags = append(in.Tags, feeds...)
	if flagged {
		in.Tags = append(in.Tags, "isc-attacker")
	}
	return in, nil
}

// iscRecent is how fresh a SANS ISC report or listing must be to count: addresses change hands,
// and a listing from years ago says nothing about who uses the address now.
const iscRecent = 30 * 24 * time.Hour

// iscMinTargets is how many distinct DShield sensors an address must have reached before its
// reports flag it (GitHub Pages, for one, has a few dozen over five years).
const iscMinTargets = 100

// iscRecentDate reports whether an ISC date (YYYY-MM-DD, possibly with a time) is within iscRecent.
// A missing or unreadable date is not recent: an undated listing cannot show the address is bad now.
func iscRecentDate(s string, now time.Time) bool {
	if len(s) < 10 {
		return false
	}
	d, err := time.Parse("2006-01-02", s[:10])
	return err == nil && now.Sub(d) <= iscRecent && d.Before(now.Add(48*time.Hour))
}

// iscCompromisedFeeds are the threat feeds ISC aggregates that list hosts seen acting
// as compromised machines or attackers. Others (Tor, spam, scanners, research
// projects) say nothing about whether a host was taken over, so they only appear as evidence.
var iscCompromisedFeeds = map[string]string{
	"emergincompromised": "Emerging Threats compromised hosts",
	"ciarmy":             "CINS Army bad actors",
}

// flexInt reads a count that a service sends as a number, a string or null.
type flexInt int

func (f *flexInt) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		*f = 0
		return nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		*f = 0
		return nil //nolint:nilerr // an unreadable count is treated as none, not as a failed lookup
	}
	*f = flexInt(n)
	return nil
}

// iscSummary words what SANS ISC reported, from the tags iscHost set ("" when nothing).
func iscSummary(tags []string) string {
	reports, last := "", ""
	var lists []string
	for _, t := range tags {
		switch {
		case strings.HasPrefix(t, "isc-reports:"):
			reports = strings.TrimPrefix(t, "isc-reports:")
		case strings.HasPrefix(t, "isc-last:"):
			last = strings.TrimPrefix(t, "isc-last:")
		case strings.HasPrefix(t, "isc-listed:"):
			lists = append(lists, strings.TrimPrefix(t, "isc-listed:"))
		}
	}
	var parts []string
	if reports != "" {
		s := "SANS ISC has " + reports + " report(s) of it attacking DShield sensors"
		if last != "" {
			s += ", most recently " + last
		}
		parts = append(parts, s)
	}
	if len(lists) > 0 {
		parts = append(parts, "SANS ISC's threat feeds list it on "+strings.Join(lists, " and "))
	}
	return strings.Join(parts, "; ")
}

// ---- EPSS ----

// epssBatch is how many CVEs go in one EPSS request (the API accepts a comma-separated list).
const epssBatch = 100

// epssMaxPerScan caps EPSS requests in one scan.
const epssMaxPerScan = 5

// epssCache keeps scores for a day: they are recomputed daily upstream.
var epssCache = struct {
	sync.Mutex
	m map[string]epssScore
}{m: map[string]epssScore{}}

type epssScore struct {
	Score float64
	At    time.Time
}

// EPSS returns FIRST's probability (0-1) that each CVE is exploited in the next 30 days.
// CVEs it does not know are left out. A failure returns what is cached.
func (e *Enricher) EPSS(ctx context.Context, cves []string) (map[string]float64, error) {
	out := map[string]float64{}
	var todo []string
	epssCache.Lock()
	for _, c := range dedupe(cves) {
		if s, ok := epssCache.m[c]; ok && time.Since(s.At) < 24*time.Hour {
			out[c] = s.Score
		} else if cveIDRe.MatchString(c) {
			todo = append(todo, c)
		}
	}
	epssCache.Unlock()
	sort.Strings(todo)
	var firstErr error
	for i := 0; i < len(todo) && i/epssBatch < epssMaxPerScan; i += epssBatch {
		batch := todo[i:min(i+epssBatch, len(todo))]
		var r struct {
			Data []struct {
				CVE  string `json:"cve"`
				EPSS string `json:"epss"`
			} `json:"data"`
		}
		t0 := time.Now()
		err := e.getJSON(ctx, e.urls.epss+"?cve="+url.QueryEscape(strings.Join(batch, ",")), nil, &r)
		e.health.Record("epss", e.via, err == nil, time.Since(t0), err)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("EPSS: %w", err)
			}
			break
		}
		now := time.Now()
		epssCache.Lock()
		for _, d := range r.Data {
			if f, err := strconv.ParseFloat(d.EPSS, 64); err == nil && f >= 0 && f <= 1 {
				id := strings.ToUpper(d.CVE)
				out[id] = f
				epssCache.m[id] = epssScore{f, now}
			}
		}
		epssCache.Unlock()
	}
	return out, firstErr
}
