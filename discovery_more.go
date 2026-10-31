package main

import (
	"context"
	"encoding/json"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// More free subdomain sources (no API key).
//
//   - CertSpotter: a second Certificate Transparency search. CT logs are the most complete
//     record of names that ever had a certificate; crt.sh is often slow or down, so a
//     second CT source keeps scans complete (see Discovery.Complete).
//   - urlscan.io: names seen in public scans submitted by anyone, which catches hosts
//     that never had a public certificate.
//   - Wayback Machine: names in archived URLs, which surfaces forgotten hosts. Slow for
//     large domains, so it is off unless switched on.

// certSpotterPages caps CertSpotter paging: the unauthenticated limit is 100 requests an hour.
const certSpotterPages = 5

func (d *Discoverer) fetchCertSpotter(ctx context.Context, root string) ([]string, error) {
	var hosts []string
	after := ""
	for page := 0; page < certSpotterPages; page++ {
		u := d.urls.certspotter + "?domain=" + url.QueryEscape(root) + "&include_subdomains=true&expand=dns_names"
		if after != "" {
			u += "&after=" + url.QueryEscape(after)
		}
		var rows []certSpotterRow
		err := d.getWithRetry(ctx, "certspotter", u, nil, 3, 10*time.Second, 2*time.Minute, 60*time.Second, func(r io.Reader) error {
			rows = nil
			return json.NewDecoder(r).Decode(&rows)
		})
		if err != nil {
			if len(hosts) > 0 {
				break // keep what the earlier pages gave
			}
			return nil, err
		}
		for _, row := range rows {
			hosts = append(hosts, row.DNSNames...)
		}
		if len(rows) == 0 {
			break
		}
		after = rows[len(rows)-1].ID
	}
	return hosts, nil
}

type certSpotterRow struct {
	ID       string   `json:"id"`
	DNSNames []string `json:"dns_names"`
}

func (d *Discoverer) fetchURLScan(ctx context.Context, root string) ([]string, error) {
	u := d.urls.urlscan + "?q=" + url.QueryEscape("domain:"+root) + "&size=1000"
	return d.fetchHosts(ctx, "urlscan", u, nil, parseURLScan)
}

// parseURLScan collects the page and task host names of urlscan.io search results.
func parseURLScan(r io.Reader) ([]string, error) {
	var res struct {
		Results []struct {
			Page struct {
				Domain string `json:"domain"`
			} `json:"page"`
			Task struct {
				Domain string `json:"domain"`
			} `json:"task"`
		} `json:"results"`
	}
	if err := json.NewDecoder(r).Decode(&res); err != nil {
		return nil, err
	}
	var hosts []string
	for _, x := range res.Results {
		hosts = append(hosts, x.Page.Domain, x.Task.Domain)
	}
	return hosts, nil
}

// waybackLimit caps how many archived URLs are read (big sites have millions).
const waybackLimit = 20000

func (d *Discoverer) fetchWayback(ctx context.Context, root string) ([]string, error) {
	u := d.urls.wayback + "?url=" + url.QueryEscape("*."+root+"/*") + "&output=json&fl=original&collapse=urlkey&limit=" + strconv.Itoa(waybackLimit)
	var hosts []string
	err := d.getWithRetry(ctx, "wayback", u, nil, 2, 10*time.Second, time.Minute, 120*time.Second, func(r io.Reader) (err error) {
		hosts, err = parseWayback(r)
		return err
	})
	return hosts, err
}

// parseWayback reads the CDX JSON (a header row, then one row per URL) into host names.
func parseWayback(r io.Reader) ([]string, error) {
	var rows [][]string
	if err := json.NewDecoder(r).Decode(&rows); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var hosts []string
	for i, row := range rows {
		if i == 0 || len(row) == 0 { // the header row names the fields
			continue
		}
		raw := row[0]
		if !strings.Contains(raw, "://") {
			raw = "http://" + raw
		}
		u, err := url.Parse(raw)
		if err != nil || u.Hostname() == "" {
			continue
		}
		h := strings.ToLower(u.Hostname())
		if !seen[h] {
			seen[h] = true
			hosts = append(hosts, h)
		}
	}
	return hosts, nil
}
