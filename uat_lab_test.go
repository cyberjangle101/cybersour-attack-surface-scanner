package main

import (
	"context"
	"fmt"
	"github.com/miekg/dns"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// TestLab starts the whole application against a made-up company ("acme-corp.test")
// with realistic weaknesses, so a person or a browser script can try the web interface.
// It only runs when EASM_LAB=1 and stops when the file /tmp/lab.stop appears.
func TestLab(t *testing.T) {
	if os.Getenv("EASM_LAB") == "" {
		t.Skip("set EASM_LAB=1 to run the interactive lab")
	}
	e := newWebEnv(t)
	h := e.harness
	d := h.dns
	for _, rr := range []string{
		"acme-corp.test. 60 IN A 203.0.113.10",
		`acme-corp.test. 60 IN TXT "v=spf1 include:_spf.acme-corp.test ~all"`,
		"acme-corp.test. 60 IN MX 10 mail.acme-corp.test.",
		"acme-corp.test. 60 IN NS ns1.acme-corp.test.",
		"www.acme-corp.test. 60 IN A 203.0.113.10",
		"mail.acme-corp.test. 60 IN A 203.0.113.11",
		"vpn.acme-corp.test. 60 IN A 203.0.113.20",
		"dev.acme-corp.test. 60 IN A 198.51.100.7",
		"api.acme-corp.test. 60 IN A 203.0.113.30",
		"intranet.acme-corp.test. 60 IN A 10.0.0.5",
		"staging.acme-corp.test. 60 IN CNAME acme-staging.herokuapp.com.",
		"old-shop.acme-corp.test. 60 IN CNAME shop-legacy.example.net.",
		`_dmarc.acme-corp.test. 60 IN TXT "v=DMARC1; p=none"`,
	} {
		d.add(t, rr)
	}
	d.addIP(t, "203.0.113.10", 64500, "203.0.113.0/24", "ACME-NET")
	d.addIP(t, "203.0.113.11", 64500, "203.0.113.0/24", "ACME-NET")
	d.addIP(t, "203.0.113.20", 64500, "203.0.113.0/24", "ACME-NET")
	d.addIP(t, "203.0.113.30", 64500, "203.0.113.0/24", "ACME-NET")
	d.addIP(t, "198.51.100.7", 64999, "198.51.100.0/24", "CHEAP-HOSTING-LTD")
	h.src.addCert("acme-corp.test", "www.acme-corp.test", "mail.acme-corp.test")
	h.src.addCert("jira.acme-corp.test", "vpn.acme-corp.test", "dev.acme-corp.test") // jira no longer resolves
	h.src.addAnubis("api.acme-corp.test", "staging.acme-corp.test", "old-shop.acme-corp.test", "intranet.acme-corp.test")
	h.intel.idb["203.0.113.10"] = idbBody("203.0.113.10", []int{80, 443}, nil, nil)
	h.intel.idb["203.0.113.20"] = idbBody("203.0.113.20", []int{443, 3389, 445}, []string{"CVE-2019-0708", "CVE-2020-0796"}, []string{"eol-os", "self-signed"})
	h.intel.idb["198.51.100.7"] = idbBody("198.51.100.7", []int{22, 3306, 9200}, []string{"CVE-2021-44228"}, []string{"database"})
	h.intel.idb["203.0.113.30"] = idbBody("203.0.113.30", []int{443, 8443}, nil, nil)
	h.intel.rdap["acme-corp.test"] = rdapBody(time.Now().Add(12 * 24 * time.Hour))

	ln, err := net.Listen("tcp", "127.0.0.1:18100")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: e.web.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.eng.Run(ctx)
	_ = os.Remove("/tmp/lab.stop")
	_ = os.WriteFile("/tmp/lab.ready", []byte("ready"), 0o600)
	for i := 0; i < 2400; i++ { // up to 40 minutes
		var b strings.Builder
		for i, m := range h.smtp.all() {
			fmt.Fprintf(&b, "=== mail %d ===\n%s\n", i+1, m)
		}
		_ = os.WriteFile("/tmp/lab-mails.txt", []byte(b.String()), 0o600)
		if _, err := os.Stat("/tmp/lab.mutate"); err == nil {
			_ = os.Remove("/tmp/lab.mutate")
			// A week later: a new forgotten host appears, RDP is closed, a database port opens, a certificate is issued.
			d.add(t, "payments.acme-corp.test. 60 IN A 198.51.100.99")
			d.addIP(t, "198.51.100.99", 64999, "198.51.100.0/24", "CHEAP-HOSTING-LTD")
			h.src.addCert("payments.acme-corp.test", "pay.acme-corp.test")
			h.intel.idb["203.0.113.20"] = idbBody("203.0.113.20", []int{443, 445}, []string{"CVE-2019-0708", "CVE-2020-0796"}, []string{"eol-os"})
			h.intel.idb["203.0.113.30"] = idbBody("203.0.113.30", []int{443, 8443, 6379}, nil, nil)
			d.remove("www.acme-corp.test.", dns.TypeA)
		}
		if _, err := os.Stat("/tmp/lab.stop"); err == nil {
			return
		}
		time.Sleep(time.Second)
	}
}
