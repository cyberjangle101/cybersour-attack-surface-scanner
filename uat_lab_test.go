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

func labListener(t *testing.T, banner string) string {
	ip, port := listen(t, banner)
	return net.JoinHostPort(ip, fmt.Sprint(port))
}

func labClosedPort(t *testing.T) string { return net.JoinHostPort("127.0.0.1", fmt.Sprint(closedPort(t))) }

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

	// slowco.test: a domain whose certificate search takes 90s, so pausing a scan or
	// restarting it with active checks can be tried while it runs.
	d.add(t, "slowco.test. 60 IN A 203.0.113.40")
	d.addIP(t, "203.0.113.40", 64500, "203.0.113.0/24", "ACME-NET")
	h.src.addCert("slowco.test", "www.slowco.test")
	h.src.mu.Lock()
	h.src.crtDelay = map[string]time.Duration{"slowco.test": 90 * time.Second}
	h.src.mu.Unlock()

	// "Confirm via active scan" reaches the lab's made-up internet hosts through local
	// listeners: vpn's SMB port answers (no banner, like real SMB), its RDP port is
	// closed, and dev's SSH port sends a banner. Nothing outside this machine is contacted.
	smb, closed := labListener(t, ""), labClosedPort(t)
	ssh := labListener(t, "SSH-2.0-OpenSSH_7.4 (lab)\r\n")
	route := map[string]string{"203.0.113.20:445": smb, "203.0.113.20:3389": closed, "198.51.100.7:22": ssh}
	oldDial := dialService
	defer func() { dialService = oldDial }()
	dialService = func(ctx context.Context, addr string) (net.Conn, error) {
		if to, ok := route[addr]; ok {
			addr = to
		} else {
			return nil, &net.OpError{Op: "dial", Net: "tcp", Err: timeoutErr{}}
		}
		var nd net.Dialer
		return nd.DialContext(ctx, "tcp", addr)
	}

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
	_ = os.WriteFile("/tmp/lab.setup-code", []byte(e.web.SetupCode()), 0o600) // nosemgrep: go.lang.security.bad_tmp.bad-tmp-file-creation -- the opt-in lab (EASM_LAB=1) hands its throwaway setup code to the UAT scripts, like its other /tmp control files
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
