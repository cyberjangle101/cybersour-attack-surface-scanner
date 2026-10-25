package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"testing"
)

// listen starts a local TCP service that sends banner (if any) to each client.
func listen(t *testing.T, banner string) (ip string, port int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if banner != "" {
				_, _ = c.Write([]byte(banner))
			}
			buf := make([]byte, 1)
			_, _ = c.Read(buf) // hold the connection until the client closes it
			_ = c.Close()
		}
	}()
	a := ln.Addr().(*net.TCPAddr)
	return a.IP.String(), a.Port
}

// closedPort returns a local port with nothing listening on it.
func closedPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return p
}

func TestCheckService(t *testing.T) {
	ip, port := listen(t, "SSH-2.0-OpenSSH_9.6\r\n")
	if r := checkService(testCtx(t), ip, port); r.State != verifyOpen || r.Banner != "SSH-2.0-OpenSSH_9.6" {
		t.Errorf("open with banner: %+v", r)
	}
	ip, port = listen(t, "")
	if r := checkService(testCtx(t), ip, port); r.State != verifyOpen || r.Banner != "" {
		t.Errorf("open without banner: %+v", r)
	}
	if r := checkService(testCtx(t), "127.0.0.1", closedPort(t)); r.State != verifyClosed {
		t.Errorf("closed port: %+v", r)
	}
	old := dialService
	defer func() { dialService = old }()
	dialService = func(context.Context, string) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: timeoutErr{}}
	}
	if r := checkService(testCtx(t), "192.0.2.1", 445); r.State != verifyFiltered {
		t.Errorf("no answer: %+v", r)
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestCleanBanner(t *testing.T) {
	cases := map[string]string{
		"220 mail.example.test ESMTP Postfix\r\n": "220 mail.example.test ESMTP Postfix",
		"\x00\x01\xffSMB\x72\x00":                 "SMBr",
		"<script>alert(1)</script>\n\tnext":       "<script>alert(1)</script> next", // escaped by html/template, kept readable
		"\x1b[31mred\x1b[0m":                      "[31mred [0m",
		strings.Repeat("A", 1000):                 strings.Repeat("A", verifyBannerMax),
	}
	for in, want := range cases {
		if got := cleanBanner([]byte(in)); got != want {
			t.Errorf("cleanBanner(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestServiceTarget(t *testing.T) {
	for _, c := range []struct {
		f      Finding
		ip     string
		port   int
		wantOK bool
	}{
		{Finding{Kind: "exposed-service", Key: "svc:203.0.113.5:445"}, "203.0.113.5", 445, true},
		{Finding{Kind: "exposed-service", Key: "svc:2001:db8::1:3389"}, "2001:db8::1", 3389, true},
		{Finding{Kind: "exposed-service", Key: "svc:not-an-ip:22"}, "", 0, false},
		{Finding{Kind: "exposed-service", Key: "svc:203.0.113.5:70000"}, "", 0, false},
		{Finding{Kind: "email-auth", Key: "svc:203.0.113.5:25"}, "", 0, false},
	} {
		ip, port, ok := serviceTarget(&c.f)
		if ok != c.wantOK || ip != c.ip || port != c.port {
			t.Errorf("%s: got %s %d %v", c.f.Key, ip, port, ok)
		}
	}
}

// insertFinding stores a finding directly, as a scan would.
func insertFinding(t *testing.T, e *webEnv, key, kind, host, detail, source string) int64 {
	t.Helper()
	now := nowUTC()
	res, err := e.store.db.Exec(`INSERT INTO findings(key,root,kind,severity,scan_sev,host,detail,first_seen,last_seen,source) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		key, "example.test", kind, "high", "high", host, detail, now, now, source)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()
	return id
}

func TestConfirmFindingViaActiveScan(t *testing.T) {
	e := newWebEnv(t)
	admin := e.browser()
	admin.setup("admin", "correct horse battery")
	an := e.signedIn("ana", RoleAnalyst)
	e.addTarget("example.test", "")

	ip, port := listen(t, "220 files.example.test FTP ready\r\n")
	open := insertFinding(t, e, fmt.Sprintf("svc:%s:%d", ip, port), "exposed-service", "files.example.test",
		fmt.Sprintf("FTP (port %d) is reachable from the internet on files.example.test (%s)", port, ip), "Shodan")
	closed := insertFinding(t, e, fmt.Sprintf("svc:127.0.0.1:%d", closedPort(t)), "exposed-service", "smb.example.test",
		"SMB (port 445) is reachable from the internet", "InternetDB")
	foreign := insertFinding(t, e, "svc:192.0.2.10:3389", "exposed-service", "rdp.example.test",
		"RDP (port 3389) is reachable from the internet on rdp.example.test (192.0.2.10, on a network outside the expected ownership)", "Shodan")
	other := insertFinding(t, e, "email:example.test:no-dmarc", "email-auth", "example.test", "No DMARC record", "")

	// Before: analysts see the evidence source but no button; admins get the button.
	if _, body, _ := an.get("/findings"); !strings.Contains(body, "Not verified by an active scan (from Shodan)") || strings.Contains(body, "Confirm via active scan") {
		t.Error("analyst view: status shown, button hidden")
	}
	if _, body, _ := admin.get("/findings"); strings.Count(body, ">Confirm via active scan<") != 3 {
		t.Error("admins should get the button on every exposed-service finding (and only those)")
	}
	if code, _, _ := an.post(fmt.Sprintf("/findings/%d/verify", open), nil); code != 403 {
		t.Errorf("analyst verify: %d", code)
	}
	if code, _, _ := admin.postRaw(fmt.Sprintf("/findings/%d/verify", open), url.Values{}); code != 403 {
		t.Errorf("verify without CSRF: %d", code)
	}

	admin.post(fmt.Sprintf("/findings/%d/verify", open), url.Values{"next": {"/findings"}})
	_, body, _ := admin.get("/findings")
	for _, want := range []string{"Confirmed:", "Verified open by active scan", "Banner: 220 files.example.test FTP ready"} {
		if !strings.Contains(body, want) {
			t.Errorf("after confirming an open port the page lacks %q", want)
		}
	}
	admin.post(fmt.Sprintf("/findings/%d/verify", closed), nil)
	if _, body, _ = admin.get("/findings"); !strings.Contains(body, "Active scan: port closed") {
		t.Error("closed port not shown")
	}

	// Outside the expected ownership: refused unless Settings allow it, and nothing is contacted.
	dialed := false
	old := dialService
	t.Cleanup(func() { dialService = old })
	dialService = func(context.Context, string) (net.Conn, error) { dialed = true; return nil, errors.New("refused") }
	admin.post(fmt.Sprintf("/findings/%d/verify", foreign), nil)
	if _, body, _ = admin.get("/findings"); dialed || !strings.Contains(body, "was not contacted") {
		t.Error("an address outside the expected ownership must not be probed by default")
	}
	st, _ := e.store.LoadSettings()
	st.ActiveForeign = true
	e.saveSettings(st)
	admin.post(fmt.Sprintf("/findings/%d/verify", foreign), nil)
	if !dialed {
		t.Error("with probing outside ownership allowed, the check should run")
	}
	dialService = old

	admin.post(fmt.Sprintf("/findings/%d/verify", other), nil)
	if _, body, _ = admin.get("/findings"); !strings.Contains(body, "Only exposed-service findings") {
		t.Error("non-port findings must be refused")
	}

	fs, _ := e.store.ListFindings("", "")
	for _, f := range fs {
		if f.ID == open && (f.VerifyState != verifyOpen || f.VerifyBy != "admin" || f.VerifyAt == "") {
			t.Errorf("stored result: %+v", f)
		}
		if f.ID == other && f.VerifyState != "" {
			t.Error("a refused check must store nothing")
		}
	}
	if _, au, _ := admin.get("/audit"); strings.Count(au, "finding.verify") < 3 {
		t.Error("each check must be audited")
	}
}
