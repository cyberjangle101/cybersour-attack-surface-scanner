package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// ---------------------------------------------------------------- fake DNS (also serves Team Cymru data)

type fakeDNS struct {
	mu       sync.Mutex
	servfail bool
	rrs      map[string][]dns.RR
	srv      *dns.Server
	addr     string
}

func newFakeDNS(t testing.TB) *fakeDNS {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeDNS{rrs: map[string][]dns.RR{}, addr: pc.LocalAddr().String()}
	started := make(chan struct{})
	f.srv = &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(f.serve), NotifyStartedFunc: func() { close(started) }}
	go func() { _ = f.srv.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = f.srv.Shutdown() })
	return f
}

func (f *fakeDNS) serve(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	if len(r.Question) > 0 {
		q := r.Question[0]
		f.mu.Lock()
		if f.servfail {
			m.Rcode = dns.RcodeServerFailure
		} else {
			f.answer(m, strings.ToLower(q.Name), q.Qtype, 0)
		}
		f.mu.Unlock()
	}
	_ = w.WriteMsg(m)
}

func (f *fakeDNS) answer(m *dns.Msg, name string, qtype uint16, depth int) {
	rrs, exists := f.rrs[name]
	if !exists { // wildcard: *.parent answers for any missing child
		if i := strings.Index(name, "."); i > 0 {
			if wr, ok := f.rrs["*."+name[i+1:]]; ok {
				exists = true
				cp := make([]dns.RR, len(wr))
				for j, rr := range wr {
					cp[j] = dns.Copy(rr)
					cp[j].Header().Name = name
				}
				rrs = cp
			}
		}
	}
	if !exists {
		m.Rcode = dns.RcodeNameError
		return
	}
	for _, rr := range rrs {
		if rr.Header().Rrtype == qtype {
			m.Answer = append(m.Answer, rr)
		}
	}
	if qtype != dns.TypeCNAME {
		for _, rr := range rrs {
			if c, ok := rr.(*dns.CNAME); ok && depth < 5 {
				m.Answer = append(m.Answer, rr)
				f.answer(m, strings.ToLower(c.Target), qtype, depth+1)
			}
		}
	}
}

func (f *fakeDNS) setServfail(b bool) { f.mu.Lock(); f.servfail = b; f.mu.Unlock() }

func (f *fakeDNS) add(t testing.TB, rr string) {
	t.Helper()
	r, err := dns.NewRR(rr)
	if err != nil {
		t.Fatalf("bad RR %q: %v", rr, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	k := strings.ToLower(r.Header().Name)
	f.rrs[k] = append(f.rrs[k], r)
}

func (f *fakeDNS) remove(owner string, rtype uint16) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := strings.ToLower(dns.Fqdn(owner))
	var keep []dns.RR
	for _, rr := range f.rrs[k] {
		if rr.Header().Rrtype != rtype {
			keep = append(keep, rr)
		}
	}
	if len(keep) == 0 {
		delete(f.rrs, k)
	} else {
		f.rrs[k] = keep
	}
}

// addIP publishes Team Cymru origin + AS-name records for an address.
func (f *fakeDNS) addIP(t testing.TB, ip string, asn int, prefix, org string) {
	t.Helper()
	p := net.ParseIP(ip).To4()
	f.add(t, fmt.Sprintf(`%d.%d.%d.%d.origin.asn.cymru.com. 60 IN TXT "%d | %s | US | arin | 2020-01-01"`, p[3], p[2], p[1], p[0], asn, prefix))
	f.mu.Lock()
	_, have := f.rrs[fmt.Sprintf("as%d.asn.cymru.com.", asn)]
	f.mu.Unlock()
	if !have {
		f.add(t, fmt.Sprintf(`AS%d.asn.cymru.com. 60 IN TXT "%d | US | arin | 2010-01-01 | %s, US"`, asn, asn, org))
	}
}

// ---------------------------------------------------------------- fake passive sources

type fakeSources struct {
	srv       *httptest.Server
	mu        sync.Mutex
	crt       []crtRow
	crtStatus int
	ht        []string
	otx       []string
	anubis    []string
	serial    int
	crtDelay  map[string]time.Duration // per root: how long crt.sh takes to answer
}

func newFakeSources(t testing.TB) *fakeSources {
	f := &fakeSources{}
	mux := http.NewServeMux()
	mux.HandleFunc("/crtsh/", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		delay := f.crtDelay[strings.TrimPrefix(r.URL.Query().Get("q"), "%.")]
		f.mu.Unlock()
		select {
		case <-time.After(delay):
		case <-r.Context().Done():
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.crtStatus != 0 {
			http.Error(w, "boom", f.crtStatus)
			return
		}
		root := strings.TrimPrefix(r.URL.Query().Get("q"), "%.")
		var out []crtRow
		for _, row := range f.crt {
			if strings.Contains(row.NameValue, root) {
				out = append(out, row)
			}
		}
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("/ht/", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		root := r.URL.Query().Get("q")
		for _, h := range f.ht {
			if strings.HasSuffix(h, root) {
				_, _ = fmt.Fprintf(w, "%s,198.18.0.1\n", h)
			}
		}
	})
	mux.HandleFunc("/otx/", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		type e struct {
			Hostname string `json:"hostname"`
		}
		var list []e
		for _, h := range f.otx {
			list = append(list, e{h})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"passive_dns": list})
	})
	mux.HandleFunc("/anubis/", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		root := strings.TrimPrefix(r.URL.Path, "/anubis/")
		out := []string{}
		for _, h := range f.anubis {
			if strings.HasSuffix(h, root) {
				out = append(out, h)
			}
		}
		_ = json.NewEncoder(w).Encode(out)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeSources) urls() sourceURLs {
	return sourceURLs{crtsh: f.srv.URL + "/crtsh/", hackertarget: f.srv.URL + "/ht/", otx: f.srv.URL + "/otx/", anubis: f.srv.URL + "/anubis/"}
}

func (f *fakeSources) addCert(names ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.serial++
	f.crt = append(f.crt, crtRow{ID: int64(1000 + f.serial), IssuerCAID: 1, IssuerName: "C=US, O=Test CA", CommonName: names[0],
		NameValue: strings.Join(names, "\n"), NotBefore: "2026-01-01T00:00:00", NotAfter: "2027-01-01T00:00:00",
		SerialNumber: fmt.Sprintf("%040x", f.serial)})
}

func (f *fakeSources) addAnubis(h ...string) {
	f.mu.Lock()
	f.anubis = append(f.anubis, h...)
	f.mu.Unlock()
}
func (f *fakeSources) setCrtStatus(c int) { f.mu.Lock(); f.crtStatus = c; f.mu.Unlock() }

// ---------------------------------------------------------------- fake SMTP server

type fakeSMTP struct {
	t        testing.TB
	ln       net.Listener
	addr     string
	tlsCfg   *tls.Config
	user     string
	pass     string
	implicit bool

	mu       sync.Mutex
	msgs     []string
	authSeen bool
	tlsSeen  bool
}

func newFakeSMTP(t testing.TB, tlsCfg *tls.Config) *fakeSMTP {
	t.Helper()
	return newFakeSMTPWith(t, tlsCfg, false, "", "")
}

// newFakeSMTPWith sets every option before the accept loop starts (no races).
func newFakeSMTPWith(t testing.TB, tlsCfg *tls.Config, implicit bool, user, pass string) *fakeSMTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeSMTP{t: t, tlsCfg: tlsCfg, implicit: implicit, user: user, pass: pass}
	s.listen(ln)
	t.Cleanup(func() { s.stop() })
	return s
}

func (s *fakeSMTP) listen(ln net.Listener) {
	s.ln, s.addr = ln, ln.Addr().String()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if s.implicit {
				c = tls.Server(c, s.tlsCfg)
			}
			go s.handle(c)
		}
	}()
}

func (s *fakeSMTP) stop() { _ = s.ln.Close() }

func (s *fakeSMTP) restart(t testing.TB) {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		t.Fatal(err)
	}
	s.listen(ln)
}

func (s *fakeSMTP) port() int {
	_, p, _ := net.SplitHostPort(s.addr)
	var n int
	_, _ = fmt.Sscan(p, &n)
	return n
}

func (s *fakeSMTP) count() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.msgs) }
func (s *fakeSMTP) all() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.msgs...)
}

func (s *fakeSMTP) handle(c net.Conn) {
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	conn := c
	r, w := bufio.NewReader(conn), conn
	say := func(l string) { _, _ = fmt.Fprintf(w, "%s\r\n", l) }
	say("220 fake ESMTP")
	isTLS := s.implicit
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			_, _ = fmt.Fprint(w, "250-fake\r\n")
			if s.tlsCfg != nil && !isTLS {
				_, _ = fmt.Fprint(w, "250-STARTTLS\r\n")
			}
			_, _ = fmt.Fprint(w, "250 AUTH PLAIN\r\n")
		case cmd == "STARTTLS":
			say("220 go ahead")
			tc := tls.Server(conn, s.tlsCfg)
			if err := tc.Handshake(); err != nil {
				return
			}
			conn, isTLS = tc, true
			r, w = bufio.NewReader(tc), tc
			s.mu.Lock()
			s.tlsSeen = true
			s.mu.Unlock()
		case strings.HasPrefix(cmd, "AUTH PLAIN"):
			parts := strings.Fields(strings.TrimSpace(line))
			raw, _ := base64.StdEncoding.DecodeString(parts[len(parts)-1])
			f := strings.Split(string(raw), "\x00")
			if len(f) == 3 && f[1] == s.user && f[2] == s.pass {
				s.mu.Lock()
				s.authSeen = true
				s.mu.Unlock()
				say("235 ok")
			} else {
				say("535 bad credentials")
			}
		case strings.HasPrefix(cmd, "MAIL FROM"), strings.HasPrefix(cmd, "RCPT TO"), cmd == "RSET":
			say("250 ok")
		case cmd == "DATA":
			say("354 go")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(strings.TrimPrefix(l, ".")) // un-dot-stuff
			}
			s.mu.Lock()
			s.msgs = append(s.msgs, b.String())
			s.mu.Unlock()
			say("250 queued")
		case cmd == "QUIT":
			say("221 bye")
			return
		default:
			say("502 unsupported")
		}
	}
}

func selfSignedTLS(t testing.TB) *tls.Config {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "127.0.0.1"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
}

type parsedMail struct{ Subject, Plain, HTML, Raw string }

func parseMail(t testing.TB, raw string) parsedMail {
	t.Helper()
	msg, err := mail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("parse mail: %v", err)
	}
	subj, _ := new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject"))
	mt, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || !strings.HasPrefix(mt, "multipart/") {
		t.Fatalf("not multipart: %q %v", mt, err)
	}
	pm := parsedMail{Subject: subj, Raw: raw}
	mr := multipart.NewReader(msg.Body, params["boundary"])
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(quotedprintable.NewReader(p))
		switch ct, _, _ := mime.ParseMediaType(p.Header.Get("Content-Type")); ct {
		case "text/plain":
			pm.Plain = string(b)
		case "text/html":
			pm.HTML = string(b)
		}
	}
	return pm
}

// ---------------------------------------------------------------- harness

type testWriter struct{ t testing.TB }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

type harness struct {
	t     testing.TB
	dir   string
	store *Store
	vault *Vault
	eng   *Engine
	dns   *fakeDNS
	src   *fakeSources
	smtp  *fakeSMTP
	intel *fakeIntel
	probe *Prober // when set, scans use it for active checks
	log   *slog.Logger
}

func newHarness(t testing.TB) *harness {
	t.Helper()
	dir := t.TempDir()
	vault, err := OpenVault(filepath.Join(dir, "easm.key"))
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenEncryptedStore(filepath.Join(dir, "easm.db"), vault.DBKey(), nil) // tests run against the encrypted store
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	log := slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelWarn}))
	if err := store.SetVault(vault); err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, dir: dir, store: store, vault: vault, log: log,
		eng: NewEngine(store, vault, log), dns: newFakeDNS(t), src: newFakeSources(t), smtp: newFakeSMTP(t, nil), intel: newFakeIntel(t)}
	h.eng.intelURLs = func() *intelURLs { u := h.intel.urls(); return &u }
	h.eng.healthEvery = 0 // automatic connector checks would reach the real internet
	h.eng.newScanner = func(cfg *Config, res *Resolver) *Scanner {
		sc := NewScanner(cfg, log, store, res)
		sc.disc.urls = h.src.urls()
		sc.enr.urls = h.intel.urls()
		sc.prober = h.probe
		cfg.Sources.CrtSh.BaseBackoff, cfg.Sources.CrtSh.MaxBackoff = 10*time.Millisecond, 20*time.Millisecond
		return sc
	}
	st := DefaultSettings()
	st.DNSResolvers = []string{h.dns.addr}
	st.DNSQPS, st.DNSTimeoutSeconds, st.DNSRetries, st.DNSWorkers = 2000, 1, 1, 8
	st.ASNBGPViewFallback = false
	st.DigestFrequency = "off"
	st.CrtShMaxAttempts = 2
	st.SMTPEnabled, st.SMTPHost, st.SMTPPort, st.SMTPSecurity = true, "127.0.0.1", h.smtp.port(), "none"
	st.SMTPFrom, st.SMTPTo = "EASM <easm@example.test>", []string{"sec@example.test"}
	h.saveSettings(st)
	return h
}

func (h *harness) saveSettings(st Settings) {
	h.t.Helper()
	if err := st.Normalize(); err != nil {
		h.t.Fatalf("settings invalid: %v", err)
	}
	if err := h.store.SaveSettings(st); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) mails() []parsedMail {
	var out []parsedMail
	for _, raw := range h.smtp.all() {
		out = append(out, parseMail(h.t, raw))
	}
	return out
}

func (h *harness) addTarget(domain, asns string) *Target {
	h.t.Helper()
	tg, err := TargetFromForm(domain, asns, "", "", "", "")
	if err != nil {
		h.t.Fatal(err)
	}
	id, err := h.store.AddTarget(tg)
	if err != nil {
		h.t.Fatal(err)
	}
	got, err := h.store.GetTarget(id)
	if err != nil {
		h.t.Fatal(err)
	}
	return got
}

func (h *harness) scan(id int64) *Target {
	h.t.Helper()
	tg, err := h.store.GetTarget(id)
	if err != nil {
		h.t.Fatal(err)
	}
	h.eng.ScanNow(testCtx(h.t), tg)
	tg, _ = h.store.GetTarget(id)
	return tg
}

func netIP(s string) net.IP { return net.ParseIP(s) }

// ---------------------------------------------------------------- fake exposure-intelligence services

type fakeIntel struct {
	srv *httptest.Server
	mu  sync.Mutex

	idb        map[string]string // ip -> JSON body (missing = 404)
	shodan     map[string]string
	shodanKey  string
	shodanDNS  []string
	censys     map[string]string
	censysTok  string
	vtSubs     []string
	vtKey      string
	rdap       map[string]string // domain -> JSON body (missing = 404)
	forceCode  map[string]int    // service name -> forced HTTP status
	hits       map[string]int
	keysSeenIn []string // raw query strings that carried a key (to prove they never reach logs)
}

func newFakeIntel(t testing.TB) *fakeIntel {
	f := &fakeIntel{idb: map[string]string{}, shodan: map[string]string{}, censys: map[string]string{}, rdap: map[string]string{},
		forceCode: map[string]int{}, hits: map[string]int{}}
	reply := func(w http.ResponseWriter, name string, body string, ok bool) {
		f.hits[name]++
		if c := f.forceCode[name]; c != 0 {
			http.Error(w, "forced", c)
			return
		}
		if !ok {
			http.Error(w, `{"detail":"No information available"}`, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/idb/", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		b, ok := f.idb[strings.TrimPrefix(r.URL.Path, "/idb/")]
		reply(w, "internetdb", b, ok)
	})
	mux.HandleFunc("/shodan/", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if k := r.URL.Query().Get("key"); k != f.shodanKey {
			f.hits["shodan-badkey"]++
			http.Error(w, `{"error":"Invalid API key"}`, http.StatusUnauthorized)
			return
		}
		f.keysSeenIn = append(f.keysSeenIn, r.URL.RawQuery)
		p := strings.TrimPrefix(r.URL.Path, "/shodan/")
		switch {
		case p == "api-info":
			reply(w, "shodan-info", `{"plan":"dev","query_credits":100,"scan_credits":5}`, true)
		case strings.HasPrefix(p, "dns/domain/"):
			subs, _ := json.Marshal(f.shodanDNS)
			reply(w, "shodan-dns", `{"subdomains":`+string(subs)+`,"more":false}`, true)
		case strings.HasPrefix(p, "shodan/host/"):
			b, ok := f.shodan[strings.TrimPrefix(p, "shodan/host/")]
			reply(w, "shodan", b, ok)
		default:
			http.NotFound(w, r)
		}
	})
	mux.HandleFunc("/censys/", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer "+f.censysTok {
			http.Error(w, "nope", http.StatusUnauthorized)
			return
		}
		b, ok := f.censys[strings.TrimPrefix(r.URL.Path, "/censys/")]
		reply(w, "censys", b, ok)
	})
	mux.HandleFunc("/vt/", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Header.Get("x-apikey") != f.vtKey {
			http.Error(w, "nope", http.StatusForbidden)
			return
		}
		var data []string
		for _, s := range f.vtSubs {
			data = append(data, `{"id":"`+s+`"}`)
		}
		reply(w, "virustotal", `{"data":[`+strings.Join(data, ",")+`],"meta":{}}`, true)
	})
	mux.HandleFunc("/rdap/", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		b, ok := f.rdap[strings.TrimPrefix(r.URL.Path, "/rdap/")]
		reply(w, "rdap", b, ok)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIntel) urls() intelURLs {
	return intelURLs{internetdb: f.srv.URL + "/idb/", shodan: f.srv.URL + "/shodan/", censys: f.srv.URL + "/censys/",
		virustotal: f.srv.URL + "/vt/", rdap: f.srv.URL + "/rdap/"}
}

func (f *fakeIntel) hitCount(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits[name]
}

func (f *fakeDNS) stop() { _ = f.srv.Shutdown() }

// runDueAndWait runs the scheduler pass and waits until every started scan has finished,
// repeating while targets are still due (the pool is bounded).
func (h *harness) runDueAndWait(t testing.TB) {
	t.Helper()
	for i := 0; i < 20; i++ {
		h.eng.runDue(testCtx(t))
		h.eng.wg.Wait()
		if due, _ := h.store.DueTargets(nowUTC()); len(due) == 0 {
			return
		}
	}
}
