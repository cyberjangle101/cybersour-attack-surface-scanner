package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

// fakeAD is a tiny LDAP server that behaves like the parts of Active Directory the agent uses:
// simple bind, user and group search, StartTLS, nested groups through the in-chain matching rule.
// Like a real directory, it accepts a bind with a DN and an EMPTY password as an anonymous bind,
// so the tests prove the agent never sends one.
type fakeAD struct {
	t      *testing.T
	ln     net.Listener
	tlsCfg *tls.Config
	CAPEM  string
	ldaps  bool

	mu      sync.Mutex
	baseDN  string
	svcDN   string
	svcPW   string
	users   map[string]*fakeUser  // by lowercase DN
	groups  map[string]*fakeGroup // by lowercase DN
	filters []string
	binds   []string // DNs bound with a password the server verified
	emptyPW int      // binds seen with a DN and an empty password
}

type fakeUser struct {
	DN, Sam, UPN, Password string
	Disabled               bool
	MemberOf               []string
}

type fakeGroup struct {
	DN, Name string
	MemberOf []string
}

func newFakeAD(t *testing.T, ldaps bool) *fakeAD {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fake-dc"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeAD{t: t, ldaps: ldaps, baseDN: "DC=corp,DC=example,DC=com", svcDN: "CN=svc-easm,OU=Svc,DC=corp,DC=example,DC=com", svcPW: "svc-secret-pw",
		users: map[string]*fakeUser{}, groups: map[string]*fakeGroup{}}
	f.CAPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	f.tlsCfg = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
	f.ln, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.ln.Close() })
	go f.serve()
	return f
}

// Addr is the host:port to configure. "localhost" matches the certificate name.
func (f *fakeAD) Addr() string {
	_, p, _ := net.SplitHostPort(f.ln.Addr().String())
	return "localhost:" + p
}

func (f *fakeAD) addGroup(name string, memberOf ...string) string {
	dn := "CN=" + name + ",OU=Groups," + f.baseDN
	f.mu.Lock()
	defer f.mu.Unlock()
	f.groups[strings.ToLower(dn)] = &fakeGroup{DN: dn, Name: name, MemberOf: memberOf}
	return dn
}

func (f *fakeAD) addUser(sam, password string, memberOf ...string) *fakeUser {
	u := &fakeUser{DN: "CN=" + sam + ",OU=People," + f.baseDN, Sam: sam, UPN: sam + "@corp.example.com", Password: password, MemberOf: memberOf}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.users[strings.ToLower(u.DN)] = u
	return u
}

func (f *fakeAD) set(fn func()) { f.mu.Lock(); fn(); f.mu.Unlock() }

func (f *fakeAD) bindCount(dn string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, b := range f.binds {
		if strings.EqualFold(b, dn) {
			n++
		}
	}
	return n
}

func (f *fakeAD) serve() {
	for {
		c, err := f.ln.Accept()
		if err != nil {
			return
		}
		go f.conn(c)
	}
}

func (f *fakeAD) conn(c net.Conn) {
	defer func() { _ = c.Close() }()
	if f.ldaps {
		c = tls.Server(c, f.tlsCfg)
	}
	for {
		p, err := ber.ReadPacket(c)
		if err != nil || len(p.Children) < 2 {
			return
		}
		id, _ := p.Children[0].Value.(int64)
		op := p.Children[1]
		switch op.Tag {
		case ldap.ApplicationBindRequest:
			dn := op.Children[1].Value.(string)
			pw := op.Children[2].Data.String()
			_, _ = c.Write(f.bind(id, dn, pw))
		case ldap.ApplicationSearchRequest:
			f.search(c, id, op)
		case ldap.ApplicationExtendedRequest:
			if op.Children[0].Data.String() == "1.3.6.1.4.1.1466.20037" {
				_, _ = c.Write(result(id, ldap.ApplicationExtendedResponse, 0, ""))
				c = tls.Server(c, f.tlsCfg)
				continue
			}
			_, _ = c.Write(result(id, ldap.ApplicationExtendedResponse, 2, "unsupported"))
		case ldap.ApplicationUnbindRequest:
			return
		default:
			return
		}
	}
}

func result(id int64, tag ber.Tag, code int64, diag string) []byte {
	env := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	env.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, "MessageID"))
	r := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "")
	r.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, code, "resultCode"))
	r.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
	r.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, diag, "diagnosticMessage"))
	env.AppendChild(r)
	return env.Bytes()
}

func (f *fakeAD) bind(id int64, dn, pw string) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	if dn != "" && pw == "" {
		f.emptyPW++
		return result(id, ldap.ApplicationBindResponse, 0, "") // "unauthenticated bind" succeeds on many servers
	}
	if strings.EqualFold(dn, f.svcDN) && pw == f.svcPW {
		f.binds = append(f.binds, dn)
		return result(id, ldap.ApplicationBindResponse, 0, "")
	}
	if u := f.users[strings.ToLower(dn)]; u != nil && u.Password == pw && !u.Disabled {
		f.binds = append(f.binds, dn)
		return result(id, ldap.ApplicationBindResponse, 0, "")
	}
	return result(id, ldap.ApplicationBindResponse, 49, "invalid credentials")
}

// chain returns every group a user belongs to, directly or through nesting.
func (f *fakeAD) chain(direct []string) map[string]bool {
	seen := map[string]bool{}
	var walk func(dn string)
	walk = func(dn string) {
		k := strings.ToLower(dn)
		if seen[k] {
			return
		}
		seen[k] = true
		if g := f.groups[k]; g != nil {
			for _, p := range g.MemberOf {
				walk(p)
			}
		}
	}
	for _, d := range direct {
		walk(d)
	}
	return seen
}

var (
	reSam   = regexp.MustCompile(`\(sAMAccountName=((?:[^()\\]|\\[0-9a-fA-F]{2})*)\)`)
	reUPN   = regexp.MustCompile(`\(userPrincipalName=((?:[^()\\]|\\[0-9a-fA-F]{2})*)\)`)
	reChain = regexp.MustCompile(`memberOf:1\.2\.840\.113556\.1\.4\.1941:=((?:[^()\\]|\\[0-9a-fA-F]{2})*)\)`)
	reCN    = regexp.MustCompile(`\(cn=((?:[^()\\]|\\[0-9a-fA-F]{2})*)\)`)
	reHex   = regexp.MustCompile(`\\([0-9a-fA-F]{2})`)
)

func unescapeFilter(s string) string {
	return reHex.ReplaceAllStringFunc(s, func(m string) string {
		n, _ := strconv.ParseUint(m[1:], 16, 8)
		return string([]byte{byte(n)})
	})
}

func entry(id int64, dn string, attrs map[string]string) []byte {
	env := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	env.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, "MessageID"))
	e := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultEntry, nil, "")
	e.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, "objectName"))
	list := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes")
	for k, v := range attrs {
		a := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attribute")
		a.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, k, "type"))
		vals := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "vals")
		vals.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, v, "val"))
		a.AppendChild(vals)
		list.AppendChild(a)
	}
	e.AppendChild(list)
	env.AppendChild(e)
	return env.Bytes()
}

func (f *fakeAD) search(c net.Conn, id int64, op *ber.Packet) {
	base := op.Children[0].Value.(string)
	flt, err := ldap.DecompileFilter(op.Children[6])
	if err != nil {
		_, _ = c.Write(result(id, ldap.ApplicationSearchResultDone, 2, "bad filter"))
		return
	}
	f.mu.Lock()
	f.filters = append(f.filters, flt)
	var out [][]byte
	switch {
	case reChain.MatchString(flt): // is <base user> a member of <group>?
		want := strings.ToLower(unescapeFilter(reChain.FindStringSubmatch(flt)[1]))
		if u := f.users[strings.ToLower(base)]; u != nil && f.chain(u.MemberOf)[want] {
			out = append(out, entry(id, u.DN, nil))
		}
	case strings.Contains(flt, "objectClass=group"):
		name := ""
		if m := reSam.FindStringSubmatch(flt); m != nil {
			name = unescapeFilter(m[1])
		}
		if m := reCN.FindStringSubmatch(flt); m != nil && name == "" {
			name = unescapeFilter(m[1])
		}
		for _, g := range f.groups {
			if strings.EqualFold(g.Name, name) {
				out = append(out, entry(id, g.DN, map[string]string{"distinguishedName": g.DN}))
			}
		}
	case strings.Contains(flt, "objectClass=*"):
		if strings.EqualFold(base, f.baseDN) {
			out = append(out, entry(id, f.baseDN, nil))
		}
	case reSam.MatchString(flt):
		want := strings.ToLower(unescapeFilter(reSam.FindStringSubmatch(flt)[1]))
		if m := reUPN.FindStringSubmatch(flt); m != nil && strings.ToLower(unescapeFilter(m[1])) != want {
			want = "\x00" // inconsistent filter: match nothing
		}
		for _, u := range f.users {
			if (strings.ToLower(u.Sam) == want || strings.ToLower(u.UPN) == want) && !(u.Disabled && strings.Contains(flt, "userAccountControl")) {
				out = append(out, entry(id, u.DN, map[string]string{"sAMAccountName": u.Sam, "userPrincipalName": u.UPN}))
			}
		}
	}
	f.mu.Unlock()
	for _, e := range out {
		_, _ = c.Write(e)
	}
	_, _ = c.Write(result(id, ldap.ApplicationSearchResultDone, 0, ""))
}
