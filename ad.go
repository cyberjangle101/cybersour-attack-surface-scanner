package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
	"unicode"

	"github.com/go-ldap/ldap/v3"
)

// Active Directory sign-in.
//
// Users are authorised in one of two ways, both managed by an administrator:
//   - an explicit AD user: an account of kind "ad" whose role an administrator sets;
//   - an AD group: members of a mapped group get that group's role (the highest wins).
//
// The agent never stores an AD password. It looks the account up with a read-only service
// account, then proves the password by binding as the user.

const (
	metaADConfig = "ad_config"
	secretADBind = "secret:ad_bind"

	// DefaultADFilter finds an enabled person by sAMAccountName or userPrincipalName.
	DefaultADFilter = "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(|(sAMAccountName={username})(userPrincipalName={username})))"

	// matchingRuleInChain is the AD "transitive membership" rule: it matches nested groups too.
	matchingRuleInChain = "1.2.840.113556.1.4.1941"

	adTimeout = 10 * time.Second

	// Kinds of account.
	kindLocal   = "local"
	kindAD      = "ad"       // explicit AD user, role set by an administrator
	kindADGroup = "ad-group" // created at first sign-in from a group mapping; role follows the groups
)

// isAD reports whether the account signs in with a directory password.
func isAD(kind string) bool { return kind == kindAD || kind == kindADGroup }

// ADGroup maps a directory group to an application role.
type ADGroup struct {
	Group string // distinguished name, or a group name (sAMAccountName / cn)
	Role  string
}

// ADConfig is the directory connection and authorisation setup.
type ADConfig struct {
	Enabled    bool
	Servers    []string // host or host:port, tried in order
	Security   string   // ldaps | starttls
	SkipVerify bool     // do not check the server certificate (not recommended)
	CAPEM      string   // extra trusted certificate authority (PEM), for an internal CA
	BindDN     string   // read-only service account
	BaseDN     string
	UserFilter string // contains {username}
	Domain     string // optional NetBIOS name; a "DOMAIN\user" sign-in must use it
	Groups     []ADGroup
}

// Errors the sign-in flow distinguishes. The user only ever sees a generic message.
var (
	errADCredentials = errors.New("directory rejected the username or password")
	errADUnavailable = errors.New("directory unavailable")
)

// ADIdentity is what a successful directory sign-in proves.
type ADIdentity struct {
	Sam    string // canonical account name (sAMAccountName)
	DN     string
	Role   string   // highest role granted by group mapping, "" when none
	Groups []string // mapped groups the user belongs to (as configured)
}

// LoadAD reads the directory settings (zero value when unset).
func (s *Store) LoadAD() (ADConfig, error) {
	c := ADConfig{Security: "ldaps", UserFilter: DefaultADFilter}
	v, ok, err := s.getMeta(metaADConfig)
	if err != nil || !ok || v == "" {
		return c, err
	}
	if err := json.Unmarshal([]byte(v), &c); err != nil {
		return c, fmt.Errorf("stored directory settings are unreadable: %w", err)
	}
	if c.UserFilter == "" {
		c.UserFilter = DefaultADFilter
	}
	return c, nil
}

// SaveAD stores validated directory settings.
func (s *Store) SaveAD(c ADConfig) error {
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return s.setMeta(metaADConfig, string(b))
}

// Validate checks a configuration and normalises it in place. Disabled configurations are
// only lightly checked so a half-finished form can still be saved.
func (c *ADConfig) Validate() error {
	c.BindDN, c.BaseDN, c.Domain = strings.TrimSpace(c.BindDN), strings.TrimSpace(c.BaseDN), strings.TrimSpace(c.Domain)
	c.CAPEM = strings.TrimSpace(c.CAPEM)
	c.UserFilter = strings.TrimSpace(c.UserFilter)
	if c.UserFilter == "" {
		c.UserFilter = DefaultADFilter
	}
	if c.Security != "ldaps" && c.Security != "starttls" {
		return errors.New("connection security must be LDAPS or StartTLS; sending directory passwords unencrypted is not supported")
	}
	var servers []string
	for _, sv := range c.Servers {
		sv = strings.TrimSpace(sv)
		if sv == "" {
			continue
		}
		if _, _, err := splitServer(sv, c.Security); err != nil {
			return err
		}
		servers = append(servers, sv)
	}
	c.Servers = servers
	if !strings.Contains(c.UserFilter, "{username}") {
		return errors.New(`the user filter must contain {username}`)
	}
	if _, err := ldap.CompileFilter(strings.ReplaceAll(c.UserFilter, "{username}", "x")); err != nil {
		return fmt.Errorf("the user filter is not valid LDAP syntax: %v", err)
	}
	if c.CAPEM != "" {
		if !x509.NewCertPool().AppendCertsFromPEM([]byte(c.CAPEM)) {
			return errors.New("the extra certificate authority is not valid PEM")
		}
	}
	var groups []ADGroup
	seen := map[string]bool{}
	for _, g := range c.Groups {
		g.Group = strings.TrimSpace(g.Group)
		if g.Group == "" {
			continue
		}
		if !validRole(g.Role) {
			return fmt.Errorf("choose a role for group %q", g.Group)
		}
		if len(g.Group) > 512 || strings.ContainsFunc(g.Group, unicode.IsControl) {
			return errors.New("a group name is invalid")
		}
		k := strings.ToLower(g.Group)
		if seen[k] {
			return fmt.Errorf("group %q is listed twice", g.Group)
		}
		seen[k] = true
		groups = append(groups, g)
	}
	c.Groups = groups
	if !c.Enabled {
		return nil
	}
	switch {
	case len(c.Servers) == 0:
		return errors.New("add at least one directory server")
	case c.BindDN == "":
		return errors.New("a read-only service account (bind DN) is required")
	case c.BaseDN == "":
		return errors.New("the base DN is required, for example DC=corp,DC=example,DC=com")
	}
	return nil
}

// splitServer validates a "host" or "host:port" entry and returns its parts.
func splitServer(s, security string) (host, port string, err error) {
	if strings.Contains(s, "://") || strings.ContainsAny(s, " /\\@?#") {
		return "", "", fmt.Errorf("%q: give a host name or address, optionally with :port", s)
	}
	port = "636"
	if security == "starttls" {
		port = "389"
	}
	if h, p, e := net.SplitHostPort(s); e == nil {
		host, port = h, p
	} else {
		host = strings.Trim(s, "[]")
	}
	if host == "" || len(host) > 253 {
		return "", "", fmt.Errorf("%q is not a valid server", s)
	}
	if n, e := net.LookupPort("tcp", port); e != nil || n < 1 {
		return "", "", fmt.Errorf("%q has an invalid port", s)
	}
	return host, port, nil
}

// directory talks to the domain controllers.
type directory struct {
	cfg    ADConfig
	bindPW string
}

// connect opens a connection to the first reachable server.
func (d *directory) connect() (*ldap.Conn, error) {
	var last error
	for _, sv := range d.cfg.Servers {
		host, port, err := splitServer(sv, d.cfg.Security)
		if err != nil {
			last = err
			continue
		}
		tc := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, InsecureSkipVerify: d.cfg.SkipVerify} //nolint:gosec // an administrator may choose this explicitly; the page warns about it
		if d.cfg.CAPEM != "" {
			pool, e := x509.SystemCertPool()
			if e != nil || pool == nil {
				pool = x509.NewCertPool()
			}
			pool.AppendCertsFromPEM([]byte(d.cfg.CAPEM))
			tc.RootCAs = pool
		}
		addr := net.JoinHostPort(host, port)
		dial := ldap.DialWithDialer(&net.Dialer{Timeout: adTimeout})
		var c *ldap.Conn
		if d.cfg.Security == "ldaps" {
			c, err = ldap.DialURL("ldaps://"+addr, dial, ldap.DialWithTLSConfig(tc))
		} else {
			if c, err = ldap.DialURL("ldap://"+addr, dial); err == nil {
				if err = c.StartTLS(tc); err != nil {
					_ = c.Close()
					c = nil
				}
			}
		}
		if err != nil {
			last = fmt.Errorf("%s: %w", addr, err)
			continue
		}
		c.SetTimeout(adTimeout)
		return c, nil
	}
	if last == nil {
		last = errors.New("no directory servers are configured")
	}
	return nil, fmt.Errorf("%w: %v", errADUnavailable, last)
}

// serviceBind opens a connection and binds as the read-only service account.
func (d *directory) serviceBind() (*ldap.Conn, error) {
	if d.bindPW == "" {
		return nil, fmt.Errorf("%w: no service account password is stored", errADUnavailable)
	}
	c, err := d.connect()
	if err != nil {
		return nil, err
	}
	if err := c.Bind(d.cfg.BindDN, d.bindPW); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("%w: the service account could not sign in: %v", errADUnavailable, err)
	}
	return c, nil
}

// normaliseLogin turns what the user typed into the text searched for.
// "CORP\alice" becomes "alice" (and must match the configured domain, if one is set).
func (d *directory) normaliseLogin(in string) (string, error) {
	in = strings.TrimSpace(in)
	if in == "" || len(in) > 256 || strings.ContainsFunc(in, unicode.IsControl) {
		return "", errADCredentials
	}
	if i := strings.IndexByte(in, '\\'); i >= 0 {
		dom, name := in[:i], in[i+1:]
		if name == "" || (d.cfg.Domain != "" && !strings.EqualFold(dom, d.cfg.Domain)) {
			return "", errADCredentials
		}
		return name, nil
	}
	return in, nil
}

// findUser looks up exactly one account for the login text.
func (d *directory) findUser(c *ldap.Conn, login string) (*ldap.Entry, error) {
	filter := strings.ReplaceAll(d.cfg.UserFilter, "{username}", ldap.EscapeFilter(login))
	res, err := c.Search(ldap.NewSearchRequest(d.cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, int(adTimeout.Seconds()), false,
		filter, []string{"sAMAccountName", "userPrincipalName"}, nil))
	if err != nil && (!ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) || res == nil) {
		return nil, fmt.Errorf("%w: user search failed: %v", errADUnavailable, err)
	}
	if len(res.Entries) != 1 {
		return nil, errADCredentials // not found, or ambiguous: never reveal which
	}
	return res.Entries[0], nil
}

// resolveGroup returns the DN for a configured group (a DN already, or a name to look up).
func (d *directory) resolveGroup(c *ldap.Conn, g string) (string, bool) {
	if strings.Contains(g, "=") {
		return g, true
	}
	e := ldap.EscapeFilter(g)
	res, err := c.Search(ldap.NewSearchRequest(d.cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, int(adTimeout.Seconds()), false,
		"(&(objectClass=group)(|(sAMAccountName="+e+")(cn="+e+")))", []string{"distinguishedName"}, nil))
	if (err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded)) || res == nil || len(res.Entries) != 1 {
		return "", false
	}
	return res.Entries[0].DN, true
}

// isMember reports whether the user is a (possibly nested) member of the group.
func (d *directory) isMember(c *ldap.Conn, userDN, groupDN string) (bool, error) {
	res, err := c.Search(ldap.NewSearchRequest(userDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, int(adTimeout.Seconds()), false,
		"(memberOf:"+matchingRuleInChain+":="+ldap.EscapeFilter(groupDN)+")", []string{"1.1"}, nil))
	if err != nil {
		return false, err
	}
	return len(res.Entries) > 0, nil
}

// roles evaluates the group mapping for a user.
func (d *directory) roles(c *ldap.Conn, userDN string) (role string, groups []string, err error) {
	for _, g := range d.cfg.Groups {
		dn, ok := d.resolveGroup(c, g.Group)
		if !ok {
			continue
		}
		in, e := d.isMember(c, userDN, dn)
		if e != nil {
			return "", nil, fmt.Errorf("%w: group check failed: %v", errADUnavailable, e)
		}
		if in {
			groups = append(groups, g.Group)
			if roleLevel(g.Role) > roleLevel(role) || role == "" {
				role = g.Role
			}
		}
	}
	return role, groups, nil
}

// Authenticate proves a directory password and reports the role the groups grant.
// Failures are errADCredentials (wrong or unknown) or wrap errADUnavailable.
func (d *directory) Authenticate(ctx context.Context, login, password string) (*ADIdentity, error) {
	if password == "" || strings.ContainsRune(password, 0) || len(password) > 512 {
		return nil, errADCredentials // an empty password would be an "unauthenticated bind" that many servers accept
	}
	name, err := d.normaliseLogin(login)
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	c, err := d.serviceBind()
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	ent, err := d.findUser(c, name)
	if err != nil {
		return nil, err
	}
	if err := c.Bind(ent.DN, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return nil, errADCredentials
		}
		return nil, fmt.Errorf("%w: %v", errADUnavailable, err)
	}
	if err := c.Bind(d.cfg.BindDN, d.bindPW); err != nil { // back to the service account for group checks
		return nil, fmt.Errorf("%w: %v", errADUnavailable, err)
	}
	role, groups, err := d.roles(c, ent.DN)
	if err != nil {
		return nil, err
	}
	sam := ent.GetAttributeValue("sAMAccountName")
	if sam == "" {
		sam = name
	}
	return &ADIdentity{Sam: sam, DN: ent.DN, Role: role, Groups: groups}, nil
}

// Lookup finds an account without a password (used when an administrator adds an AD user).
func (d *directory) Lookup(login string) (*ADIdentity, error) {
	name, err := d.normaliseLogin(login)
	if err != nil {
		return nil, err
	}
	c, err := d.serviceBind()
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	ent, err := d.findUser(c, name)
	if err != nil {
		return nil, err
	}
	sam := ent.GetAttributeValue("sAMAccountName")
	if sam == "" {
		sam = name
	}
	return &ADIdentity{Sam: sam, DN: ent.DN}, nil
}

// Ping checks that the servers are reachable and the service account works, and that the
// base DN exists.
func (d *directory) Ping() error {
	c, err := d.serviceBind()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Search(ldap.NewSearchRequest(d.cfg.BaseDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, int(adTimeout.Seconds()), false,
		"(objectClass=*)", []string{"1.1"}, nil)); err != nil {
		return fmt.Errorf("the base DN could not be read: %v", err)
	}
	return nil
}
