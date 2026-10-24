package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	selfSignedCertFile = "server.crt"
	selfSignedKeyFile  = "server.key"
	selfSignedLife     = 2 * 365 * 24 * time.Hour // validity of a generated certificate
	selfSignedRenewAt  = 30 * 24 * time.Hour      // renewed when less than this remains
)

// certKeeper supplies the web server's TLS certificate. It loads a saved
// self-signed certificate from the data folder, creates one on first use, and
// renews it before it expires (also while the agent is running).
type certKeeper struct {
	dir   string
	hosts []string // names and addresses the certificate must cover
	log   *slog.Logger

	mu   sync.Mutex
	cert *tls.Certificate
	leaf *x509.Certificate

	// An administrator-supplied certificate (see customcert.go) is served in preference to the self-signed one.
	vault        *Vault
	custom       *tls.Certificate
	customLeaf   *x509.Certificate
	customChain  int
	customWarned bool
}

// newCertKeeper prepares a keeper for a listen address and returns it with the
// certificate already loaded or created, so start-up fails early on problems.
func newCertKeeper(dataDir, listen string, extraHosts []string, log *slog.Logger) (*certKeeper, error) {
	k := &certKeeper{dir: dataDir, hosts: certHosts(listen, extraHosts), log: log}
	if _, err := k.Get(nil); err != nil {
		return nil, err
	}
	return k, nil
}

// certHosts lists every name and address the certificate should be valid for:
// localhost and the loopback addresses, this machine's name, the listen
// address and, when listening on all interfaces, the machine's own addresses.
func certHosts(listen string, extra []string) []string {
	set := map[string]bool{"localhost": true, "127.0.0.1": true, "::1": true}
	if name, err := os.Hostname(); err == nil && name != "" {
		set[strings.ToLower(name)] = true
	}
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		host = listen
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		if addrs, err := net.InterfaceAddrs(); err == nil {
			for _, a := range addrs {
				if n, ok := a.(*net.IPNet); ok && !n.IP.IsLinkLocalUnicast() {
					set[n.IP.String()] = true
				}
			}
		}
	} else if host != "" {
		set[strings.ToLower(host)] = true
	}
	for _, h := range extra {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			set[h] = true
		}
	}
	out := make([]string, 0, len(set))
	for h := range set {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// setListen changes the listen address the certificate must cover. The cached
// certificate is dropped, so the next connection gets one that covers the new names.
func (k *certKeeper) setListen(listen string, extraHosts []string) error {
	k.mu.Lock()
	k.hosts = certHosts(listen, extraHosts)
	k.cert, k.leaf = nil, nil
	k.mu.Unlock()
	_, err := k.Get(nil)
	return err
}

// Get is the tls.Config.GetCertificate callback. It renews the certificate when
// it is close to expiry, so a long-running service never serves an expired one.
func (k *certKeeper) Get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if c := k.customUsable(); c != nil {
		return c, nil
	}
	if k.cert != nil && time.Until(k.leaf.NotAfter) > selfSignedRenewAt {
		return k.cert, nil
	}
	if c, leaf := k.loadSaved(); c != nil {
		k.cert, k.leaf = c, leaf
		return c, nil
	}
	c, leaf, err := k.create()
	if err != nil {
		return nil, err
	}
	k.cert, k.leaf = c, leaf
	return c, nil
}

// loadSaved returns the certificate on disk if it is still valid for long
// enough and covers every required name; otherwise it returns nil.
func (k *certKeeper) loadSaved() (*tls.Certificate, *x509.Certificate) {
	c, err := tls.LoadX509KeyPair(filepath.Join(k.dir, selfSignedCertFile), filepath.Join(k.dir, selfSignedKeyFile))
	if err != nil || len(c.Certificate) == 0 {
		return nil, nil
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil || time.Now().Before(leaf.NotBefore) || time.Until(leaf.NotAfter) <= selfSignedRenewAt {
		return nil, nil
	}
	for _, h := range k.hosts {
		if leaf.VerifyHostname(h) != nil {
			return nil, nil // the listen address or host name changed
		}
	}
	return &c, leaf
}

// create makes a new ECDSA P-256 key and a self-signed certificate for the
// required names, and saves them (the key readable by the owner only).
func (k *certKeeper) create() (*tls.Certificate, *x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "EASM Agent", Organization: []string{"EASM Agent (self-signed)"}},
		NotBefore:             now.Add(-time.Hour), // tolerate small clock differences
		NotAfter:              now.Add(selfSignedLife),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, h := range k.hosts {
		if ip := net.ParseIP(h); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	// Key first: a certificate without its key is useless, the reverse is harmless.
	if err := writeFileAtomic(filepath.Join(k.dir, selfSignedKeyFile), keyPEM); err != nil {
		return nil, nil, fmt.Errorf("saving TLS key: %w", err)
	}
	if err := writeFileAtomic(filepath.Join(k.dir, selfSignedCertFile), certPEM); err != nil {
		return nil, nil, fmt.Errorf("saving TLS certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	if k.log != nil {
		k.log.Info("created a self-signed TLS certificate (browsers will warn once; compare the fingerprint to be sure it is yours)",
			"file", filepath.Join(k.dir, selfSignedCertFile), "sha256", Fingerprint(der), "valid_until", leaf.NotAfter.Format("2006-01-02"))
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, leaf, nil
}

// Fingerprint returns the SHA-256 fingerprint of a DER certificate as
// colon-separated upper-case hex, the form browsers show.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

// tlsConfig is the server's TLS policy: TLS 1.2 or newer, certificate from the keeper.
func (k *certKeeper) tlsConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: k.Get}
}
