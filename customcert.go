package main

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// An administrator can replace the automatic self-signed certificate with one issued by
// a certificate authority. The certificate chain is stored as customCertFile; the private key
// is stored only in sealed form (AES-256-GCM under the master key from easm.key), so the
// key is never on disk in clear. The change takes effect on the next connection.
const (
	customCertFile = "custom.crt"
	customKeyFile  = "custom.key.sealed"
)

// ServerCertInfo describes the certificate the web interface is serving.
type ServerCertInfo struct {
	Source      string // "uploaded" or "self-signed"
	Subject     string
	Issuer      string
	NotBefore   time.Time
	NotAfter    time.Time
	Names       []string // DNS names and IP addresses the certificate covers
	Fingerprint string
	ChainLength int
	SelfSigned  bool
	DaysLeft    int
	Missing     []string // names the agent is reached by that the certificate does not cover
}

// CertControl lets the Settings page inspect and replace the server certificate.
type CertControl interface {
	Info() ServerCertInfo
	// InstallCustom validates and installs a certificate chain and its private key (PEM). The key
	// may be omitted when it is part of certPEM. It returns warnings that do not block the change.
	InstallCustom(certPEM, keyPEM string) (ServerCertInfo, []string, error)
	// RemoveCustom goes back to the automatic self-signed certificate.
	RemoveCustom() error
}

// attachVault gives the keeper the vault used to seal an uploaded private key, and loads any
// certificate uploaded earlier.
func (k *certKeeper) attachVault(v *Vault) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.vault = v
	k.loadCustomLocked()
}

func (k *certKeeper) loadCustomLocked() {
	k.custom, k.customLeaf, k.customChain = nil, nil, 0
	certPEM, err := os.ReadFile(filepath.Join(k.dir, customCertFile)) //nolint:gosec // G304: the agent's own data file
	if err != nil || k.vault == nil {
		return
	}
	sealed, err := os.ReadFile(filepath.Join(k.dir, customKeyFile)) //nolint:gosec // G304: the agent's own data file
	if err != nil {
		return
	}
	keyPEM, err := k.vault.Open(strings.TrimSpace(string(sealed)))
	if err != nil {
		if k.log != nil {
			k.log.Error("the uploaded TLS key cannot be decrypted (was easm.key replaced?); using the self-signed certificate")
		}
		return
	}
	c, err := tls.X509KeyPair(certPEM, []byte(keyPEM))
	if err != nil || len(c.Certificate) == 0 {
		return
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		return
	}
	c.Leaf = leaf
	k.custom, k.customLeaf, k.customChain = &c, leaf, len(c.Certificate)
}

// customUsable returns the uploaded certificate while it is within its validity period.
func (k *certKeeper) customUsable() *tls.Certificate {
	if k.custom == nil || k.customLeaf == nil {
		return nil
	}
	now := time.Now()
	if now.Before(k.customLeaf.NotBefore) || now.After(k.customLeaf.NotAfter) {
		if !k.customWarned && k.log != nil {
			k.customWarned = true
			k.log.Warn("the uploaded TLS certificate is not valid now; serving the self-signed certificate until a valid one is uploaded",
				"valid_from", k.customLeaf.NotBefore, "valid_until", k.customLeaf.NotAfter)
		}
		return nil
	}
	return k.custom
}

// Info implements CertControl.
func (k *certKeeper) Info() ServerCertInfo {
	k.mu.Lock()
	defer k.mu.Unlock()
	if c := k.customUsable(); c != nil {
		return k.describe(c.Leaf, "uploaded", k.customChain)
	}
	if k.leaf == nil {
		return ServerCertInfo{Source: "self-signed"}
	}
	info := k.describe(k.leaf, "self-signed", 1)
	if k.custom != nil { // an uploaded certificate exists but has expired
		info.Missing = append([]string{"the uploaded certificate has expired or is not valid yet"}, info.Missing...)
	}
	return info
}

func (k *certKeeper) describe(leaf *x509.Certificate, source string, chain int) ServerCertInfo {
	info := ServerCertInfo{
		Source: source, Subject: leaf.Subject.String(), Issuer: leaf.Issuer.String(),
		NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter, Fingerprint: Fingerprint(leaf.Raw),
		ChainLength: chain, SelfSigned: leaf.Subject.String() == leaf.Issuer.String(),
		DaysLeft: int(time.Until(leaf.NotAfter).Hours() / 24),
	}
	info.Names = append(info.Names, leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		info.Names = append(info.Names, ip.String())
	}
	if len(info.Names) == 0 && leaf.Subject.CommonName != "" {
		info.Names = append(info.Names, leaf.Subject.CommonName+" (common name only; modern browsers ignore it)")
	}
	if source == "uploaded" {
		info.Missing = uncovered(leaf, k.hosts)
	}
	return info
}

// uncovered lists the names in hosts that leaf is not valid for.
func uncovered(leaf *x509.Certificate, hosts []string) []string {
	var out []string
	for _, h := range hosts {
		if leaf.VerifyHostname(h) != nil {
			out = append(out, h)
		}
	}
	sort.Strings(out)
	return out
}

// InstallCustom implements CertControl.
func (k *certKeeper) InstallCustom(certPEM, keyPEM string) (ServerCertInfo, []string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.vault == nil {
		return ServerCertInfo{}, nil, errors.New("the encryption key is not available, so a private key cannot be stored safely")
	}
	chain, keyBlock, warnings, err := parseServerCert([]byte(certPEM), []byte(keyPEM), time.Now())
	if err != nil {
		return ServerCertInfo{}, nil, err
	}
	pair, err := tls.X509KeyPair(chain, keyBlock)
	if err != nil {
		return ServerCertInfo{}, nil, fmt.Errorf("the certificate and private key do not belong together: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return ServerCertInfo{}, nil, err
	}
	pair.Leaf = leaf
	if miss := uncovered(leaf, k.hosts); len(miss) > 0 {
		warnings = append(warnings, "The certificate does not cover "+strings.Join(miss, ", ")+
			". Browsers will still warn when you reach the agent by those names.")
	}
	sealed, err := k.vault.Seal(string(keyBlock))
	if err != nil {
		return ServerCertInfo{}, nil, err
	}
	// Key first: a certificate without its key is useless, the reverse is harmless.
	if err := writeFileAtomic(filepath.Join(k.dir, customKeyFile), []byte(sealed+"\n")); err != nil {
		return ServerCertInfo{}, nil, fmt.Errorf("saving the private key: %w", err)
	}
	if err := writeFileAtomic(filepath.Join(k.dir, customCertFile), chain); err != nil {
		return ServerCertInfo{}, nil, fmt.Errorf("saving the certificate: %w", err)
	}
	k.custom, k.customLeaf, k.customChain, k.customWarned = &pair, leaf, len(pair.Certificate), false
	if k.log != nil {
		k.log.Info("a CA-issued TLS certificate was installed", "subject", leaf.Subject.String(), "issuer", leaf.Issuer.String(),
			"sha256", Fingerprint(leaf.Raw), "valid_until", leaf.NotAfter.Format("2006-01-02"))
	}
	return k.describe(leaf, "uploaded", len(pair.Certificate)), warnings, nil
}

// RemoveCustom implements CertControl.
func (k *certKeeper) RemoveCustom() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, f := range []string{customCertFile, customKeyFile} {
		if err := os.Remove(filepath.Join(k.dir, f)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	k.custom, k.customLeaf, k.customChain = nil, nil, 0
	return nil
}

// parseServerCert checks an uploaded chain and key and returns them as clean PEM: the server
// certificate first, then the intermediates in the order given, and the key as one PKCS#8 or
// original-format block. Problems that make the upload unusable are errors; things worth
// knowing (a missing intermediate, a self-signed certificate) are warnings.
func parseServerCert(certIn, keyIn []byte, now time.Time) (chainPEM, keyPEM []byte, warnings []string, err error) {
	var certs []*x509.Certificate
	var keyBlock *pem.Block
	for _, in := range [][]byte{certIn, keyIn} {
		rest := in
		for {
			var b *pem.Block
			b, rest = pem.Decode(rest)
			if b == nil {
				break
			}
			switch {
			case b.Type == "CERTIFICATE":
				c, perr := x509.ParseCertificate(b.Bytes)
				if perr != nil {
					return nil, nil, nil, fmt.Errorf("a certificate in the file is damaged: %w", perr)
				}
				certs = append(certs, c)
			case b.Type == "ENCRYPTED PRIVATE KEY" || b.Headers["Proc-Type"] != "":
				return nil, nil, nil, errors.New("the private key is password-protected. Remove the password first, for example: openssl pkey -in protected.key -out server.key")
			case strings.HasSuffix(b.Type, "PRIVATE KEY"):
				if keyBlock != nil {
					return nil, nil, nil, errors.New("more than one private key was supplied")
				}
				keyBlock = b
			}
		}
	}
	if len(certs) == 0 {
		return nil, nil, nil, errors.New("no certificate found: paste the PEM text that starts with -----BEGIN CERTIFICATE-----")
	}
	if keyBlock == nil {
		return nil, nil, nil, errors.New("no private key found: paste the PEM text that starts with -----BEGIN PRIVATE KEY----- (or upload it in the key box)")
	}
	signer, err := parsePrivateKey(keyBlock)
	if err != nil {
		return nil, nil, nil, err
	}
	// Put the certificate that belongs to the key first, whatever order the file had.
	leafAt := -1
	for i, c := range certs {
		if samePublicKey(c.PublicKey, signer.Public()) {
			leafAt = i
			break
		}
	}
	if leafAt < 0 {
		return nil, nil, nil, errors.New("none of the certificates matches this private key")
	}
	leaf := certs[leafAt]
	ordered := []*x509.Certificate{leaf}
	for i, c := range certs {
		if i != leafAt && !bytes.Equal(c.Raw, leaf.Raw) {
			ordered = append(ordered, c)
		}
	}
	switch {
	case leaf.IsCA:
		return nil, nil, nil, errors.New("this is a certificate authority certificate, not a server certificate")
	case now.After(leaf.NotAfter):
		return nil, nil, nil, fmt.Errorf("the certificate expired on %s", leaf.NotAfter.Format("2006-01-02"))
	case now.Before(leaf.NotBefore):
		return nil, nil, nil, fmt.Errorf("the certificate is not valid until %s", leaf.NotBefore.Format("2006-01-02"))
	}
	if len(leaf.ExtKeyUsage) > 0 {
		ok := false
		for _, u := range leaf.ExtKeyUsage {
			if u == x509.ExtKeyUsageServerAuth || u == x509.ExtKeyUsageAny {
				ok = true
			}
		}
		if !ok {
			return nil, nil, nil, errors.New("the certificate is not allowed to be used for web servers (no server-authentication usage)")
		}
	}
	switch leaf.SignatureAlgorithm {
	case x509.MD5WithRSA, x509.SHA1WithRSA, x509.ECDSAWithSHA1, x509.DSAWithSHA1:
		return nil, nil, nil, fmt.Errorf("the certificate is signed with %s, which browsers reject", leaf.SignatureAlgorithm)
	}
	if pub, ok := leaf.PublicKey.(*rsa.PublicKey); ok && pub.N.BitLen() < 2048 {
		return nil, nil, nil, fmt.Errorf("the RSA key is only %d bits; at least 2048 is required", pub.N.BitLen())
	}
	if time.Until(leaf.NotAfter) < 14*24*time.Hour {
		warnings = append(warnings, "This certificate expires in less than two weeks ("+leaf.NotAfter.Format("2006-01-02")+").")
	}
	if len(ordered) == 1 && leaf.Subject.String() != leaf.Issuer.String() {
		warnings = append(warnings, "Only the server certificate was supplied, without the intermediate certificates. Some browsers and tools will not trust it; paste the full chain your CA sent.")
	}
	if leaf.Subject.String() == leaf.Issuer.String() {
		warnings = append(warnings, "This certificate is self-signed, so browsers will still warn.")
	}
	var out bytes.Buffer
	for _, c := range ordered {
		_ = pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	return out.Bytes(), pem.EncodeToMemory(keyBlock), warnings, nil
}

func parsePrivateKey(b *pem.Block) (crypto.Signer, error) {
	if k, err := x509.ParsePKCS8PrivateKey(b.Bytes); err == nil {
		if s, ok := k.(crypto.Signer); ok {
			return s, nil
		}
	}
	if k, err := x509.ParsePKCS1PrivateKey(b.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParseECPrivateKey(b.Bytes); err == nil {
		return k, nil
	}
	return nil, errors.New("the private key could not be read (supported: RSA and ECDSA keys in PEM format)")
}

func samePublicKey(a, b crypto.PublicKey) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	if e, ok := a.(equaler); ok {
		return e.Equal(b)
	}
	return false
}
