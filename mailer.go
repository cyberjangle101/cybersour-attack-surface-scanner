package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"time"
)

// Mailer sends alert and digest emails over SMTP (STARTTLS, implicit TLS or plain).
type Mailer struct {
	cfg    SMTPCfg
	health *HealthBoard
}

// NewMailer creates a Mailer from SMTP settings.
func NewMailer(cfg SMTPCfg) *Mailer { return &Mailer{cfg: cfg} }

// WithHealth makes the mailer report SMTP outcomes to the health board.
func (m *Mailer) WithHealth(h *HealthBoard) *Mailer { m.health = h; return m }

type loginAuth struct{ user, pass string }

// Start begins SMTP LOGIN authentication by announcing the mechanism.
func (a *loginAuth) Start(s *smtp.ServerInfo) (string, []byte, error) {
	if !s.TLS && s.Name != "localhost" && s.Name != "127.0.0.1" {
		return "", nil, errors.New("refusing LOGIN auth over an unencrypted connection")
	}
	return "LOGIN", nil, nil
}

// Next answers the server's Username:/Password: prompts in turn.
func (a *loginAuth) Next(from []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	switch strings.ToLower(strings.TrimSpace(string(from))) {
	case "username:":
		return []byte(a.user), nil
	case "password:":
		return []byte(a.pass), nil
	}
	return nil, fmt.Errorf("unexpected server challenge %q", from)
}

// buildMIME assembles the multipart/alternative message with plain and HTML bodies and safe headers.
func (m *Mailer) buildMIME(subject, plain, htmlBody string) ([]byte, error) {
	from, err := mail.ParseAddress(m.cfg.From)
	if err != nil {
		return nil, err
	}
	domain := "localhost"
	if i := strings.LastIndex(from.Address, "@"); i >= 0 {
		domain = from.Address[i+1:]
	}
	boundary := "easm_" + randHex(12)
	var b bytes.Buffer
	hdr := func(k, v string) {
		v = strings.NewReplacer("\r", " ", "\n", " ").Replace(v) // header-injection guard
		_, _ = fmt.Fprintf(&b, "%s: %s\r\n", k, v)
	}
	hdr("From", m.cfg.From)
	hdr("To", strings.Join(m.cfg.To, ", "))
	hdr("Subject", mime.QEncoding.Encode("utf-8", subject))
	hdr("Date", time.Now().Format(time.RFC1123Z))
	hdr("Message-ID", fmt.Sprintf("<%s@%s>", randHex(12), domain))
	hdr("MIME-Version", "1.0")
	hdr("X-Mailer", "easm-agent")
	hdr("Content-Type", `multipart/alternative; boundary="`+boundary+`"`)
	b.WriteString("\r\n")
	part := func(ctype, body string) {
		_, _ = fmt.Fprintf(&b, "--%s\r\nContent-Type: %s; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n", boundary, ctype)
		qw := quotedprintable.NewWriter(&b)
		_, _ = qw.Write([]byte(body))
		_ = qw.Close()
		b.WriteString("\r\n")
	}
	part("text/plain", plain)
	part("text/html", htmlBody)
	_, _ = fmt.Fprintf(&b, "--%s--\r\n", boundary)
	return b.Bytes(), nil
}

// Send delivers one message and records the outcome on the health board.
func (m *Mailer) Send(ctx context.Context, subject, plain, htmlBody string) error {
	start := time.Now()
	err := m.send(ctx, subject, plain, htmlBody)
	m.health.Record("smtp", "scan", err == nil, time.Since(start), err)
	return err
}

// Probe connects, negotiates TLS and authenticates without sending anything.
func (m *Mailer) Probe(ctx context.Context) error {
	start := time.Now()
	cl, err := m.dial(ctx)
	if err == nil {
		_ = cl.Quit()
		_ = cl.Close()
	}
	m.health.Record("smtp", "check", err == nil, time.Since(start), err)
	return err
}

// dial opens the connection, upgrades it to TLS and authenticates. The caller closes the client.
func (m *Mailer) dial(ctx context.Context) (*smtp.Client, error) {
	c := m.cfg
	addr := net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
	d := &net.Dialer{Timeout: c.Timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("connect %s: %w", addr, err)
	}
	_ = conn.SetDeadline(time.Now().Add(2 * c.Timeout))

	tlsCfg := &tls.Config{ServerName: c.Host, MinVersion: tls.VersionTLS12, InsecureSkipVerify: c.InsecureSkipVerify} //nolint:gosec // opt-in for lab relays
	if c.Security == "tls" {
		tc := tls.Client(conn, tlsCfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("TLS handshake: %w", err)
		}
		conn = tc
	}
	cl, err := smtp.NewClient(conn, c.Host)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("SMTP greeting: %w", err)
	}

	ehlo := c.EHLOName
	if ehlo == "" {
		if h, err := os.Hostname(); err == nil && h != "" && !strings.ContainsAny(h, " _") {
			ehlo = h
		} else {
			ehlo = "localhost"
		}
	}
	fail := func(err error) (*smtp.Client, error) { _ = cl.Close(); return nil, err }
	if err := cl.Hello(ehlo); err != nil {
		return fail(fmt.Errorf("EHLO: %w", err))
	}
	if c.Security == "starttls" {
		if ok, _ := cl.Extension("STARTTLS"); !ok {
			return fail(errors.New("server does not advertise STARTTLS; refusing to continue in cleartext"))
		}
		if err := cl.StartTLS(tlsCfg); err != nil {
			return fail(fmt.Errorf("STARTTLS: %w", err))
		}
	}
	if c.Username != "" {
		ok, mechs := cl.Extension("AUTH")
		if !ok {
			return fail(errors.New("server does not support AUTH"))
		}
		var auth smtp.Auth
		switch {
		case strings.Contains(mechs, "PLAIN"):
			auth = smtp.PlainAuth("", c.Username, c.Password, c.Host)
		case strings.Contains(mechs, "LOGIN"):
			auth = &loginAuth{c.Username, c.Password}
		default:
			return fail(fmt.Errorf("no supported AUTH mechanism (server offers %q)", mechs))
		}
		if err := cl.Auth(auth); err != nil {
			return fail(fmt.Errorf("AUTH: %w", err))
		}
	}
	return cl, nil
}

// send performs one SMTP transaction with the configured security mode and authentication.
func (m *Mailer) send(ctx context.Context, subject, plain, htmlBody string) error {
	c := m.cfg
	msg, err := m.buildMIME(subject, plain, htmlBody)
	if err != nil {
		return err
	}
	from, _ := mail.ParseAddress(c.From)
	cl, err := m.dial(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = cl.Close() }()
	if err := cl.Mail(from.Address); err != nil {
		return fmt.Errorf("MAIL FROM: %w", err)
	}
	for _, r := range c.To {
		a, _ := mail.ParseAddress(r)
		if err := cl.Rcpt(a.Address); err != nil {
			return fmt.Errorf("RCPT TO %s: %w", a.Address, err)
		}
	}
	w, err := cl.Data()
	if err != nil {
		return fmt.Errorf("DATA: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("end of DATA: %w", err)
	}
	return cl.Quit()
}
