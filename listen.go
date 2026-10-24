package main

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// defaultListen is where the web interface listens unless told otherwise: this computer only.
const defaultListen = "127.0.0.1:8080"

// metaListen is the database key under which the listen address chosen in the web interface is kept.
const metaListen = "web_listen"

// ListenControl lets the Settings page read and change where the web server
// listens. The running program implements it; tests may leave it unset.
type ListenControl interface {
	// Address is the address the server listens on now.
	Address() string
	// Locked is true when the address was fixed on the command line or in the
	// config file, which then takes priority over a value saved in the interface.
	Locked() bool
	// Change binds addr, switches the server to it and remembers it. If binding
	// fails nothing changes. It returns the URL to open next.
	Change(addr string) (string, error)
}

// listenChoice is one ready-made address offered on the Settings page.
type listenChoice struct{ Label, Value string }

// ResolveListen turns what a person typed into a "host:port" listen address.
// The host may be an IP address, "*" or "all" (every interface), "localhost",
// or the name of a network interface such as "eth0" (its first usable address).
func ResolveListen(host, port string) (string, error) {
	p, err := strconv.Atoi(strings.TrimSpace(port))
	if err != nil || p < 1 || p > 65535 {
		return "", errors.New("the port must be a number between 1 and 65535")
	}
	host = strings.TrimSpace(host)
	switch strings.ToLower(host) {
	case "", "*", "all", "any":
		host = "0.0.0.0"
	case "localhost":
		host = "127.0.0.1"
	}
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		return net.JoinHostPort(ip.String(), strconv.Itoa(p)), nil
	}
	ifc, err := net.InterfaceByName(host)
	if err != nil {
		return "", errors.New("enter an IP address, an interface name (for example eth0), or * for all interfaces")
	}
	addrs, _ := ifc.Addrs()
	var v6 string
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok || n.IP.IsLinkLocalUnicast() {
			continue
		}
		if n.IP.To4() != nil {
			return net.JoinHostPort(n.IP.String(), strconv.Itoa(p)), nil
		}
		if v6 == "" {
			v6 = n.IP.String()
		}
	}
	if v6 != "" {
		return net.JoinHostPort(v6, strconv.Itoa(p)), nil
	}
	return "", fmt.Errorf("interface %q has no usable address", host)
}

// ListenChoices lists the addresses this computer has, for the Settings page.
func ListenChoices() []listenChoice {
	out := []listenChoice{
		{"This computer only (127.0.0.1)", "127.0.0.1"},
		{"All interfaces (0.0.0.0)", "0.0.0.0"},
	}
	ifs, _ := net.Interfaces()
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && !n.IP.IsLoopback() && !n.IP.IsLinkLocalUnicast() {
				out = append(out, listenChoice{fmt.Sprintf("%s (%s)", n.IP, ifc.Name), n.IP.String()})
			}
		}
	}
	return out
}

// splitListen separates a listen address into host and port for display.
func splitListen(addr string) (host, port string) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, ""
	}
	return h, p
}

// buildAllowedHosts returns the Host header values accepted when the server is
// bound to a loopback address (a defence against DNS rebinding), or nil when no
// check applies.
func buildAllowedHosts(listen string, extra []string) map[string]bool {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return nil
	}
	ip := net.ParseIP(host)
	loop := host == "localhost" || (ip != nil && ip.IsLoopback())
	if !loop && len(extra) == 0 {
		return nil
	}
	m := map[string]bool{}
	if loop {
		for _, h := range []string{"localhost", "127.0.0.1", "::1"} {
			m[h] = true
		}
	}
	for _, h := range extra {
		m[strings.ToLower(strings.TrimSpace(h))] = true
	}
	return m
}
