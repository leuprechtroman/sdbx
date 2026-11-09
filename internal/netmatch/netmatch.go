// Package netmatch entscheidet über Netzwerkziele anhand von Domain-, IP- und CIDR-Mustern (Spec 6.3).
package netmatch

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Kind ist die Art eines Musters.
type Kind int

const (
	Exact      Kind = iota // example.com
	Subdomains             // *.example.com (ohne Apex)
	ApexAndSub             // **.example.com
	IP                     // 203.0.113.7
	CIDR                   // 10.0.0.0/8
)

// Pattern ist ein geparstes Muster.
type Pattern struct {
	Raw    string
	Kind   Kind
	Host   string // normalisierter Hostname bzw. Suffix
	Addr   netip.Addr
	Prefix netip.Prefix
	Port   int // 0 = alle Ports
	Source string
}

// NormalizeHost normalisiert einen Hostnamen: Kleinschreibung, Punkt am Ende weg, IDNA → Punycode.
func NormalizeHost(h string) (string, error) {
	h = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
	if h == "" {
		return "", fmt.Errorf("leerer Hostname")
	}
	labels := strings.Split(h, ".")
	for i, l := range labels {
		if l == "" {
			return "", fmt.Errorf("leeres Label in %q", h)
		}
		if !isASCII(l) {
			enc, err := punycodeEncode(l)
			if err != nil {
				return "", err
			}
			labels[i] = "xn--" + enc
		}
	}
	return strings.Join(labels, "."), nil
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func validLabel(l string) bool {
	if l == "" || len(l) > 63 {
		return false
	}
	for _, c := range l {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// Parse parst ein Muster aus der Konfiguration.
func Parse(raw string) (Pattern, error) {
	p := Pattern{Raw: raw}
	s := strings.TrimSpace(raw)
	if s == "" {
		return p, fmt.Errorf("leeres Muster")
	}
	// CIDR
	if strings.Contains(s, "/") {
		pre, err := netip.ParsePrefix(s)
		if err != nil {
			return p, fmt.Errorf("ungültiger CIDR-Bereich %q", raw)
		}
		p.Kind, p.Prefix = CIDR, pre.Masked()
		return p, nil
	}
	host, port := s, 0
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end < 0 {
			return p, fmt.Errorf("ungültige IPv6-Adresse %q", raw)
		}
		host = s[1:end]
		rest := s[end+1:]
		if rest != "" {
			if !strings.HasPrefix(rest, ":") {
				return p, fmt.Errorf("ungültiges Muster %q", raw)
			}
			v, err := strconv.Atoi(rest[1:])
			if err != nil || v < 1 || v > 65535 {
				return p, fmt.Errorf("ungültiger Port in %q", raw)
			}
			port = v
		}
	} else if strings.Count(s, ":") == 1 {
		h, ps, _ := strings.Cut(s, ":")
		v, err := strconv.Atoi(ps)
		if err != nil || v < 1 || v > 65535 {
			return p, fmt.Errorf("ungültiger Port in %q", raw)
		}
		host, port = h, v
	}
	p.Port = port
	if a, err := netip.ParseAddr(host); err == nil {
		p.Kind, p.Addr = IP, a.Unmap()
		return p, nil
	}
	switch {
	case strings.HasPrefix(host, "**."):
		p.Kind, host = ApexAndSub, host[3:]
	case strings.HasPrefix(host, "*."):
		p.Kind, host = Subdomains, host[2:]
	default:
		p.Kind = Exact
	}
	if strings.Contains(host, "*") {
		return p, fmt.Errorf("%q: * ist nur als erstes Label erlaubt (*.example.com, **.example.com)", raw)
	}
	n, err := NormalizeHost(host)
	if err != nil {
		return p, fmt.Errorf("%q: %v", raw, err)
	}
	for _, l := range strings.Split(n, ".") {
		if !validLabel(l) {
			return p, fmt.Errorf("%q: ungültiges Label %q", raw, l)
		}
	}
	p.Host = n
	return p, nil
}

// MatchHost prüft einen normalisierten Hostnamen (oder eine IP) samt Port.
func (p Pattern) MatchHost(host string, ip netip.Addr, port int) bool {
	if p.Port != 0 && p.Port != port {
		return false
	}
	switch p.Kind {
	case Exact:
		return host != "" && host == p.Host
	case Subdomains:
		return host != "" && strings.HasSuffix(host, "."+p.Host)
	case ApexAndSub:
		return host != "" && (host == p.Host || strings.HasSuffix(host, "."+p.Host))
	case IP:
		return ip.IsValid() && ip.Unmap() == p.Addr
	case CIDR:
		return ip.IsValid() && p.Prefix.Contains(ip.Unmap())
	}
	return false
}

// Decision ist das Ergebnis einer Prüfung.
type Decision struct {
	Allowed bool
	Rule    string // Muster oder "default", "ports"
	Source  string
}

// Matcher bündelt die Netzwerkregeln.
type Matcher struct {
	Allow        []Pattern
	Deny         []Pattern
	DefaultAllow bool
	Ports        []int
	AllowPrivate bool
}

// Decide entscheidet über ein Ziel vor der DNS-Auflösung (Spec 6.3, Schritte 1–4).
func (m *Matcher) Decide(target string, port int) (Decision, error) {
	host, ip := "", netip.Addr{}
	if a, err := netip.ParseAddr(strings.Trim(target, "[]")); err == nil {
		ip = a.Unmap()
	} else {
		h, err := NormalizeHost(target)
		if err != nil {
			return Decision{}, err
		}
		host = h
	}
	if len(m.Ports) > 0 {
		ok := false
		for _, p := range m.Ports {
			ok = ok || p == port
		}
		if !ok {
			return Decision{Allowed: false, Rule: "ports"}, nil
		}
	}
	for _, p := range m.Deny {
		if p.MatchHost(host, ip, port) {
			return Decision{Allowed: false, Rule: p.Raw, Source: p.Source}, nil
		}
	}
	for _, p := range m.Allow {
		if p.MatchHost(host, ip, port) {
			return Decision{Allowed: true, Rule: p.Raw, Source: p.Source}, nil
		}
	}
	return Decision{Allowed: m.DefaultAllow, Rule: "default"}, nil
}

// AddressAllowed prüft eine aufgelöste Adresse gegen den Private-IP-Schutz (Spec 6.3, Schritt 5).
func (m *Matcher) AddressAllowed(a netip.Addr, port int) bool {
	a = a.Unmap()
	if !IsPrivate(a) || m.AllowPrivate {
		return true
	}
	for _, p := range m.Allow {
		if (p.Kind == CIDR || p.Kind == IP) && p.MatchHost("", a, port) {
			return true
		}
	}
	return false
}

var privatePrefixes = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4",
		"::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8", "64:ff9b::/96",
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// IsPrivate meldet Loopback, Link-Local (inkl. Cloud-Metadaten), private, CGNAT- und Sonderbereiche.
func IsPrivate(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range privatePrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
