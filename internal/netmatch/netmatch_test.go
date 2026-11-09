package netmatch

import (
	"net/netip"
	"testing"
)

func TestPunycode(t *testing.T) {
	for in, want := range map[string]string{
		"münchen.de":     "xn--mnchen-3ya.de",
		"bücher.example": "xn--bcher-kva.example",
		"例え.jp":          "xn--r8jz45g.jp",
		"Example.COM.":   "example.com",
	} {
		got, err := NormalizeHost(in)
		if err != nil || got != want {
			t.Errorf("%s → %s (%v), erwartet %s", in, got, err, want)
		}
	}
}

func TestParseErrors(t *testing.T) {
	for _, bad := range []string{"", "ex*ample.com", "a.*.com", "host:0", "host:99999", "host:abc", "10.0.0.0/33", "[::1", "[::1]x",
		"[::1]:0", "[::1]:70000", "[::1]:", "bad label.com", "a..b"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("%q hätte abgelehnt werden müssen", bad)
		}
	}
}

func mustMatcher(t *testing.T, allow, deny []string, def bool) *Matcher {
	m := &Matcher{DefaultAllow: def}
	for _, a := range allow {
		p, err := Parse(a)
		if err != nil {
			t.Fatal(err)
		}
		m.Allow = append(m.Allow, p)
	}
	for _, d := range deny {
		p, err := Parse(d)
		if err != nil {
			t.Fatal(err)
		}
		m.Deny = append(m.Deny, p)
	}
	return m
}

func TestDecide(t *testing.T) {
	m := mustMatcher(t,
		[]string{"github.com", "*.example.com", "**.npmjs.org", "api.test:443", "203.0.113.7", "10.1.0.0/16", "[2001:db8::1]",
			"[2001:db8::2]:8080", "198.51.100.9:22"},
		[]string{"upload.example.com"}, false)
	cases := []struct {
		host string
		port int
		want bool
		rule string
	}{
		{"github.com", 443, true, "github.com"},
		{"GitHub.com.", 443, true, "github.com"},
		{"api.github.com", 443, false, "default"},
		{"a.example.com", 443, true, "*.example.com"},
		{"x.y.example.com", 80, true, "*.example.com"},
		{"example.com", 443, false, "default"},
		{"upload.example.com", 443, false, "upload.example.com"},
		{"npmjs.org", 443, true, "**.npmjs.org"},
		{"registry.npmjs.org", 443, true, "**.npmjs.org"},
		{"api.test", 443, true, "api.test:443"},
		{"api.test", 80, false, "default"},
		{"203.0.113.7", 22, true, "203.0.113.7"},
		{"10.1.2.3", 5432, true, "10.1.0.0/16"},
		{"2001:db8::1", 443, true, "[2001:db8::1]"},
		{"2001:db8::2", 8080, true, "[2001:db8::2]:8080"},
		{"[2001:db8::2]", 8080, true, "[2001:db8::2]:8080"},
		{"2001:db8::2", 443, false, "default"},
		{"198.51.100.9", 22, true, "198.51.100.9:22"},
		{"198.51.100.9", 443, false, "default"},
		{"evilgithub.com", 443, false, "default"},
	}
	for _, c := range cases {
		d, err := m.Decide(c.host, c.port)
		if err != nil || d.Allowed != c.want || d.Rule != c.rule {
			t.Errorf("%s:%d → %+v (%v), erwartet %v/%s", c.host, c.port, d, err, c.want, c.rule)
		}
	}
	m.Ports = []int{443}
	if d, _ := m.Decide("github.com", 22); d.Allowed || d.Rule != "ports" {
		t.Errorf("Port-Beschränkung greift nicht: %+v", d)
	}
	allowAll := mustMatcher(t, nil, []string{"evil.com"}, true)
	if d, _ := allowAll.Decide("anything.org", 443); !d.Allowed {
		t.Error("default allow greift nicht")
	}
	if d, _ := allowAll.Decide("evil.com", 443); d.Allowed {
		t.Error("deny muss vor default allow greifen")
	}
}

func TestPrivate(t *testing.T) {
	m := mustMatcher(t, []string{"10.1.0.0/16"}, nil, false)
	for ip, want := range map[string]bool{
		"127.0.0.1": false, "169.254.169.254": false, "192.168.1.1": false, "100.64.0.1": false,
		"::1": false, "fe80::1": false, "::ffff:127.0.0.1": false, "fd00::1": false,
		"10.1.2.3": true, "93.184.216.34": true, "2606:4700::1": true,
	} {
		if got := m.AddressAllowed(netip.MustParseAddr(ip), 443); got != want {
			t.Errorf("%s: %v, erwartet %v", ip, got, want)
		}
	}
	m.AllowPrivate = true
	if !m.AddressAllowed(netip.MustParseAddr("127.0.0.1"), 80) {
		t.Error("allow_private greift nicht")
	}
}
