package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"sdbx/internal/audit"
	"sdbx/internal/netmatch"
)

func matcher(t *testing.T, allow ...string) *netmatch.Matcher {
	m := &netmatch.Matcher{}
	for _, a := range allow {
		p, err := netmatch.Parse(a)
		if err != nil {
			t.Fatal(err)
		}
		m.Allow = append(m.Allow, p)
	}
	return m
}

// start startet Proxy und Upstream; alle Testdomains lösen auf 127.0.0.1 auf.
func start(t *testing.T, m *netmatch.Matcher, token string, learn bool) (*Server, string, *httptest.Server, *audit.Logger) {
	t.Helper()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hallo von %s%s", r.Host, r.URL.Path)
	}))
	t.Cleanup(up.Close)
	log := audit.New("test", nil, "json")
	s := &Server{Matcher: m, Token: token, Log: log, Learn: learn,
		Resolve: func(ctx context.Context, host string) ([]netip.Addr, error) {
			if strings.HasSuffix(host, ".test") {
				return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
			}
			return nil, fmt.Errorf("unbekannt")
		}}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go s.Serve(l)
	t.Cleanup(s.Close)
	return s, l.Addr().String(), up, log
}

func upstreamPort(up *httptest.Server) string {
	_, p, _ := net.SplitHostPort(strings.TrimPrefix(up.URL, "http://"))
	return p
}

func client(proxyAddr, token string) *http.Client {
	u := &url.URL{Scheme: "http", Host: proxyAddr}
	if token != "" {
		u.User = url.UserPassword(User, token)
	}
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(u)}}
}

func TestHTTPAllowedAndDenied(t *testing.T) {
	_, addr, up, log := start(t, matcher(t, "allowed.test", "127.0.0.1/32"), "tok", false)
	port := upstreamPort(up)
	resp, err := client(addr, "tok").Get("http://allowed.test:" + port + "/x")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(body), "hallo von allowed.test") {
		t.Fatalf("erlaubte Anfrage: %d %s", resp.StatusCode, body)
	}
	resp, err = client(addr, "tok").Get("http://blocked.test:" + port + "/x")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	if resp.StatusCode != 403 || !strings.Contains(string(body), "nicht freigegeben") {
		t.Fatalf("blockierte Anfrage: %d %s", resp.StatusCode, body)
	}
	if log.Count("net.allow") != 1 || log.Count("net.deny") != 1 {
		t.Fatalf("Audit: allow=%d deny=%d", log.Count("net.allow"), log.Count("net.deny"))
	}
}

func TestAuthRequired(t *testing.T) {
	_, addr, up, _ := start(t, matcher(t, "allowed.test", "127.0.0.1/32"), "tok", false)
	resp, err := client(addr, "").Get("http://allowed.test:" + upstreamPort(up) + "/")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("ohne Token: %d", resp.StatusCode)
	}
	resp, _ = client(addr, "falsch").Get("http://allowed.test:" + upstreamPort(up) + "/")
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("falsches Token: %d", resp.StatusCode)
	}
}

func TestConnectTunnel(t *testing.T) {
	_, addr, up, _ := start(t, matcher(t, "allowed.test", "127.0.0.1/32"), "", false)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "CONNECT allowed.test:%s HTTP/1.1\r\nHost: allowed.test:%s\r\n\r\n", upstreamPort(up), upstreamPort(up))
	br := bufio.NewReader(c)
	line, _ := br.ReadString('\n')
	if !strings.Contains(line, "200") {
		t.Fatalf("CONNECT: %q", line)
	}
	br.ReadString('\n')
	fmt.Fprintf(c, "GET /tunnel HTTP/1.1\r\nHost: allowed.test\r\nConnection: close\r\n\r\n")
	rest, _ := io.ReadAll(br)
	if !strings.Contains(string(rest), "hallo von allowed.test/tunnel") {
		t.Fatalf("Tunnel-Antwort: %s", rest)
	}
}

func TestPrivateAddressBlocked(t *testing.T) {
	// Domain erlaubt, löst aber auf 127.0.0.1 auf – ohne CIDR-Freigabe muss das scheitern (DNS-Rebinding).
	_, addr, up, log := start(t, matcher(t, "allowed.test"), "", false)
	resp, err := client(addr, "").Get("http://allowed.test:" + upstreamPort(up) + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 403 || !strings.Contains(string(body), "private") {
		t.Fatalf("private Adresse nicht blockiert: %d %s", resp.StatusCode, body)
	}
	ev := log.Events()
	if len(ev) == 0 || ev[0].Fields["reason"] != "private Adresse" {
		t.Fatalf("Audit-Grund fehlt: %+v", ev)
	}
}

func TestHostHeaderMismatch(t *testing.T) {
	_, addr, up, _ := start(t, matcher(t, "allowed.test", "127.0.0.1/32"), "", false)
	c, _ := net.Dial("tcp", addr)
	defer c.Close()
	fmt.Fprintf(c, "GET http://allowed.test:%s/ HTTP/1.1\r\nHost: evil.test\r\n\r\n", upstreamPort(up))
	line, _ := bufio.NewReader(c).ReadString('\n')
	if !strings.Contains(line, "400") {
		t.Fatalf("abweichender Host-Header: %q", line)
	}
}

func TestSOCKS(t *testing.T) {
	_, addr, up, _ := start(t, matcher(t, "allowed.test", "127.0.0.1/32"), "tok", false)
	port := 0
	fmt.Sscan(upstreamPort(up), &port)

	c, _ := net.Dial("tcp", addr)
	if err := DialSOCKS(c, "tok", "allowed.test", port); err != nil {
		t.Fatalf("SOCKS erlaubt: %v", err)
	}
	fmt.Fprintf(c, "GET /socks HTTP/1.1\r\nHost: allowed.test\r\nConnection: close\r\n\r\n")
	b, _ := io.ReadAll(c)
	if !strings.Contains(string(b), "hallo von allowed.test/socks") {
		t.Fatalf("SOCKS-Antwort: %s", b)
	}
	c.Close()

	c, _ = net.Dial("tcp", addr)
	if err := DialSOCKS(c, "tok", "blocked.test", port); err == nil || !strings.Contains(err.Error(), "nicht freigegeben") {
		t.Fatalf("SOCKS blockiert: %v", err)
	}
	c.Close()

	c, _ = net.Dial("tcp", addr)
	if err := DialSOCKS(c, "falsch", "allowed.test", port); err == nil {
		t.Fatal("falsches SOCKS-Token akzeptiert")
	}
	c.Close()
}

// CONNECT zu gesperrten Zielen und zu erlaubten Domains mit privater Adresse liefert 403 mit Deny-Kennung.
func TestConnectDenied(t *testing.T) {
	_, addr, up, _ := start(t, matcher(t, "allowed.test"), "", false)
	port := upstreamPort(up)
	for host, want := range map[string]string{"blocked.test": "nicht freigegeben", "allowed.test": "private"} {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(c, "CONNECT %s:%s HTTP/1.1\r\nHost: %s:%s\r\n\r\n", host, port, host, port)
		resp, err := io.ReadAll(c)
		c.Close()
		if err != nil || !strings.HasPrefix(string(resp), "HTTP/1.1 403") || !strings.Contains(string(resp), "X-Sdbx-Deny: 1") || !strings.Contains(string(resp), want) {
			t.Errorf("CONNECT %s: %q", host, resp)
		}
	}
}

// Ein ausdrücklich erlaubtes IP-Literal gilt als Freigabe der Adresse; ohne sie bleibt es gesperrt.
func TestIPLiteralTarget(t *testing.T) {
	for allow, want := range map[string]int{"allowed.test": 403, "127.0.0.1": 200} {
		_, addr, up, _ := start(t, matcher(t, allow), "", false)
		resp, err := client(addr, "").Get("http://127.0.0.1:" + upstreamPort(up) + "/")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("allow %s: %d, erwartet %d", allow, resp.StatusCode, want)
		}
	}
}

// socksRaw sendet eine SOCKS5-Anfrage ohne Authentifizierung und liefert den Antwortcode (-1 = Verbindung zu).
func socksRaw(t *testing.T, addr string, req []byte) int {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	c.Write([]byte{5, 1, 0})
	m := make([]byte, 2)
	if _, err := io.ReadFull(c, m); err != nil || m[1] != 0 {
		t.Fatalf("Methodenwahl: %v %v", m, err)
	}
	c.Write(req)
	rep := make([]byte, 10)
	if _, err := io.ReadFull(c, rep); err != nil {
		return -1
	}
	return int(rep[1])
}

func TestSOCKSRequests(t *testing.T) {
	_, addr, up, _ := start(t, matcher(t, "allowed.test"), "", false)
	port := 0
	fmt.Sscan(upstreamPort(up), &port)
	p := []byte{byte(port >> 8), byte(port)}
	ipv4 := append([]byte{5, 1, 0, 1, 127, 0, 0, 1}, p...)
	ipv6 := append(append([]byte{5, 1, 0, 4}, netip.IPv6Loopback().AsSlice()...), p...)
	for name, tc := range map[string]struct {
		req  []byte
		want int
	}{
		"IPv4-Literal ohne Freigabe": {ipv4, socksNotAllowed},
		"IPv6-Literal ohne Freigabe": {ipv6, socksNotAllowed},
		"erlaubte Domain, privat":    {append(append([]byte{5, 1, 0, 3, 12}, "allowed.test"...), p...), socksNotAllowed},
		"BIND statt CONNECT":         {append([]byte{5, 2, 0, 1, 127, 0, 0, 1}, p...), socksCmdUnsupp},
		"unbekannter Adresstyp":      {append([]byte{5, 1, 0, 9}, p...), socksAddrUnsupp},
		"falsche Version in Anfrage": {append([]byte{4, 1, 0, 1, 127, 0, 0, 1}, p...), -1},
	} {
		if got := socksRaw(t, addr, tc.req); got != tc.want {
			t.Errorf("%s: Antwort %d, erwartet %d", name, got, tc.want)
		}
	}
	_, addr, _, _ = start(t, matcher(t, "127.0.0.1/32"), "", false)
	if got := socksRaw(t, addr, ipv4); got != socksOK {
		t.Errorf("IPv4-Literal mit CIDR-Freigabe: %d", got)
	}
}

// Mit Token muss der Client Benutzername/Passwort anbieten; nur "keine Authentifizierung" wird abgelehnt.
func TestSOCKSAuthMethodRequired(t *testing.T) {
	_, addr, _, _ := start(t, matcher(t, "allowed.test"), "tok", false)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte{5, 1, 0})
	m := make([]byte, 2)
	if _, err := io.ReadFull(c, m); err != nil || m[1] != socksMethodRefuse {
		t.Fatalf("ohne Authentifizierung: %v %v", m, err)
	}
}

func TestLearnMode(t *testing.T) {
	_, addr, up, log := start(t, matcher(t, "127.0.0.1/32"), "", true)
	resp, err := client(addr, "").Get("http://unlisted.test:" + upstreamPort(up) + "/")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("Lernmodus muss durchlassen: %d", resp.StatusCode)
	}
	if log.Count("net.learn") != 1 {
		t.Fatalf("net.learn fehlt")
	}
}

func TestNonHTTPSchemeRejected(t *testing.T) {
	_, addr, _, _ := start(t, matcher(t, "allowed.test"), "", false)
	c, _ := net.Dial("tcp", addr)
	defer c.Close()
	fmt.Fprintf(c, "GET ftp://allowed.test/x HTTP/1.1\r\nHost: allowed.test\r\n\r\n")
	line, _ := bufio.NewReader(c).ReadString('\n')
	if !strings.Contains(line, "400") {
		t.Fatalf("ftp-Schema: %q", line)
	}
}
