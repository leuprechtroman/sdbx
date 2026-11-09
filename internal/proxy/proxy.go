// Package proxy implementiert den Filter-Proxy (Spec 6.2): HTTP CONNECT, HTTP mit
// absoluter URI und SOCKS5 auf einem Port, erkannt am ersten Byte.
package proxy

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"sdbx/internal/audit"
	"sdbx/internal/netmatch"
)

// User ist der Benutzername für Proxy-Authentifizierung.
const User = "sdbx"

// Server ist der Filter-Proxy.
type Server struct {
	Matcher     *netmatch.Matcher
	Token       string // leer = keine Authentifizierung
	Log         *audit.Logger
	Learn       bool // Lernmodus: Regelverstöße werden protokolliert, aber zugelassen
	DialTimeout time.Duration
	Resolve     func(ctx context.Context, host string) ([]netip.Addr, error)
	Dial        func(ctx context.Context, network, addr string) (net.Conn, error)

	wg     sync.WaitGroup
	mu     sync.Mutex
	closed bool
	lns    []net.Listener
}

func (s *Server) init() {
	if s.DialTimeout == 0 {
		s.DialTimeout = 15 * time.Second
	}
	if s.Resolve == nil {
		s.Resolve = func(ctx context.Context, host string) ([]netip.Addr, error) {
			addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
			return addrs, err
		}
	}
	if s.Dial == nil {
		d := &net.Dialer{}
		s.Dial = d.DialContext
	}
}

// Serve nimmt Verbindungen an, bis der Listener geschlossen wird.
func (s *Server) Serve(l net.Listener) error {
	s.init()
	s.mu.Lock()
	s.lns = append(s.lns, l)
	s.mu.Unlock()
	for {
		c, err := l.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handle(c)
		}()
	}
}

// Close schließt alle Listener.
func (s *Server) Close() {
	s.mu.Lock()
	s.closed = true
	for _, l := range s.lns {
		l.Close()
	}
	s.mu.Unlock()
}

func (s *Server) handle(c net.Conn) {
	defer c.Close()
	br := bufio.NewReaderSize(c, 64<<10)
	c.SetReadDeadline(time.Now().Add(30 * time.Second))
	b, err := br.Peek(1)
	if err != nil {
		return
	}
	if b[0] == 0x05 {
		s.socks(c, br)
		return
	}
	s.http(c, br)
}

// Ergebnis einer Zielprüfung samt Verbindung.
type target struct {
	host string
	port int
	ip   netip.Addr
	dec  netmatch.Decision
}

func (s *Server) logDecision(t target, allowed bool, reason string) {
	f := map[string]any{"host": t.host, "port": t.port, "rule": t.dec.Rule}
	if t.dec.Source != "" {
		f["source"] = t.dec.Source
	}
	if t.ip.IsValid() {
		f["ip"] = t.ip.String()
	}
	if reason != "" {
		f["reason"] = reason
	}
	switch {
	case allowed && s.Learn && !t.dec.Allowed:
		s.Log.Emit("net.learn", f)
	case allowed:
		s.Log.Emit("net.allow", f)
	default:
		s.Log.Emit("net.deny", f)
	}
}

// errDenied ist eine Regelablehnung.
type errDenied struct{ msg string }

func (e *errDenied) Error() string { return e.msg }

// connect prüft das Ziel nach Spec 6.3 und baut die Verbindung auf.
func (s *Server) connect(host string, port int) (net.Conn, error) {
	t := target{host: strings.ToLower(strings.Trim(host, "[]")), port: port}
	dec, err := s.Matcher.Decide(t.host, port)
	if err != nil {
		t.dec = netmatch.Decision{Rule: "ungültig"}
		s.logDecision(t, false, err.Error())
		return nil, &errDenied{"ungültiges Ziel: " + err.Error()}
	}
	t.dec = dec
	if !dec.Allowed && !s.Learn {
		s.logDecision(t, false, "")
		return nil, &errDenied{fmt.Sprintf("%s:%d nicht freigegeben (Regel: %s)", t.host, port, dec.Rule)}
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.DialTimeout)
	defer cancel()
	var addrs []netip.Addr
	if a, err := netip.ParseAddr(t.host); err == nil {
		addrs = []netip.Addr{a.Unmap()}
	} else {
		addrs, err = s.Resolve(ctx, t.host)
		if err != nil || len(addrs) == 0 {
			s.logDecision(t, false, "DNS-Auflösung fehlgeschlagen")
			return nil, fmt.Errorf("%s konnte nicht aufgelöst werden", t.host)
		}
	}
	var allowed []netip.Addr
	for _, a := range addrs {
		if s.Matcher.AddressAllowed(a, port) {
			allowed = append(allowed, a.Unmap())
		}
	}
	if len(allowed) == 0 {
		t.ip = addrs[0].Unmap()
		s.logDecision(t, false, "private Adresse")
		return nil, &errDenied{fmt.Sprintf("%s:%d löst auf eine private/lokale Adresse auf (%s); network.allow_private oder CIDR-Freigabe nötig", t.host, port, addrs[0])}
	}
	var lastErr error
	for _, a := range allowed {
		c, err := s.Dial(ctx, "tcp", net.JoinHostPort(a.String(), strconv.Itoa(port)))
		if err == nil {
			t.ip = a
			s.logDecision(t, true, "")
			return c, nil
		}
		lastErr = err
	}
	t.ip = allowed[0]
	s.logDecision(t, false, "Verbindung fehlgeschlagen")
	return nil, lastErr
}

func pipe(a net.Conn, aReader io.Reader, b net.Conn) {
	a.SetReadDeadline(time.Time{})
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(b, aReader)
		if cw, ok := b.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		io.Copy(a, b)
		if cw, ok := a.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	<-done
}

func (s *Server) authOK(h http.Header) bool {
	if s.Token == "" {
		return true
	}
	v := h.Get("Proxy-Authorization")
	const prefix = "Basic "
	if !strings.HasPrefix(v, prefix) {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(v, prefix))
	if err != nil {
		return false
	}
	want := User + ":" + s.Token
	return subtle.ConstantTimeCompare(raw, []byte(want)) == 1
}

func httpError(c net.Conn, code int, msg string, extra string) {
	body := "sdbx: " + msg + "\n"
	fmt.Fprintf(c, "HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n%s\r\n%s",
		code, http.StatusText(code), len(body), extra, body)
}

func splitHostPort(hp string, defPort int) (string, int, error) {
	if !strings.Contains(hp, ":") || (strings.HasPrefix(hp, "[") && strings.HasSuffix(hp, "]")) {
		return strings.Trim(hp, "[]"), defPort, nil
	}
	h, p, err := net.SplitHostPort(hp)
	if err != nil {
		return "", 0, err
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return "", 0, fmt.Errorf("ungültiger Port")
	}
	return h, n, nil
}

// rawHostHeader liest den Host-Header aus dem noch ungeparsten Anfragekopf.
// http.ReadRequest ersetzt ihn bei absoluten URIs durch den URI-Host.
func rawHostHeader(br *bufio.Reader) (string, bool) {
	n := br.Buffered()
	if n == 0 {
		n = 1
	}
	for n <= br.Size() {
		b, err := br.Peek(n)
		if i := strings.Index(string(b), "\r\n\r\n"); i >= 0 {
			for _, line := range strings.Split(string(b[:i]), "\r\n")[1:] {
				k, v, ok := strings.Cut(line, ":")
				if ok && strings.EqualFold(strings.TrimSpace(k), "host") {
					return strings.TrimSpace(v), true
				}
			}
			return "", false
		}
		if err != nil {
			return "", false
		}
		if br.Buffered() > len(b) {
			n = br.Buffered()
		} else {
			n = len(b) + 1
		}
	}
	return "", false
}

func (s *Server) http(c net.Conn, br *bufio.Reader) {
	rawHost, hasHost := rawHostHeader(br)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if !s.authOK(req.Header) {
		httpError(c, http.StatusProxyAuthRequired, "Proxy-Authentifizierung fehlt oder ist falsch", "Proxy-Authenticate: Basic realm=\"sdbx\"\r\n")
		return
	}
	if req.Method == http.MethodConnect {
		host, port, err := splitHostPort(req.Host, 443)
		if err != nil {
			httpError(c, http.StatusBadRequest, "ungültiges CONNECT-Ziel", "")
			return
		}
		up, err := s.connect(host, port)
		if err != nil {
			code := http.StatusBadGateway
			var d *errDenied
			if errors.As(err, &d) {
				code = http.StatusForbidden
			}
			httpError(c, code, err.Error(), "X-Sdbx-Deny: 1\r\n")
			return
		}
		defer up.Close()
		fmt.Fprint(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
		pipe(c, br, up)
		return
	}
	if req.URL == nil || req.URL.Host == "" {
		httpError(c, http.StatusBadRequest, "Proxy-Anfragen brauchen eine absolute URI", "")
		return
	}
	if req.URL.Scheme != "http" {
		httpError(c, http.StatusBadRequest, "nur http:// ohne CONNECT erlaubt; für https CONNECT verwenden", "")
		return
	}
	uh, up, err1 := splitHostPort(req.URL.Host, 80)
	hostHeader := req.Host
	if hasHost {
		hostHeader = rawHost
	}
	hh, hp, err2 := splitHostPort(hostHeader, 80)
	if err1 != nil || err2 != nil || !strings.EqualFold(uh, hh) || up != hp {
		httpError(c, http.StatusBadRequest, "Host-Header weicht von der Ziel-URI ab", "")
		return
	}
	upc, err := s.connect(uh, up)
	if err != nil {
		code := http.StatusBadGateway
		var d *errDenied
		if errors.As(err, &d) {
			code = http.StatusForbidden
		}
		httpError(c, code, err.Error(), "X-Sdbx-Deny: 1\r\n")
		return
	}
	defer upc.Close()
	for _, h := range []string{"Proxy-Authorization", "Proxy-Connection", "Proxy-Authenticate"} {
		req.Header.Del(h)
	}
	req.Header.Set("Connection", "close")
	req.Close = true
	req.RequestURI = ""
	if err := req.Write(upc); err != nil {
		return
	}
	c.SetReadDeadline(time.Time{})
	io.Copy(c, upc)
}

// SOCKS5-Antwortcodes (RFC 1928).
const (
	socksOK           = 0x00
	socksFail         = 0x01
	socksNotAllowed   = 0x02
	socksHostUnreach  = 0x04
	socksCmdUnsupp    = 0x07
	socksAddrUnsupp   = 0x08
	socksMethodNone   = 0x00
	socksMethodUser   = 0x02
	socksMethodRefuse = 0xFF
)

func socksReply(c net.Conn, code byte) {
	c.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
}

func (s *Server) socks(c net.Conn, br *bufio.Reader) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	want := byte(socksMethodNone)
	if s.Token != "" {
		want = socksMethodUser
	}
	offered := false
	for _, m := range methods {
		offered = offered || m == want
	}
	if !offered {
		c.Write([]byte{5, socksMethodRefuse})
		return
	}
	c.Write([]byte{5, want})
	if want == socksMethodUser {
		v := make([]byte, 2)
		if _, err := io.ReadFull(br, v); err != nil {
			return
		}
		user := make([]byte, v[1])
		if _, err := io.ReadFull(br, user); err != nil {
			return
		}
		pl := make([]byte, 1)
		if _, err := io.ReadFull(br, pl); err != nil {
			return
		}
		pass := make([]byte, pl[0])
		if _, err := io.ReadFull(br, pass); err != nil {
			return
		}
		if string(user) != User || subtle.ConstantTimeCompare(pass, []byte(s.Token)) != 1 {
			c.Write([]byte{1, 1})
			return
		}
		c.Write([]byte{1, 0})
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil {
		return
	}
	if req[0] != 5 {
		return
	}
	if req[1] != 1 {
		socksReply(c, socksCmdUnsupp)
		return
	}
	var host string
	switch req[3] {
	case 1:
		b := make([]byte, 4)
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = netip.AddrFrom4([4]byte(b)).String()
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(br, l); err != nil {
			return
		}
		b := make([]byte, l[0])
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = string(b)
	case 4:
		b := make([]byte, 16)
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = netip.AddrFrom16([16]byte(b)).String()
	default:
		socksReply(c, socksAddrUnsupp)
		return
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(br, pb); err != nil {
		return
	}
	port := int(binary.BigEndian.Uint16(pb))
	up, err := s.connect(host, port)
	if err != nil {
		var d *errDenied
		if errors.As(err, &d) {
			socksReply(c, socksNotAllowed)
		} else {
			socksReply(c, socksHostUnreach)
		}
		return
	}
	defer up.Close()
	socksReply(c, socksOK)
	pipe(c, br, up)
}

// DialSOCKS verbindet über einen SOCKS5-Proxy (für __connect und Tests).
func DialSOCKS(proxyConn net.Conn, token, host string, port int) error {
	method := byte(socksMethodNone)
	if token != "" {
		method = socksMethodUser
	}
	if _, err := proxyConn.Write([]byte{5, 1, method}); err != nil {
		return err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(proxyConn, resp); err != nil {
		return err
	}
	if resp[1] != method {
		return fmt.Errorf("Proxy lehnt Authentifizierung ab")
	}
	if token != "" {
		msg := []byte{1, byte(len(User))}
		msg = append(msg, User...)
		msg = append(msg, byte(len(token)))
		msg = append(msg, token...)
		proxyConn.Write(msg)
		if _, err := io.ReadFull(proxyConn, resp); err != nil {
			return err
		}
		if resp[1] != 0 {
			return fmt.Errorf("Proxy-Authentifizierung fehlgeschlagen")
		}
	}
	if len(host) > 255 {
		return fmt.Errorf("Hostname zu lang")
	}
	msg := []byte{5, 1, 0, 3, byte(len(host))}
	msg = append(msg, host...)
	msg = binary.BigEndian.AppendUint16(msg, uint16(port))
	proxyConn.Write(msg)
	rep := make([]byte, 10)
	if _, err := io.ReadFull(proxyConn, rep); err != nil {
		return err
	}
	switch rep[1] {
	case socksOK:
		return nil
	case socksNotAllowed:
		return fmt.Errorf("sdbx: %s:%d ist nicht freigegeben", host, port)
	default:
		return fmt.Errorf("SOCKS-Fehler %d", rep[1])
	}
}
