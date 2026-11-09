// Package bridge leitet Verbindungen zwischen TCP und Unix-Sockets weiter (Spec 2.3, 6.4)
// und stellt __connect für SSH-ProxyCommand bereit.
package bridge

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"

	"sdbx/internal/proxy"
)

// Pair beschreibt eine Weiterleitung.
type Pair struct {
	Listen string // "tcp:127.0.0.1:3128" oder "unix:/pfad"
	Target string // "unix:/pfad" oder "tcp:127.0.0.1:5432"
}

// ParsePair parst "listen=target".
func ParsePair(s string) (Pair, error) {
	l, t, ok := strings.Cut(s, "=")
	if !ok || !validAddr(l) || !validAddr(t) {
		return Pair{}, fmt.Errorf("ungültige Weiterleitung %q (Format: tcp:127.0.0.1:N=unix:/pfad)", s)
	}
	return Pair{Listen: l, Target: t}, nil
}

func (p Pair) String() string { return p.Listen + "=" + p.Target }

func validAddr(a string) bool {
	return strings.HasPrefix(a, "tcp:") || strings.HasPrefix(a, "unix:")
}

func split(a string) (network, addr string) {
	n, rest, _ := strings.Cut(a, ":")
	return n, rest
}

// Listen öffnet den Listener einer Weiterleitung.
func Listen(p Pair) (net.Listener, error) {
	n, a := split(p.Listen)
	if n == "unix" {
		os.Remove(a)
	}
	return net.Listen(n, a)
}

// Relay nimmt Verbindungen an und verbindet sie mit dem Ziel.
func Relay(l net.Listener, target string) error {
	n, a := split(target)
	for {
		c, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go func() {
			defer c.Close()
			u, err := net.Dial(n, a)
			if err != nil {
				return
			}
			defer u.Close()
			Pipe(c, u)
		}()
	}
}

// Pipe kopiert in beide Richtungen, bis beide Seiten fertig sind.
func Pipe(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		} else {
			dst.Close()
		}
	}
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
}

// Run startet alle Weiterleitungen und blockiert.
func Run(pairs []Pair) error {
	errc := make(chan error, len(pairs))
	for _, p := range pairs {
		l, err := Listen(p)
		if err != nil {
			return fmt.Errorf("%s: %w", p.Listen, err)
		}
		go func(l net.Listener, t string) { errc <- Relay(l, t) }(l, p.Target)
	}
	return <-errc
}

// Connect verbindet stdin/stdout über den SOCKS-Proxy aus ALL_PROXY mit host:port
// (für GIT_SSH_COMMAND="ssh -o ProxyCommand='sdbx __connect %h %p'").
func Connect(host, port string, stdin io.Reader, stdout io.Writer) error {
	raw := os.Getenv("ALL_PROXY")
	if raw == "" {
		raw = os.Getenv("all_proxy")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("ALL_PROXY ist nicht gesetzt – __connect funktioniert nur innerhalb von sdbx")
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("ungültiger Port %q", port)
	}
	c, err := net.Dial("tcp", u.Host)
	if err != nil {
		return err
	}
	defer c.Close()
	tok, _ := u.User.Password()
	if err := proxy.DialSOCKS(c, tok, host, p); err != nil {
		return err
	}
	done := make(chan struct{}, 2)
	go func() { io.Copy(c, stdin); c.(*net.TCPConn).CloseWrite(); done <- struct{}{} }()
	go func() { io.Copy(stdout, c); done <- struct{}{} }()
	<-done
	return nil
}
