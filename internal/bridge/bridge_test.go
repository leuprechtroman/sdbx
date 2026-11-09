package bridge

import (
	"bufio"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestRelayTCPToUnix(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "up.sock")
	ul, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ul.Close()
	go func() {
		for {
			c, err := ul.Accept()
			if err != nil {
				return
			}
			go func() {
				line, _ := bufio.NewReader(c).ReadString('\n')
				fmt.Fprintf(c, "echo:%s", line)
				c.Close()
			}()
		}
	}()
	p, err := ParsePair("tcp:127.0.0.1:0=unix:" + sock)
	if err != nil {
		t.Fatal(err)
	}
	l, err := Listen(p)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go Relay(l, p.Target)
	c, err := net.DialTimeout("tcp", l.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(c, "ping\n")
	resp, _ := bufio.NewReader(c).ReadString('\n')
	if resp != "echo:ping\n" {
		t.Fatalf("Antwort %q", resp)
	}
}

func TestParsePair(t *testing.T) {
	for _, bad := range []string{"x", "tcp:1=", "udp:1=unix:/x", "=unix:/x"} {
		if _, err := ParsePair(bad); err == nil {
			t.Errorf("%q hätte abgelehnt werden müssen", bad)
		}
	}
}

func TestConnectNeedsProxy(t *testing.T) {
	t.Setenv("ALL_PROXY", "")
	t.Setenv("all_proxy", "")
	if err := Connect("h", "22", nil, nil); err == nil {
		t.Fatal("ohne ALL_PROXY muss __connect fehlschlagen")
	}
}
