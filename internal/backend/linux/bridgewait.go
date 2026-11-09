package linux

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// waitBridge wartet, bis alle TCP-Listener der Bridge erreichbar sind.
func waitBridge(pairs []string) error {
	deadline := time.Now().Add(5 * time.Second)
	for _, p := range pairs {
		l, _, _ := strings.Cut(p, "=")
		if !strings.HasPrefix(l, "tcp:") {
			continue
		}
		addr := strings.TrimPrefix(l, "tcp:")
		for {
			c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
			if err == nil {
				c.Close()
				break
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("Bridge auf %s startet nicht: %v", addr, err)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	return nil
}
