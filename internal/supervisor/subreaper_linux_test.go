package supervisor

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Ein Enkel, dessen Elternprozess endet, hängt danach an sdbx und wird vom Aufräumen erfasst.
func TestSubreaperCollectsOrphans(t *testing.T) {
	if !becomeSubreaper() {
		t.Fatal("PR_SET_CHILD_SUBREAPER fehlgeschlagen")
	}
	out, err := exec.Command("sh", "-c", "setsid sleep 30 >/dev/null 2>&1 & echo $!").Output()
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Kill(pid, syscall.SIGKILL)
	if pp := processTable()[pid]; pp != os.Getpid() {
		t.Fatalf("Waise %d hängt an %d statt an sdbx (%d)", pid, pp, os.Getpid())
	}
	killTree(os.Getpid(), syscall.SIGKILL, false)
	var ws syscall.WaitStatus
	for i := 0; i < 100; i++ {
		if p, _ := syscall.Wait4(pid, &ws, syscall.WNOHANG, nil); p == pid {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Error("Waise läuft nach killTree weiter")
}
