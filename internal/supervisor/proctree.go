package supervisor

import (
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

// processTable liefert pid → ppid aller Prozesse.
func processTable() map[int]int {
	t := map[int]int{}
	if runtime.GOOS == "linux" {
		ents, _ := os.ReadDir("/proc")
		for _, e := range ents {
			pid, err := strconv.Atoi(e.Name())
			if err != nil {
				continue
			}
			b, err := os.ReadFile("/proc/" + e.Name() + "/stat")
			if err != nil {
				continue
			}
			s := string(b)
			i := strings.LastIndexByte(s, ')')
			if i < 0 {
				continue
			}
			f := strings.Fields(s[i+1:])
			if len(f) > 1 {
				if pp, err := strconv.Atoi(f[1]); err == nil {
					t[pid] = pp
				}
			}
		}
		return t
	}
	out, err := exec.Command("ps", "-A", "-o", "pid=,ppid=").Output()
	if err != nil {
		return t
	}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 {
			pid, e1 := strconv.Atoi(f[0])
			pp, e2 := strconv.Atoi(f[1])
			if e1 == nil && e2 == nil {
				t[pid] = pp
			}
		}
	}
	return t
}

// descendants liefert root und alle Nachfahren.
func descendants(root int, t map[int]int) []int {
	children := map[int][]int{}
	for pid, pp := range t {
		children[pp] = append(children[pp], pid)
	}
	out := []int{root}
	for i := 0; i < len(out); i++ {
		out = append(out, children[out[i]]...)
	}
	return out
}

// killTree sendet sig an alle Nachfahren von root (Kinder zuerst eingesammelt), mit withRoot auch an root.
func killTree(root int, sig syscall.Signal, withRoot bool) {
	if root <= 0 {
		return
	}
	pids := descendants(root, processTable())
	if !withRoot {
		pids = pids[1:]
	}
	for i := len(pids) - 1; i >= 0; i-- {
		syscall.Kill(pids[i], sig)
	}
}

// signalChildren sendet sig an die direkten Kinder von pid.
func signalChildren(pid int, sig syscall.Signal) {
	for c, pp := range processTable() {
		if pp == pid {
			syscall.Kill(c, sig)
		}
	}
}
