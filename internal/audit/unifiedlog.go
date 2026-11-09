package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Zeilenformat: "Sandbox: prozess(pid) deny(1) operation ziel"
var sandboxLine = regexp.MustCompile(`Sandbox: (.+?)\((\d+)\) deny\(\d+\) (\S+)(?: (.*))?$`)

// Violation ist ein Seatbelt-Verstoß aus dem Unified Log.
type Violation struct {
	Process string
	PID     int
	Op      string
	Target  string
	Marker  string // Text aus "(with message …)" der verweigernden Regel
}

// RunMarker ist die Markierung, mit der das Seatbelt-Profil eines Laufs seine Verweigerungen versieht.
func RunMarker(runID string) string { return "sdbx-run:" + runID }

// ParseSandboxMessage parst eine Seatbelt-Meldung. Seatbelt hängt "(with message …)" in einer eigenen Zeile an.
func ParseSandboxMessage(msg string) (Violation, bool) {
	line, marker, _ := strings.Cut(strings.TrimSpace(msg), "\n")
	m := sandboxLine.FindStringSubmatch(strings.TrimSpace(line))
	if m == nil {
		return Violation{}, false
	}
	pid, _ := strconv.Atoi(m[2])
	return Violation{Process: m[1], PID: pid, Op: m[3], Target: strings.TrimSpace(m[4]), Marker: strings.TrimSpace(marker)}, true
}

// EventFor ordnet einen Verstoß einem Audit-Ereignis zu.
func EventFor(v Violation) (string, map[string]any) {
	f := map[string]any{"process": v.Process, "pid": v.PID, "op": v.Op}
	switch {
	case v.Op == "mach-lookup":
		f["service"] = v.Target
		return "mach.deny", f
	case strings.HasPrefix(v.Op, "network-outbound") && strings.HasPrefix(v.Target, "/"):
		f["path"] = v.Target
		return "socket.deny", f
	case strings.HasPrefix(v.Op, "network"):
		f["target"] = v.Target
		return "net.deny", f
	default:
		f["path"] = v.Target
		return "fs.deny", f
	}
}

// StreamUnifiedLog liest "log stream" (nur macOS) und meldet Verstöße mit der Markierung marker.
// Es kehrt erst zurück, wenn der Stream mitliest, damit Verstöße direkt nach dem Start nicht fehlen.
// stop beendet das Lesen.
func StreamUnifiedLog(l *Logger, marker string) (stop func(), err error) {
	cmd := exec.Command("/usr/bin/log", "stream", "--style", "ndjson", "--predicate", `sender == "Sandbox"`)
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	br := bufio.NewReader(out)
	ready := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		// Kopfzeile "Filtering the log data using …": ab hier werden Meldungen erfasst
		_, err := br.ReadString('\n')
		ready <- err
		if err == nil {
			readNDJSON(br, l, marker)
		}
	}()
	stop = func() {
		cmd.Process.Kill()
		cmd.Wait()
		<-done
	}
	select {
	case err := <-ready:
		if err != nil {
			stop()
			return nil, fmt.Errorf("log stream: %w", err)
		}
	case <-time.After(5 * time.Second):
		stop()
		return nil, fmt.Errorf("log stream: keine Ausgabe nach 5 s")
	}
	return stop, nil
}

func readNDJSON(r io.Reader, l *Logger, marker string) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var rec struct {
			EventMessage string `json:"eventMessage"`
		}
		if json.Unmarshal(sc.Bytes(), &rec) != nil {
			continue
		}
		v, ok := ParseSandboxMessage(rec.EventMessage)
		if !ok || v.Marker != marker {
			continue
		}
		typ, f := EventFor(v)
		l.Emit(typ, f)
	}
}

// strace-Zeile: 123 openat(AT_FDCWD, "/home/u/.ssh/id", O_RDONLY) = -1 EACCES (Permission denied)
var straceLine = regexp.MustCompile(`^(?:\[pid\s+)?(\d+)\]?\s+(\w+)\((.*)\)\s+= -1 (EACCES|EPERM|EROFS)`)
var firstQuoted = regexp.MustCompile(`"((?:[^"\\]|\\.)*)"`)

// straceNoise filtert Proben ohne Wirkung und die Einrichtung durch bwrap selbst.
func straceNoise(op, path string) bool {
	switch op {
	case "access", "faccessat", "faccessat2", "stat", "lstat", "newfstatat", "statx", "readlink", "readlinkat", "statfs":
		return true
	}
	for _, p := range []string{"/newroot", "/oldroot", "/proc/", "/sys/"} {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// ParseStrace wertet ein strace-Protokoll für den Lernmodus aus.
func ParseStrace(r io.Reader, l *Logger) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	seen := map[string]bool{}
	for sc.Scan() {
		m := straceLine.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		q := firstQuoted.FindStringSubmatch(m[3])
		if q == nil || !strings.HasPrefix(q[1], "/") || straceNoise(m[2], q[1]) {
			continue
		}
		key := m[2] + " " + q[1]
		if seen[key] {
			continue
		}
		seen[key] = true
		pid, _ := strconv.Atoi(m[1])
		l.Emit("fs.deny", map[string]any{"op": m[2], "path": q[1], "errno": m[4], "pid": pid})
	}
}
