package audit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestEmitJSONAndSummary(t *testing.T) {
	var buf bytes.Buffer
	l := New("r1", &buf, "json")
	l.now = func() time.Time { return time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC) }
	l.Emit("net.deny", map[string]any{"host": "evil.com", "port": 443})
	l.Emit("net.deny", map[string]any{"host": "evil.com", "port": 443})
	l.Emit("net.allow", map[string]any{"host": "ok.com", "port": 443})
	var rec map[string]any
	if err := json.Unmarshal([]byte(strings.Split(buf.String(), "\n")[0]), &rec); err != nil {
		t.Fatal(err)
	}
	if rec["type"] != "net.deny" || rec["host"] != "evil.com" || rec["run"] != "r1" || rec["ts"] != "2026-10-28T12:00:00Z" {
		t.Errorf("JSON: %v", rec)
	}
	var s bytes.Buffer
	l.Summary(&s)
	if !strings.Contains(s.String(), "net evil.com:443 (2×)") || strings.Contains(s.String(), "ok.com") {
		t.Errorf("Zusammenfassung: %s", s.String())
	}
}

func TestParseSandboxMessage(t *testing.T) {
	cases := map[string][2]string{
		"Sandbox: git(1234) deny(1) file-read-data /Users/r/.ssh/id_ed25519":          {"fs.deny", "/Users/r/.ssh/id_ed25519"},
		"Sandbox: Google Chrome He(812) deny(1) mach-lookup com.apple.CARenderServer": {"mach.deny", ""},
		"Sandbox: curl(99) deny(1) network-outbound /private/tmp/x.sock":              {"socket.deny", "/private/tmp/x.sock"},
		"Sandbox: curl(99) deny(1) network-outbound 93.184.216.34:443":                {"net.deny", ""},
	}
	for msg, want := range cases {
		v, ok := ParseSandboxMessage(msg)
		if !ok {
			t.Fatalf("nicht erkannt: %s", msg)
		}
		typ, f := EventFor(v)
		if typ != want[0] || (want[1] != "" && f["path"] != want[1]) {
			t.Errorf("%s → %s %v", msg, typ, f)
		}
	}
	if v, _ := ParseSandboxMessage("Sandbox: Google Chrome He(812) deny(1) mach-lookup x"); v.Process != "Google Chrome He" || v.PID != 812 {
		t.Errorf("Prozessname mit Leerzeichen: %+v", v)
	}
	v, ok := ParseSandboxMessage("Sandbox: cat(7) deny(1) file-read-data /Users/r/.ssh/id\nsdbx-run:abc")
	if !ok || v.Target != "/Users/r/.ssh/id" || v.Marker != "sdbx-run:abc" {
		t.Errorf("Markierung: %+v", v)
	}
	l := New("r", nil, "json")
	readNDJSON(strings.NewReader(
		`{"eventMessage":"Sandbox: a(5) deny(1) file-write-create /x\nsdbx-run:r"}`+"\n"+
			`{"eventMessage":"Sandbox: b(6) deny(1) file-read-data /y\nsdbx-run:anderer"}`+"\n"+
			`{"eventMessage":"Sandbox: c(7) deny(1) file-read-data /z"}`+"\n"), l, RunMarker("r"))
	if l.Count("fs.deny") != 1 {
		t.Error("Markierungsfilter greift nicht")
	}
}

func TestParseStrace(t *testing.T) {
	log := `123 openat(AT_FDCWD, "/home/u/.ssh/id_ed25519", O_RDONLY|O_CLOEXEC) = -1 EACCES (Permission denied)
[pid   124] mkdir("/home/u/.cache/x", 0777) = -1 EROFS (Read-only file system)
125 openat(AT_FDCWD, "/etc/ok", O_RDONLY) = 3
126 connect(3, {sa_family=AF_UNIX, sun_path="/run/x.sock"}, 110) = -1 ENOENT (No such file or directory)
123 openat(AT_FDCWD, "/home/u/.ssh/id_ed25519", O_RDONLY|O_CLOEXEC) = -1 EACCES (Permission denied)
`
	l := New("r", nil, "json")
	ParseStrace(strings.NewReader(log), l)
	if l.Count("fs.deny") != 2 {
		t.Fatalf("erwartet 2 Verstöße, %d", l.Count("fs.deny"))
	}
}
