//go:build escape && darwin

package escape

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// Stirbt der Aufräumprozess vor dem Befehl, kann sdbx abgelöste Prozesse nicht mehr beenden und muss warnen.
func TestReaperKilledWarns(t *testing.T) {
	e := newEnv(t, "")
	cmd, wait := e.start(nil, sdbxBin, "run", "--", "sh", "-c", `exec >/dev/null 2>&1; echo $$ > pid-sh; touch bereit; sleep 30`)
	e.waitFile("bereit")
	out, _ := exec.Command("pgrep", "-P", strconv.Itoa(cmd.Process.Pid), "-f", "__reap").Output()
	reaper, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		cmd.Process.Kill()
		t.Fatalf("Aufräumprozess nicht gefunden: %q", out)
	}
	syscall.Kill(reaper, syscall.SIGKILL)
	r := wait()
	if b, err := os.ReadFile(filepath.Join(e.ws, "pid-sh")); err == nil {
		if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
			syscall.Kill(pid, syscall.SIGKILL)
		}
	}
	expect(t, r, "Aufräumprozess der Sandbox wurde vorzeitig beendet")
}

// Unter macOS verhindert Seatbelt das Anlegen geschützter Pfade bereits.
func TestProtectedCreationBlocked(t *testing.T) {
	e := newEnv(t, "")
	r := e.sh(`echo 'export X=1' > .envrc && echo ENVRC; mkdir -p .vscode && echo VSCODE`)
	refuse(t, r, "ENVRC")
	refuse(t, r, "VSCODE")
	if _, err := os.Stat(filepath.Join(e.ws, ".envrc")); err == nil {
		t.Error(".envrc wurde angelegt")
	}
}

// Die Zwischenablage ist ein Exfiltrationsweg (Mach-Service com.apple.pasteboard.1).
// Das Find-Pasteboard statt der allgemeinen Zwischenablage, damit die Gegenprobe sie nicht überschreibt.
func TestPasteboardBlocked(t *testing.T) {
	const try = `echo GEHEIM-CLIP | pbcopy -pboard find && pbpaste -pboard find`
	e := newEnv(t, "")
	refuse(t, e.sh(try), "GEHEIM-CLIP")
	e.config("version: 1\nmacos:\n  mach_services: [default, com.apple.pasteboard.1]\n")
	expect(t, e.sh(try), "GEHEIM-CLIP")
}

// Ohne Mach-Gruppe keychain ist der Schlüsselbund nicht erreichbar.
// Mit dem Test-HOME gibt es keinen login-Schlüsselbund; System.keychain listet securityd aber immer.
func TestKeychainBlockedByDefault(t *testing.T) {
	const try = `security list-keychains 2>&1`
	e := newEnv(t, "")
	refuse(t, e.sh(try), "System.keychain")
	e.config("version: 1\nmacos:\n  mach_services: [default, keychain]\n")
	expect(t, e.sh(try), "System.keychain")
}

// AppleEvents dürfen keine anderen Apps steuern.
// "get name" taugt nicht: AppleScript beantwortet name/id/version lokal, ohne ein Event zu senden.
// Keine Gegenprobe mit Freigabe: Der Mach-Service allein reicht nicht, Seatbelt verweigert zusätzlich appleevent-send.
func TestAppleEventsBlocked(t *testing.T) {
	const try = `osascript -e 'tell application "Finder" to count windows' 2>/dev/null && echo GESTEUERT`
	e := newEnv(t, "")
	requireHost(t, e.hostSh(try), "GESTEUERT")
	refuse(t, e.sh(try), "GESTEUERT")
}

// Verstöße sofort nach dem Start und von kurzlebigen Kindprozessen landen in der Zusammenfassung;
// ein paralleler Lauf mit eigener Markierung wird nicht mitgezählt.
func TestViolationsReported(t *testing.T) {
	e := newEnv(t, "version: 1\naudit:\n  summary: true\n")
	other := newEnv(t, "")
	done := make(chan struct{})
	go func() {
		defer close(done)
		other.sh(`sleep 0.5; cat "$HOME/notes.txt" > /dev/null; echo x > "$HOME/fremder-lauf"`)
	}()
	r := e.run(nil, "run", "--", "sh", "-c", `echo x > "$HOME/sofort"; cat "$HOME/.ssh/id_ed25519"; sleep 1; true`)
	<-done
	expect(t, r, "/sofort")
	expect(t, r, "id_ed25519")
	if strings.Contains(r.err, "fremder-lauf") {
		t.Errorf("Verstoß eines anderen Laufs zugeordnet:\n%s", r.err)
	}
}

// Der Proxy ist auf macOS über 127.0.0.1 erreichbar und braucht das Token.
func TestProxyNeedsToken(t *testing.T) {
	e := newEnv(t, "")
	expect(t, e.py(`import os, re, urllib.request
os.environ.pop("NO_PROXY", None); os.environ.pop("no_proxy", None)
u = re.sub(r"//[^@]+@", "//", os.environ["HTTP_PROXY"])
try:
    urllib.request.build_opener(urllib.request.ProxyHandler({"http": u})).open("http://example.com", timeout=5)
    print("OHNE-TOKEN")
except urllib.error.HTTPError as ex:
    print("CODE", ex.code)`), "CODE 407")
}
