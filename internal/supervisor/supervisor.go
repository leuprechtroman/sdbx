// Package supervisor führt einen Befehl in der Sandbox aus (Spec 2.2–2.4).
package supervisor

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"sdbx/internal/audit"
	"sdbx/internal/backend"
	"sdbx/internal/backend/darwin"
	"sdbx/internal/backend/linux"
	"sdbx/internal/bridge"
	"sdbx/internal/envfilter"
	"sdbx/internal/integrations"
	"sdbx/internal/policy"
	"sdbx/internal/proxy"
	"sdbx/internal/reaper"
	"sdbx/internal/tui"
	"sdbx/internal/version"
)

// Exit-Codes (Spec 3.3).
const (
	ExitTimeout  = 124
	ExitConfig   = 125
	ExitSetup    = 126
	ExitNotFound = 127
)

// SetupError ist ein Fehler beim Einrichten der Sandbox (Exit 126).
type SetupError struct{ Err error }

func (e *SetupError) Error() string { return e.Err.Error() }
func (e *SetupError) Unwrap() error { return e.Err }

// NotFoundError meldet einen nicht gefundenen Befehl (Exit 127).
type NotFoundError struct{ Cmd string }

func (e *NotFoundError) Error() string { return "Befehl nicht gefunden: " + e.Cmd }

// Options steuern einen Lauf.
type Options struct {
	Policy       *policy.Policy
	Caps         policy.Caps
	Integrations []*integrations.Result
	Argv         []string
	HostEnv      []string
	Cwd          string
	Exe          string
	RunID        string
	Log          *audit.Logger
	Stdin        io.Reader
	Stdout       io.Writer
	Stderr       io.Writer
	Learn        bool
	KeepTmp      bool
	DryRun       bool
	Verbose      bool
}

// NewRunID erzeugt eine zufällige Lauf-ID.
func NewRunID() string {
	b := make([]byte, 6)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func randomToken() string {
	b := make([]byte, 24)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func randomPort() int {
	n, _ := rand.Int(rand.Reader, big.NewInt(40000))
	return 20000 + int(n.Int64())
}

// TmpDirFor liefert den Pfad des privaten Temp-Verzeichnisses für eine Lauf-ID.
func TmpDirFor(userTmp, runID string) string {
	return filepath.Join(userTmp, "sdbx-"+runID)
}

func (o *Options) printf(format string, a ...any) {
	fmt.Fprintf(o.Stderr, "sdbx: "+format+"\n", a...)
}

// Run führt den Lauf aus und liefert den Exit-Code des Zielbefehls.
func Run(o Options) (int, error) {
	p := o.Policy
	if len(o.Argv) == 0 {
		return ExitConfig, fmt.Errorf("kein Befehl angegeben")
	}
	for _, r := range o.Integrations {
		if r.Argv != nil {
			if o.Verbose {
				o.printf("Integration %s schreibt die Kommandozeile um: %s", r.Name, strings.Join(r.Argv, " "))
			}
			o.Argv = r.Argv
		}
	}
	// Laufverzeichnisse
	if err := os.MkdirAll(p.SdbxTmp, 0o700); err != nil {
		return ExitSetup, &SetupError{err}
	}
	runDir := filepath.Join(p.SdbxTmp, ".sdbx")
	if err := os.MkdirAll(filepath.Join(runDir, "net"), 0o700); err != nil {
		return ExitSetup, &SetupError{err}
	}
	if !o.KeepTmp && !o.DryRun {
		defer os.RemoveAll(p.SdbxTmp)
	}
	for i, r := range p.Rules {
		if r.Create && !r.Exists {
			if err := os.MkdirAll(r.Path, 0o755); err != nil {
				return ExitSetup, &SetupError{fmt.Errorf("create_missing %s: %w", r.Path, err)}
			}
			p.Rules[i].Exists, p.Rules[i].IsDir = true, true
		}
	}
	rt := &backend.Runtime{RunID: o.RunID, RunDir: runDir, SdbxTmp: p.SdbxTmp, SdbxExe: o.Exe, Cwd: o.Cwd, Argv: o.Argv}
	for _, r := range o.Integrations {
		rt.SocketAllowDirs = append(rt.SocketAllowDirs, r.SocketAllowDirs...)
	}
	bwrapMode := p.Platform == "linux" && p.Linux.Backend != "landlock"

	// Proxy und lokale Ports
	var srv *proxy.Server
	token := randomToken()
	if p.Net.Mode == "proxy" {
		srv = &proxy.Server{Matcher: p.Net.Matcher, Token: token, Log: o.Log, Learn: o.Learn}
		var l net.Listener
		var err error
		if bwrapMode {
			rt.ProxyHostSocket = filepath.Join(runDir, "net", "proxy.sock")
			l, err = net.Listen("unix", rt.ProxyHostSocket)
			rt.ProxyPort = randomPort()
		} else {
			l, err = net.Listen("tcp", "127.0.0.1:0")
			if err == nil {
				rt.ProxyPort = l.Addr().(*net.TCPAddr).Port
			}
		}
		if err != nil {
			return ExitSetup, &SetupError{fmt.Errorf("Proxy: %w", err)}
		}
		go srv.Serve(l)
		defer srv.Close()
	}
	if bwrapMode && p.Net.Mode != "host" {
		rt.LocalSockets = map[int]string{}
		for _, port := range p.Net.Local {
			sock := filepath.Join(runDir, "net", fmt.Sprintf("local-%d.sock", port))
			l, err := net.Listen("unix", sock)
			if err != nil {
				return ExitSetup, &SetupError{err}
			}
			defer l.Close()
			go bridge.Relay(l, "tcp:127.0.0.1:"+strconv.Itoa(port))
			rt.LocalSockets[port] = sock
		}
	}

	// Umgebung
	innerTmp, innerExe := p.SdbxTmp, o.Exe
	if p.Platform == "linux" {
		innerTmp = linux.InnerTmp(p, rt)
		if bwrapMode {
			innerExe = linux.NewLayout(p, rt).ExeInner
		}
	}
	forced := map[string]string{
		"SDBX": "1", "SDBX_VERSION": version.Version, "SDBX_WORKSPACE": p.Workspace, "SDBX_RUN": o.RunID, "TMPDIR": innerTmp,
	}
	if srv != nil {
		hp := fmt.Sprintf("http://%s:%s@127.0.0.1:%d", proxy.User, token, rt.ProxyPort)
		sp := fmt.Sprintf("socks5h://%s:%s@127.0.0.1:%d", proxy.User, token, rt.ProxyPort)
		for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
			forced[k] = hp
		}
		forced["ALL_PROXY"], forced["all_proxy"] = sp, sp
		forced["NO_PROXY"], forced["no_proxy"] = "localhost,127.0.0.1,::1", "localhost,127.0.0.1,::1"
		forced["NODE_USE_ENV_PROXY"] = "1"
		if p.Net.SSH {
			forced["GIT_SSH_COMMAND"] = fmt.Sprintf("ssh -o ProxyCommand='%s __connect %%h %%p'", innerExe)
		}
	}
	envRes := envfilter.Build(o.HostEnv, p.Env, forced)
	rt.Env = envRes.Env
	if len(envRes.Removed) > 0 {
		o.Log.Emit("env.removed", map[string]any{"names": envRes.Removed})
	}
	if len(envRes.Lifted) > 0 {
		o.printf("Warnung: eingebaute Sperre aufgehoben für %s (env.passthrough)", strings.Join(envRes.Lifted, ", "))
	}

	// Befehl vorab suchen (Exit 127)
	pathEnv, _ := envfilter.Lookup(rt.Env, "PATH")
	if _, err := LookPath(o.Argv[0], pathEnv, o.Cwd); err != nil {
		return ExitNotFound, &NotFoundError{Cmd: o.Argv[0]}
	}

	// Backend
	var launch *backend.Launch
	var err error
	switch p.Platform {
	case "darwin":
		launch, err = darwin.Prepare(p, rt)
	case "linux":
		f := linux.Facts{}
		if bwrapMode {
			f = linux.HostFacts(p, rt)
		}
		f.Cgroup = o.Caps.Cgroup
		launch, err = linux.Prepare(p, rt, f)
	default:
		err = fmt.Errorf("Plattform %s wird nicht unterstützt", p.Platform)
	}
	if err != nil {
		return ExitSetup, &SetupError{err}
	}
	if o.Verbose {
		for _, n := range launch.Notes {
			o.printf("%s", n)
		}
	}
	args, env := launch.Args, launch.Env
	// cgroup v2 über systemd-run (Spec 7.7)
	if p.Platform == "linux" && o.Caps.Cgroup && (p.Limits.MaxMemory > 0 || p.Limits.MaxProcesses > 0) {
		sr, err := exec.LookPath("systemd-run")
		if err != nil {
			return ExitSetup, &SetupError{fmt.Errorf("systemd-run fehlt")}
		}
		envBin, _ := exec.LookPath("env")
		args, env = cgroupWrap(sr, envBin, p.Limits, args, env, os.Getuid())
	}
	// Lernmodus unter Linux: strace um den Start legen
	straceLog := ""
	if o.Learn && p.Platform == "linux" {
		if st, err := exec.LookPath("strace"); err == nil {
			straceLog = filepath.Join(runDir, "strace.log")
			args = append([]string{st, "-f", "-qq", "-e", "trace=%file,connect", "-e", "status=failed", "-o", straceLog, "--"}, args...)
		} else {
			o.printf("Hinweis: strace fehlt – Dateisystem-Verstöße werden im Lernmodus nicht erfasst")
		}
	}
	if o.DryRun {
		fmt.Fprintln(o.Stdout, shellQuote(args))
		return 0, nil
	}

	cmd := &exec.Cmd{Path: args[0], Args: args, Env: env, Dir: launch.Dir, Stdin: o.Stdin, Stdout: o.Stdout, Stderr: o.Stderr}
	var reapStatus *os.File
	if launch.Reaper {
		r, w, err := os.Pipe()
		if err != nil {
			return ExitSetup, &SetupError{err}
		}
		defer r.Close()
		defer w.Close()
		cmd.ExtraFiles = []*os.File{w} // fd 3 = reaper.StatusFD
		reapStatus = r
	}
	o.Log.Emit("run.start", map[string]any{"argv": o.Argv, "platform": p.Platform, "workspace": p.Workspace})

	// macOS: Verstöße aus dem Unified Log, zugeordnet über die Markierung im Profil
	var stopLog func()
	if p.Platform == "darwin" {
		if stop, err := audit.StreamUnifiedLog(o.Log, audit.RunMarker(o.RunID)); err == nil {
			stopLog = stop
			defer stopLog()
		} else {
			o.printf("Warnung: Verstöße werden nicht protokolliert (%v)", err)
		}
	}

	interactive := false
	if f, ok := o.Stdin.(*os.File); ok {
		interactive = tui.IsTerminal(int(f.Fd()))
	}
	sigs := make(chan os.Signal, 8)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGWINCH)
	defer signal.Stop(sigs)
	subreaper := becomeSubreaper()
	start := time.Now()
	if err := cmd.Start(); err != nil {
		return ExitSetup, &SetupError{fmt.Errorf("Start fehlgeschlagen: %w", err)}
	}
	for _, f := range cmd.ExtraFiles {
		f.Close()
	}
	waitc := make(chan error, 1)
	go func() { waitc <- cmd.Wait() }()
	var timeout <-chan time.Time
	if p.Limits.Timeout > 0 {
		t := time.NewTimer(p.Limits.Timeout)
		defer t.Stop()
		timeout = t.C
	}
	timedOut := false
	var waitErr error
loop:
	for {
		select {
		case err := <-waitc:
			waitErr = err
			break loop
		case s := <-sigs:
			// Bei interaktiven Läufen bekommt das Kind Ctrl-C selbst (gleiche Prozessgruppe).
			if interactive && (s == syscall.SIGINT || s == syscall.SIGQUIT || s == syscall.SIGWINCH) {
				continue
			}
			switch {
			case launch.Reaper:
				signalChildren(cmd.Process.Pid, s.(syscall.Signal))
			case bwrapMode:
				// bwrap leitet Signale nicht weiter, sondern stirbt, und --die-with-parent tötet die Sandbox per SIGKILL.
				// Init im PID-Namespace ignoriert Signale ohne Handler; ankommen sollen sie beim Befehl und seinen Kindern.
				killTree(cmd.Process.Pid, s.(syscall.Signal), false)
			default:
				cmd.Process.Signal(s)
			}
		case <-timeout:
			timedOut = true
			o.Log.Emit("limit.hit", map[string]any{"limit": "timeout", "value": p.Limits.Timeout.String()})
			o.printf("Timeout nach %s – Prozess wird beendet", p.Limits.Timeout)
			// Der Aufräumer bleibt verschont: Er beendet nach dem Befehl die abgelösten Prozesse.
			killTree(cmd.Process.Pid, syscall.SIGTERM, !launch.Reaper)
			grace := time.NewTimer(p.Limits.KillGrace)
			select {
			case waitErr = <-waitc:
				grace.Stop()
			case <-grace.C:
				killTree(cmd.Process.Pid, syscall.SIGKILL, !launch.Reaper)
				select {
				case waitErr = <-waitc:
				case <-time.After(5 * time.Second):
					cmd.Process.Kill()
					waitErr = <-waitc
				}
			}
			break loop
		}
	}
	if cmd.Process != nil {
		killTree(cmd.Process.Pid, syscall.SIGKILL, false)
	}
	if subreaper {
		killTree(os.Getpid(), syscall.SIGKILL, false) // abgelöste Prozesse aus der Sandbox hängen jetzt an sdbx
	}
	code := exitCode(waitErr, cmd)
	if reapStatus != nil {
		if c, ok := reaper.ReadStatus(reapStatus); ok {
			code = c
		} else {
			o.Log.Emit("reaper.killed", map[string]any{"exit": code})
			o.printf("Warnung: Der Aufräumprozess der Sandbox wurde vorzeitig beendet – abgelöste Prozesse aus der Sandbox laufen möglicherweise weiter")
		}
	}
	if timedOut {
		code = ExitTimeout
	}
	o.Log.Emit("run.end", map[string]any{"exit": code, "duration": time.Since(start).Round(time.Millisecond).String()})

	// Nachprüfungen
	if straceLog != "" {
		if f, err := os.Open(straceLog); err == nil {
			audit.ParseStrace(f, o.Log)
			f.Close()
		}
	}
	for _, w := range postChecks(p, o.Log) {
		o.printf("Warnung: %s", w)
	}
	for _, r := range o.Integrations {
		if r.Post != nil {
			for _, w := range r.Post(o.Log) {
				o.printf("Warnung: %s", w)
			}
		}
	}
	if stopLog != nil {
		time.Sleep(300 * time.Millisecond) // letzte Log-Zeilen abwarten
	}
	return code, nil
}

// postChecks meldet geschützte Pfade, die während des Laufs entstanden sind
// (unter Linux nicht verhinderbar, Spec 5.4).
func postChecks(p *policy.Policy, log *audit.Logger) []string {
	var out []string
	for _, r := range p.Rules {
		if (r.Kind != policy.KindProtected && r.Kind != policy.KindReadonly) || r.Exists || r.Glob != "" {
			continue
		}
		if _, err := os.Lstat(r.Path); err == nil {
			log.Emit("protected.created", map[string]any{"path": r.Path, "note": r.Note})
			out = append(out, fmt.Sprintf("geschützter Pfad %s wurde in der Sandbox angelegt – Inhalt prüfen, bevor er außerhalb genutzt wird", r.Path))
		}
	}
	return append(out, newRepoChecks(p, log)...)
}

// newRepoChecks meldet Git-Repositories, die während des Laufs entstanden sind. Ihre geschützten
// Pfade waren beim Start unbekannt; Hooks können auf dem Umweg über Umbenennen entstehen.
func newRepoChecks(p *policy.Policy, log *audit.Logger) []string {
	if p.Workspace == "" {
		return nil
	}
	known := map[string]bool{p.Workspace: true}
	for _, r := range p.Repos {
		known[r] = true
	}
	var out []string
	for _, repo := range policy.FindRepos(p.Workspace) {
		if known[repo] {
			continue
		}
		var found []string
		for _, rel := range policy.ProtectedInRepo {
			if _, err := os.Lstat(filepath.Join(repo, rel)); err == nil && rel != ".git/hooks" {
				found = append(found, rel)
			}
		}
		hooks := activeHooks(repo)
		log.Emit("repo.created", map[string]any{"path": repo, "protected": found, "hooks": hooks})
		msg := fmt.Sprintf("neues Git-Repository %s wurde in der Sandbox angelegt – %s prüfen, bevor dort Git oder andere Werkzeuge außerhalb laufen", repo, strings.Join(found, ", "))
		if len(hooks) > 0 {
			msg += "; aktive Hooks: " + strings.Join(hooks, ", ")
		}
		out = append(out, msg)
	}
	return out
}

// activeHooks liefert die Hooks eines Repositories, die Git ausführen würde (alles außer *.sample).
func activeHooks(repo string) []string {
	ents, _ := os.ReadDir(filepath.Join(repo, ".git", "hooks"))
	var out []string
	for _, e := range ents {
		if !strings.HasSuffix(e.Name(), ".sample") {
			out = append(out, e.Name())
		}
	}
	return out
}

func exitCode(err error, cmd *exec.Cmd) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok {
			if ws.Signaled() {
				return 128 + int(ws.Signal())
			}
			return ws.ExitStatus()
		}
		return ee.ExitCode()
	}
	return ExitSetup
}

// LookPath sucht name wie die Shell in pathEnv; Namen mit "/" gelten relativ zu cwd.
func LookPath(name, pathEnv, cwd string) (string, error) {
	if strings.Contains(name, "/") {
		p := name
		if !filepath.IsAbs(p) {
			p = filepath.Join(cwd, p)
		}
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
		return "", fmt.Errorf("nicht gefunden")
	}
	for _, d := range filepath.SplitList(pathEnv) {
		if d == "" {
			d = "."
		}
		p := filepath.Join(d, name)
		if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("nicht gefunden")
}

// cgroupWrap legt systemd-run --user --scope um den Start. systemd-run findet den Nutzer-Bus über
// XDG_RUNTIME_DIR, das die gefilterte Sandbox-Umgebung nicht enthält; env -u nimmt es dem Befehl wieder.
func cgroupWrap(systemdRun, envBin string, l policy.Limits, args, env []string, uid int) ([]string, []string) {
	pre := []string{systemdRun, "--user", "--scope", "--quiet", "--collect"}
	if l.MaxMemory > 0 {
		pre = append(pre, "-p", fmt.Sprintf("MemoryMax=%d", l.MaxMemory), "-p", "MemorySwapMax=0")
	}
	if l.MaxProcesses > 0 {
		pre = append(pre, "-p", fmt.Sprintf("TasksMax=%d", l.MaxProcesses))
	}
	pre = append(pre, "--")
	if _, ok := envfilter.Lookup(env, "XDG_RUNTIME_DIR"); !ok && envBin != "" {
		pre = append(pre, envBin, "-u", "XDG_RUNTIME_DIR")
		env = append(append([]string(nil), env...), fmt.Sprintf("XDG_RUNTIME_DIR=/run/user/%d", uid))
	}
	return append(pre, args...), env
}

func shellQuote(args []string) string {
	var out []string
	for _, a := range args {
		if a == "" || strings.ContainsAny(a, " \t\n'\"\\$`!*?[]{}();<>|&~#") {
			a = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		}
		out = append(out, a)
	}
	return strings.Join(out, " ")
}
