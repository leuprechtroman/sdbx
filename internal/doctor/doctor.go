// Package doctor prüft Plattformvoraussetzungen (Spec 10.2).
package doctor

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"sdbx/internal/backend/linux"
	"sdbx/internal/integrations/clausona"
)

// Options für doctor.
type Options struct {
	Platform string
	Home     string
	UID      int
}

// Check ist ein Prüfergebnis.
type Check struct {
	Level string // ok | warn | fail
	Name  string
	Msg   string
	Fix   string
}

func run(timeout time.Duration, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	done := make(chan struct{})
	var out []byte
	var err error
	go func() { out, err = cmd.CombinedOutput(); close(done) }()
	select {
	case <-done:
		return strings.TrimSpace(string(out)), err
	case <-time.After(timeout):
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		return "", fmt.Errorf("Zeitüberschreitung")
	}
}

func readInt(path string) (int, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(b)))
	return v, err == nil
}

// Checks führt alle Prüfungen aus.
func Checks(o Options) []Check {
	var cs []Check
	add := func(level, name, msg, fix string) { cs = append(cs, Check{level, name, msg, fix}) }
	switch o.Platform {
	case "linux":
		if bw, err := exec.LookPath("bwrap"); err != nil {
			add("fail", "bubblewrap", "bwrap nicht gefunden", "Paket bubblewrap installieren (apt install bubblewrap, dnf install bubblewrap)")
		} else {
			v, _ := run(5*time.Second, bw, "--version")
			add("ok", "bubblewrap", v+" ("+bw+")", "")
			if out, err := run(10*time.Second, bw, "--ro-bind", "/", "/", "--dev", "/dev", "--unshare-user-try", "--unshare-net", "--unshare-pid", "--proc", "/proc", "--", "true"); err != nil {
				fix := "User Namespaces prüfen (siehe unten) oder linux.backend: landlock mit --degraded verwenden"
				add("fail", "bwrap-Probelauf", strings.TrimSpace(out+" "+err.Error()), fix)
			} else {
				add("ok", "bwrap-Probelauf", "Namespaces funktionieren", "")
			}
		}
		if v, ok := readInt("/proc/sys/kernel/unprivileged_userns_clone"); ok && v == 0 {
			add("fail", "User Namespaces", "kernel.unprivileged_userns_clone = 0", "sysctl -w kernel.unprivileged_userns_clone=1")
		}
		if v, ok := readInt("/proc/sys/user/max_user_namespaces"); ok && v == 0 {
			add("fail", "User Namespaces", "user.max_user_namespaces = 0", "sysctl -w user.max_user_namespaces=15000")
		}
		if v, ok := readInt("/proc/sys/kernel/apparmor_restrict_unprivileged_userns"); ok && v == 1 {
			add("warn", "AppArmor", "kernel.apparmor_restrict_unprivileged_userns = 1 (Ubuntu ab 24.04)",
				"ein AppArmor-Profil für bwrap aktivieren (Distributionsdokumentation) oder linux.backend: landlock mit --degraded")
		}
		if abi := linux.LandlockABI(); abi == 0 {
			add("warn", "Landlock", "nicht verfügbar – bwrap allein setzt die Policy durch", "Kernel ≥ 5.13 mit lsm=…,landlock")
		} else {
			msg := fmt.Sprintf("ABI %d", abi)
			if abi < 4 {
				msg += " (Netzwerkregeln erst ab ABI 4, nur für linux.backend: landlock relevant)"
			}
			add("ok", "Landlock", msg, "")
		}
		if _, err := exec.LookPath("systemd-run"); err == nil {
			if _, err := os.Stat(fmt.Sprintf("/run/user/%d/bus", o.UID)); err == nil {
				add("ok", "cgroup v2", "systemd-run --user verfügbar (max_memory, max_processes)", "")
			} else {
				add("warn", "cgroup v2", "kein Nutzer-Bus – max_memory nicht durchsetzbar", "in einer systemd-Benutzersitzung starten")
			}
		} else {
			add("warn", "cgroup v2", "systemd-run fehlt – max_memory nicht durchsetzbar", "")
		}
		if _, err := exec.LookPath("strace"); err != nil {
			add("warn", "strace", "fehlt – Lernmodus erfasst keine Dateisystem-Verstöße", "apt install strace")
		} else {
			add("ok", "strace", "vorhanden (Lernmodus)", "")
		}
	case "darwin":
		if _, err := os.Stat("/usr/bin/sandbox-exec"); err != nil {
			add("fail", "sandbox-exec", "/usr/bin/sandbox-exec fehlt", "")
		} else if out, err := run(10*time.Second, "/usr/bin/sandbox-exec", "-p", "(version 1)(allow default)(deny file-ioctl (ioctl-command TIOCSTI))", "/usr/bin/true"); err != nil {
			add("fail", "sandbox-exec", "Probelauf fehlgeschlagen: "+out, "")
		} else {
			add("ok", "sandbox-exec", "Seatbelt funktioniert (inkl. ioctl-Filter)", "")
		}
		if v, err := run(5*time.Second, "sw_vers", "-productVersion"); err == nil {
			add("ok", "macOS", v, "")
		}
	default:
		add("fail", "Plattform", o.Platform+" wird nicht unterstützt", "")
	}
	if v, err := run(5*time.Second, "node", "--version"); err == nil {
		m := regexp.MustCompile(`v(\d+)\.(\d+)`).FindStringSubmatch(v)
		if len(m) == 3 {
			major, _ := strconv.Atoi(m[1])
			minor, _ := strconv.Atoi(m[2])
			if major >= 24 || (major == 22 && minor >= 21) {
				add("ok", "Node.js", v+" (NODE_USE_ENV_PROXY unterstützt)", "")
			} else {
				add("warn", "Node.js", v+" ignoriert die Proxy-Variablen für fetch()", "Node 24 (bzw. späte 22er-Version) verwenden")
			}
		}
	}
	if clausona.Detect(o.Home) {
		if r, err := clausona.LoadRegistry(o.Home); err != nil {
			add("warn", "clausona", err.Error(), "")
		} else {
			add("ok", "clausona", fmt.Sprintf("Registry v%d, %d Profile", r.Version, len(r.Profiles)), "")
		}
	}
	if st, err := os.Stat(filepath.Join(o.Home, ".sdbx")); err == nil && st.IsDir() {
		add("warn", "Altlast", "~/.sdbx stammt von einem früheren Prototyp und wird nicht mehr verwendet", "rm -rf ~/.sdbx")
	}
	return cs
}

// Run gibt die Prüfungen aus; Exit 1 bei Fehlern.
func Run(w io.Writer, o Options) int {
	code := 0
	sym := map[string]string{"ok": "✓", "warn": "!", "fail": "✗"}
	for _, c := range Checks(o) {
		fmt.Fprintf(w, "%s %-18s %s\n", sym[c.Level], c.Name, c.Msg)
		if c.Fix != "" {
			fmt.Fprintf(w, "  → %s\n", c.Fix)
		}
		if c.Level == "fail" {
			code = 1
		}
	}
	return code
}
