//go:build linux

package linux

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// RunInit läuft als "sdbx __init <spec>" innerhalb von bwrap: Limits, Landlock,
// seccomp und Bridge einrichten, dann den Zielbefehl per exec starten.
// Der Aufrufer muss den Haupt-Thread gesperrt haben (runtime.LockOSThread).
func RunInit(specPath string) error {
	data, err := os.ReadFile(specPath)
	if err != nil {
		return fmt.Errorf("Spezifikation nicht lesbar: %w", err)
	}
	var spec InitSpec
	if err := json.Unmarshal(data, &spec); err != nil {
		return fmt.Errorf("Spezifikation fehlerhaft: %w", err)
	}
	if len(spec.Argv) == 0 {
		return fmt.Errorf("kein Befehl")
	}
	for _, r := range spec.Rlimits {
		lim := syscall.Rlimit{Cur: r.Value, Max: r.Value}
		if err := syscall.Setrlimit(r.Resource, &lim); err != nil {
			return fmt.Errorf("Limit %s: %w", r.Name, err)
		}
	}
	if spec.NoNewPrivs {
		if err := NoNewPrivs(); err != nil {
			return fmt.Errorf("no_new_privs: %w", err)
		}
	}
	if spec.Landlock != nil {
		abi, err := ApplyLandlock(spec.Landlock)
		if err != nil {
			if spec.Landlock.Mode == "required" {
				return fmt.Errorf("Landlock: %w", err)
			}
			fmt.Fprintf(os.Stderr, "sdbx: Warnung: Landlock nicht angewandt: %v\n", err)
		} else if abi == 0 && spec.Landlock.Mode == "required" {
			return fmt.Errorf("Landlock ist erforderlich, aber im Kernel nicht verfügbar")
		}
	}
	if spec.Seccomp != nil {
		if err := InstallSeccomp(spec.Seccomp); err != nil {
			return err
		}
	}
	if len(spec.Bridges) > 0 {
		cmd := exec.Command(spec.BridgeExe, append([]string{"__bridge"}, spec.Bridges...)...)
		cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
		cmd.Stdout, cmd.Stderr = nil, os.Stderr
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("Bridge: %w", err)
		}
		if err := waitBridge(spec.Bridges); err != nil {
			return err
		}
	}
	path, err := exec.LookPath(spec.Argv[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "sdbx: Befehl nicht gefunden: %s\n", spec.Argv[0])
		os.Exit(127)
	}
	if err := syscall.Exec(path, spec.Argv, os.Environ()); err != nil {
		if err == syscall.EACCES {
			fmt.Fprintf(os.Stderr, "sdbx: %s darf in der Sandbox nicht ausgeführt werden (%v)\n", path, err)
			os.Exit(126)
		}
		return fmt.Errorf("exec %s: %w", path, err)
	}
	return nil
}
