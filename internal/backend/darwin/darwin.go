package darwin

import (
	"fmt"
	"os"
	"path/filepath"

	"sdbx/internal/backend"
	"sdbx/internal/policy"
)

// SandboxExec ist der Pfad von sandbox-exec.
const SandboxExec = "/usr/bin/sandbox-exec"

// Prepare erzeugt Profil und Startbeschreibung.
func Prepare(p *policy.Policy, rt *backend.Runtime) (*backend.Launch, error) {
	prof, err := Generate(p, rt)
	if err != nil {
		return nil, err
	}
	pf := filepath.Join(rt.RunDir, "profile.sb")
	if err := os.WriteFile(pf, []byte(prof.Text), 0o600); err != nil {
		return nil, err
	}
	if len(rt.Argv) == 0 {
		return nil, fmt.Errorf("kein Befehl angegeben")
	}
	args := []string{SandboxExec, "-f", pf}
	args = append(args, prof.Args()...)
	reap := rt.SdbxExe != ""
	if reap {
		args = append(args, rt.SdbxExe, "__reap", "--")
	}
	args = append(args, rt.Argv...)
	return &backend.Launch{Path: SandboxExec, Args: args, Env: rt.Env, Dir: rt.Cwd, Reaper: reap}, nil
}
