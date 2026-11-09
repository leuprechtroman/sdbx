// Package reaper startet unter macOS den Zielprozess innerhalb der Sandbox und beendet nach
// dessen Ende alle übrigen Prozesse derselben Sandbox (Spec 5.7).
//
// Seatbelt erlaubt Signale nur innerhalb derselben Sandbox ((allow signal (target same-sandbox))).
// kill(-1) aus der Sandbox trifft daher genau die Prozesse dieses Laufs, auch solche, die sich
// mit nohup, & oder setsid vom Prozessbaum gelöst haben und für den Supervisor unsichtbar sind.
package reaper

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// StatusFD ist der Deskriptor, über den der Aufräumer den Exit-Code an den Supervisor meldet.
// kill(-1) trifft unter Seatbelt auch den Aufräumer selbst, sein eigener Exit-Status ist daher immer SIGKILL.
const StatusFD = 3

// Run führt argv aus, meldet den Exit-Code (128+n bei Signal n) über StatusFD und räumt danach auf.
func Run(argv []string) int {
	status := statusPipe()
	// Der Supervisor schickt Signale direkt an das Kind, das Terminal erreicht es über die
	// gemeinsame Prozessgruppe. Hier nur abfangen, damit der Aufräumer bis zum Ende lebt.
	sigs := make(chan os.Signal, 8)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGWINCH, syscall.SIGUSR1, syscall.SIGUSR2)
	go func() {
		for range sigs {
		}
	}()
	code := run(argv)
	if status != nil {
		fmt.Fprintf(status, "%d\n", code)
		status.Close()
	}
	if sandboxed() {
		killAll()
	} else {
		fmt.Fprintln(os.Stderr, "sdbx: __reap läuft nicht in einer Sandbox – kein Aufräumen")
	}
	return code
}

func run(argv []string) int {
	if len(argv) == 0 {
		fmt.Fprintln(os.Stderr, "sdbx: __reap erwartet einen Befehl")
		return 126
	}
	path, err := exec.LookPath(argv[0])
	if err != nil && !errors.Is(err, exec.ErrDot) {
		fmt.Fprintf(os.Stderr, "sdbx: %s: %v\n", argv[0], err)
		return 127
	}
	cmd := &exec.Cmd{Path: path, Args: argv, Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr}
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "sdbx: %s: %v\n", argv[0], err)
		return 126
	}
	cmd.Wait()
	ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if !ok {
		return cmd.ProcessState.ExitCode()
	}
	if ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return ws.ExitStatus()
}

// statusPipe liefert StatusFD, wenn dort eine Pipe liegt, und schützt sie vor Vererbung an den Befehl.
// Ohne Pipe kann fd 3 ein Deskriptor der Go-Laufzeit sein und darf nicht angefasst werden.
func statusPipe() *os.File {
	var st syscall.Stat_t
	if syscall.Fstat(StatusFD, &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFIFO {
		return nil
	}
	syscall.CloseOnExec(StatusFD)
	return os.NewFile(StatusFD, "status")
}

// ReadStatus liest den gemeldeten Exit-Code; ok ist false, wenn der Aufräumer keinen gemeldet hat.
func ReadStatus(r io.Reader) (code int, ok bool) {
	b, _ := io.ReadAll(r)
	code, err := strconv.Atoi(strings.TrimSpace(string(b)))
	return code, err == nil
}

// sandboxed meldet, ob Signale an den Elternprozess (den Supervisor außerhalb der Sandbox)
// verweigert werden. Nur dann ist kill(-1) auf die eigene Sandbox beschränkt; ohne Sandbox
// träfe es alle Prozesse des Nutzers.
func sandboxed() bool {
	pp := os.Getppid()
	return pp > 1 && syscall.Kill(pp, 0) == syscall.EPERM
}

// killAll beendet alle Prozesse, die der Aufräumer signalisieren darf. Wiederholt, weil Prozesse
// während des Durchlaufs noch forken können; kill(-1) meldet ESRCH, sobald keiner mehr übrig ist.
func killAll() {
	for i := 0; i < 50; i++ {
		if syscall.Kill(-1, syscall.SIGKILL) != nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}
