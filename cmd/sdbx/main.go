// Command sdbx führt Befehle in einer Sandbox auf Betriebssystemebene aus.
package main

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"sdbx/internal/backend/linux"
	"sdbx/internal/bridge"
	"sdbx/internal/cli"
	"sdbx/internal/reaper"
)

func init() {
	// __init muss alle Einschränkungen auf dem Thread anwenden, der danach exec ausführt.
	if len(os.Args) > 1 && os.Args[1] == "__init" {
		runtime.LockOSThread()
	}
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "__init":
			if len(os.Args) != 3 {
				fatal(126, "__init erwartet eine Spezifikation")
			}
			if err := linux.RunInit(os.Args[2]); err != nil {
				fatal(126, err.Error())
			}
			return
		case "__reap":
			if len(os.Args) < 4 || os.Args[2] != "--" {
				fatal(126, "__reap -- <befehl> [args…]")
			}
			os.Exit(reaper.Run(os.Args[3:]))
		case "__bridge":
			// Liegt in der Prozessgruppe des Befehls: Ctrl-C oder weitergeleitetes SIGTERM dürfen dem Befehl
			// nicht das Netz nehmen. Die Bridge endet per Pdeathsig mit dem Befehl.
			signal.Ignore(syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
			var pairs []bridge.Pair
			for _, a := range os.Args[2:] {
				p, err := bridge.ParsePair(a)
				if err != nil {
					fatal(126, err.Error())
				}
				pairs = append(pairs, p)
			}
			if err := bridge.Run(pairs); err != nil {
				fatal(126, "Bridge: "+err.Error())
			}
			return
		case "__connect":
			if len(os.Args) != 4 {
				fatal(2, "__connect <host> <port>")
			}
			if err := bridge.Connect(os.Args[2], os.Args[3], os.Stdin, os.Stdout); err != nil {
				fatal(1, err.Error())
			}
			return
		}
	}
	os.Exit(cli.Main(os.Args[1:], cli.HostEnv(), cli.IO{In: os.Stdin, Out: os.Stdout, Err: os.Stderr}))
}

func fatal(code int, msg string) {
	fmt.Fprintf(os.Stderr, "sdbx: %s\n", msg)
	os.Exit(code)
}
