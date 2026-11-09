package supervisor

import "syscall"

const prSetChildSubreaper = 36

// becomeSubreaper lässt verwaiste Nachfahren (setsid, Doppel-Fork) bei sdbx statt bei init landen,
// damit das Aufräumen sie auch ohne PID-Namespace findet.
func becomeSubreaper() bool {
	_, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, prSetChildSubreaper, 1, 0)
	return errno == 0
}
