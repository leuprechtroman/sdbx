// Package tui enthält Terminal-Grundlagen und eine kleine Formular-TUI für sdbx init.
package tui

import (
	"syscall"
	"unsafe"
)

// State ist der gesicherte Terminalzustand.
type State struct{ t syscall.Termios }

func getTermios(fd int) (*syscall.Termios, error) {
	var t syscall.Termios
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), ioctlGet, uintptr(unsafe.Pointer(&t))); e != 0 {
		return nil, e
	}
	return &t, nil
}

func setTermios(fd int, t *syscall.Termios) error {
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), ioctlSet, uintptr(unsafe.Pointer(t))); e != 0 {
		return e
	}
	return nil
}

// IsTerminal meldet, ob fd ein Terminal ist.
func IsTerminal(fd int) bool {
	_, err := getTermios(fd)
	return err == nil
}

// MakeRaw schaltet das Terminal in den Raw-Modus.
func MakeRaw(fd int) (*State, error) {
	t, err := getTermios(fd)
	if err != nil {
		return nil, err
	}
	old := *t
	t.Iflag &^= syscall.IGNBRK | syscall.BRKINT | syscall.PARMRK | syscall.ISTRIP | syscall.INLCR | syscall.IGNCR | syscall.ICRNL | syscall.IXON
	t.Oflag &^= syscall.OPOST
	t.Lflag &^= syscall.ECHO | syscall.ECHONL | syscall.ICANON | syscall.ISIG | syscall.IEXTEN
	t.Cflag &^= syscall.CSIZE | syscall.PARENB
	t.Cflag |= syscall.CS8
	t.Cc[syscall.VMIN] = 1
	t.Cc[syscall.VTIME] = 0
	if err := setTermios(fd, t); err != nil {
		return nil, err
	}
	return &State{t: old}, nil
}

// Restore stellt den gesicherten Zustand wieder her.
func Restore(fd int, s *State) error {
	if s == nil {
		return nil
	}
	return setTermios(fd, &s.t)
}

type winsize struct{ Row, Col, X, Y uint16 }

// Size liefert die Terminalgröße (Spalten, Zeilen).
func Size(fd int) (int, int) {
	var ws winsize
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.TIOCGWINSZ, uintptr(unsafe.Pointer(&ws))); e != 0 || ws.Col == 0 {
		return 80, 24
	}
	return int(ws.Col), int(ws.Row)
}
