// Package audit protokolliert Entscheidungen und Verstöße (Spec 9).
package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"
)

// Event ist ein Audit-Ereignis.
type Event struct {
	TS     time.Time      `json:"ts"`
	Run    string         `json:"run"`
	Type   string         `json:"type"`
	Fields map[string]any `json:"-"`
}

// MarshalJSON schreibt Felder flach neben ts/run/type.
func (e Event) MarshalJSON() ([]byte, error) {
	m := map[string]any{"ts": e.TS.UTC().Format(time.RFC3339Nano), "run": e.Run, "type": e.Type}
	for k, v := range e.Fields {
		m[k] = v
	}
	return json.Marshal(m)
}

// Logger sammelt Ereignisse.
type Logger struct {
	mu      sync.Mutex
	run     string
	out     io.Writer
	format  string
	live    io.Writer // optionale Live-Ausgabe (verbose)
	events  []Event
	counts  map[string]int
	denied  map[string]int // Ziel → Anzahl
	keepAll bool
	now     func() time.Time
}

// New erzeugt einen Logger. out darf nil sein.
func New(run string, out io.Writer, format string) *Logger {
	return &Logger{run: run, out: out, format: format, counts: map[string]int{}, denied: map[string]int{}, keepAll: true, now: time.Now}
}

// SetLive aktiviert die Live-Ausgabe auf w.
func (l *Logger) SetLive(w io.Writer) { l.live = w }

// Run liefert die Lauf-ID.
func (l *Logger) Run() string { return l.run }

// Emit protokolliert ein Ereignis.
func (l *Logger) Emit(typ string, fields map[string]any) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	e := Event{TS: l.now(), Run: l.run, Type: typ, Fields: fields}
	if l.keepAll {
		l.events = append(l.events, e)
	}
	l.counts[typ]++
	if strings.HasSuffix(typ, ".deny") || typ == "net.learn" {
		key := denyKey(typ, fields)
		if key != "" {
			l.denied[key]++
		}
	}
	if l.out != nil {
		l.write(l.out, e, l.format)
	}
	if l.live != nil {
		l.write(l.live, e, "text")
	}
}

func denyKey(typ string, f map[string]any) string {
	switch {
	case strings.HasPrefix(typ, "net."):
		return fmt.Sprintf("net %v:%v", f["host"], f["port"])
	case typ == "fs.deny":
		return fmt.Sprintf("fs %v %v", f["op"], f["path"])
	case typ == "socket.deny":
		return fmt.Sprintf("socket %v", f["path"])
	case typ == "mach.deny":
		return fmt.Sprintf("mach %v", f["service"])
	}
	return ""
}

func (l *Logger) write(w io.Writer, e Event, format string) {
	if format == "json" {
		b, _ := json.Marshal(e)
		fmt.Fprintf(w, "%s\n", b)
		return
	}
	fmt.Fprintf(w, "%s %s %s\n", e.TS.Format("15:04:05.000"), e.Type, FormatFields(e.Fields))
}

// FormatFields formatiert Felder sortiert als key=value.
func FormatFields(f map[string]any) string {
	keys := make([]string, 0, len(f))
	for k := range f {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%v", k, f[k]))
	}
	return strings.Join(parts, " ")
}

// Events liefert eine Kopie aller Ereignisse.
func (l *Logger) Events() []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]Event(nil), l.events...)
}

// Count liefert die Anzahl eines Ereignistyps.
func (l *Logger) Count(typ string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.counts[typ]
}

// Summary schreibt eine Kurzfassung (Spec 9: audit.summary).
func (l *Logger) Summary(w io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.denied) == 0 {
		return
	}
	keys := make([]string, 0, len(l.denied))
	for k := range l.denied {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Fprintf(w, "sdbx: %d blockierte Zugriffe in diesem Lauf:\n", len(keys))
	for i, k := range keys {
		if i == 20 {
			fmt.Fprintf(w, "  … und %d weitere (vollständig im Audit-Log)\n", len(keys)-20)
			break
		}
		fmt.Fprintf(w, "  %s (%d×)\n", k, l.denied[k])
	}
}
