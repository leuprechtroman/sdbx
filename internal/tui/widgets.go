package tui

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Fehler für Navigation.
var (
	ErrBack   = errors.New("zurück")
	ErrCancel = errors.New("abgebrochen")
)

// Option ist ein Auswahlpunkt.
type Option struct {
	Label string
	Desc  string
}

// UI rendert Formulare auf einem Terminal oder zeilenweise (barrierearm).
type UI struct {
	In         *bufio.Reader
	Out        io.Writer
	Accessible bool
	Width      int
	lines      int
}

// New erzeugt eine UI.
func New(in io.Reader, out io.Writer, accessible bool) *UI {
	return &UI{In: bufio.NewReader(in), Out: out, Accessible: accessible, Width: 80}
}

// Key ist ein Tastendruck.
type Key struct {
	Type int
	Rune rune
}

// Tastentypen.
const (
	KRune = iota
	KUp
	KDown
	KLeft
	KRight
	KEnter
	KSpace
	KTab
	KBackspace
	KEsc
	KCtrlC
	KOther
)

// ReadKey liest einen Tastendruck im Raw-Modus.
func (u *UI) ReadKey() (Key, error) {
	b, err := u.In.ReadByte()
	if err != nil {
		return Key{}, err
	}
	switch b {
	case 3:
		return Key{Type: KCtrlC}, nil
	case '\r', '\n':
		return Key{Type: KEnter}, nil
	case ' ':
		return Key{Type: KSpace, Rune: ' '}, nil
	case '\t':
		return Key{Type: KTab}, nil
	case 127, 8:
		return Key{Type: KBackspace}, nil
	case 27:
		if u.In.Buffered() == 0 {
			return Key{Type: KEsc}, nil
		}
		b2, _ := u.In.ReadByte()
		if b2 != '[' && b2 != 'O' {
			u.In.UnreadByte() // nächste Taste nicht verschlucken
			return Key{Type: KEsc}, nil
		}
		b3, _ := u.In.ReadByte()
		switch b3 {
		case 'A':
			return Key{Type: KUp}, nil
		case 'B':
			return Key{Type: KDown}, nil
		case 'C':
			return Key{Type: KRight}, nil
		case 'D':
			return Key{Type: KLeft}, nil
		}
		for b3 >= '0' && b3 <= '9' || b3 == ';' { // z. B. ESC [ 3 ~
			b3, _ = u.In.ReadByte()
		}
		return Key{Type: KOther}, nil
	}
	if b < 0x80 {
		return Key{Type: KRune, Rune: rune(b)}, nil
	}
	u.In.UnreadByte()
	r, _, err := u.In.ReadRune()
	return Key{Type: KRune, Rune: r}, err
}

const (
	bold  = "\x1b[1m"
	dim   = "\x1b[2m"
	cyan  = "\x1b[36m"
	red   = "\x1b[31m"
	reset = "\x1b[0m"
)

// render zeichnet den Block neu (überschreibt den vorherigen).
func (u *UI) render(lines []string) {
	var b strings.Builder
	if u.lines > 0 {
		fmt.Fprintf(&b, "\x1b[%dA\r\x1b[J", u.lines)
	}
	for _, l := range lines {
		b.WriteString(l)
		b.WriteString("\r\n")
	}
	io.WriteString(u.Out, b.String())
	u.lines = len(lines)
}

// Done beendet einen Block, damit der nächste darunter beginnt.
func (u *UI) Done(summary string) {
	if u.Accessible {
		return
	}
	if summary != "" {
		u.render([]string{summary})
	}
	u.lines = 0
}

func header(title, help string) []string {
	out := []string{bold + title + reset}
	if help != "" {
		for _, l := range strings.Split(help, "\n") {
			out = append(out, dim+l+reset)
		}
	}
	return out
}

func footer(s string) string { return dim + s + reset }

// Select bietet eine Einfachauswahl.
func (u *UI) Select(title, help string, opts []Option, def int) (int, error) {
	if u.Accessible {
		return u.lineSelect(title, help, opts, def)
	}
	cur := def
	for {
		lines := header(title, help)
		for i, o := range opts {
			mark, style := "  ", ""
			if i == cur {
				mark, style = cyan+"› ", bold
			}
			l := mark + style + o.Label + reset
			if o.Desc != "" {
				l += dim + " – " + o.Desc + reset
			}
			lines = append(lines, l)
		}
		lines = append(lines, footer("↑/↓ wählen · Enter bestätigen · Esc zurück · Ctrl-C abbrechen"))
		u.render(lines)
		k, err := u.ReadKey()
		if err != nil {
			return 0, ErrCancel
		}
		switch k.Type {
		case KUp:
			cur = (cur - 1 + len(opts)) % len(opts)
		case KDown, KTab:
			cur = (cur + 1) % len(opts)
		case KEnter:
			u.Done(fmt.Sprintf("%s %s✓ %s%s", title, cyan, opts[cur].Label, reset))
			return cur, nil
		case KEsc:
			return 0, ErrBack
		case KCtrlC:
			return 0, ErrCancel
		case KRune:
			if n, err := strconv.Atoi(string(k.Rune)); err == nil && n >= 1 && n <= len(opts) {
				cur = n - 1
			}
		}
	}
}

// MultiSelect bietet eine Mehrfachauswahl.
func (u *UI) MultiSelect(title, help string, opts []Option, sel []bool) ([]bool, error) {
	sel = append([]bool(nil), sel...)
	for len(sel) < len(opts) {
		sel = append(sel, false)
	}
	if u.Accessible {
		return u.lineMulti(title, help, opts, sel)
	}
	cur := 0
	for {
		lines := header(title, help)
		for i, o := range opts {
			box := "[ ]"
			if sel[i] {
				box = cyan + "[x]" + reset
			}
			mark := "  "
			if i == cur {
				mark = cyan + "› " + reset
			}
			l := mark + box + " " + o.Label
			if o.Desc != "" {
				l += dim + " – " + o.Desc + reset
			}
			lines = append(lines, l)
		}
		lines = append(lines, footer("↑/↓ bewegen · Leertaste auswählen · Enter bestätigen · Esc zurück"))
		u.render(lines)
		k, err := u.ReadKey()
		if err != nil {
			return nil, ErrCancel
		}
		switch k.Type {
		case KUp:
			cur = (cur - 1 + len(opts)) % len(opts)
		case KDown, KTab:
			cur = (cur + 1) % len(opts)
		case KSpace:
			sel[cur] = !sel[cur]
		case KEnter:
			var chosen []string
			for i, s := range sel {
				if s {
					chosen = append(chosen, opts[i].Label)
				}
			}
			if len(chosen) == 0 {
				chosen = []string{"keine"}
			}
			u.Done(fmt.Sprintf("%s %s✓ %s%s", title, cyan, strings.Join(chosen, ", "), reset))
			return sel, nil
		case KEsc:
			return nil, ErrBack
		case KCtrlC:
			return nil, ErrCancel
		}
	}
}

// Input liest eine Zeile mit Validierung.
func (u *UI) Input(title, help, def string, validate func(string) error) (string, error) {
	if u.Accessible {
		return u.lineInput(title, help, def, validate)
	}
	buf := []rune(def)
	msg := ""
	for {
		lines := header(title, help)
		lines = append(lines, cyan+"› "+reset+string(buf)+"█")
		if msg != "" {
			lines = append(lines, red+msg+reset)
		}
		lines = append(lines, footer("Enter bestätigen · Esc zurück"))
		u.render(lines)
		k, err := u.ReadKey()
		if err != nil {
			return "", ErrCancel
		}
		switch k.Type {
		case KRune, KSpace:
			buf = append(buf, k.Rune)
			msg = ""
		case KBackspace:
			if len(buf) > 0 {
				buf = buf[:len(buf)-1]
			}
		case KEnter:
			v := strings.TrimSpace(string(buf))
			if validate != nil {
				if err := validate(v); err != nil {
					msg = err.Error()
					continue
				}
			}
			u.Done(fmt.Sprintf("%s %s✓ %s%s", title, cyan, v, reset))
			return v, nil
		case KEsc:
			return "", ErrBack
		case KCtrlC:
			return "", ErrCancel
		}
	}
}

// ListInput sammelt Einträge, bis eine leere Eingabe bestätigt wird.
func (u *UI) ListInput(title, help string, items []string, validate func(string) error) ([]string, error) {
	items = append([]string(nil), items...)
	if u.Accessible {
		fmt.Fprintf(u.Out, "%s\n", title)
		if help != "" {
			fmt.Fprintf(u.Out, "%s\n", help)
		}
		for {
			fmt.Fprintf(u.Out, "Aktuell: %s\nNeuer Eintrag (leer = fertig, < = zurück, - = letzten entfernen): ", listOrNone(items))
			line, err := u.In.ReadString('\n')
			if err != nil && line == "" {
				return nil, ErrCancel
			}
			line = strings.TrimSpace(line)
			switch line {
			case "":
				return items, nil
			case "<":
				return nil, ErrBack
			case "-":
				if len(items) > 0 {
					items = items[:len(items)-1]
				}
				continue
			}
			if validate != nil {
				if err := validate(line); err != nil {
					fmt.Fprintf(u.Out, "Fehler: %v\n", err)
					continue
				}
			}
			items = append(items, line)
		}
	}
	buf := []rune{}
	msg := ""
	for {
		lines := header(title, help)
		for _, it := range items {
			lines = append(lines, "  • "+it)
		}
		lines = append(lines, cyan+"› "+reset+string(buf)+"█")
		if msg != "" {
			lines = append(lines, red+msg+reset)
		}
		lines = append(lines, footer("Enter hinzufügen · Enter auf leerer Zeile fertig · Backspace auf leerer Zeile entfernt den letzten · Esc zurück"))
		u.render(lines)
		k, err := u.ReadKey()
		if err != nil {
			return nil, ErrCancel
		}
		switch k.Type {
		case KRune, KSpace:
			buf = append(buf, k.Rune)
			msg = ""
		case KBackspace:
			if len(buf) > 0 {
				buf = buf[:len(buf)-1]
			} else if len(items) > 0 {
				items = items[:len(items)-1]
			}
		case KEnter:
			v := strings.TrimSpace(string(buf))
			if v == "" {
				u.Done(fmt.Sprintf("%s %s✓ %s%s", title, cyan, listOrNone(items), reset))
				return items, nil
			}
			if validate != nil {
				if err := validate(v); err != nil {
					msg = err.Error()
					continue
				}
			}
			items = append(items, v)
			buf = buf[:0]
		case KEsc:
			return nil, ErrBack
		case KCtrlC:
			return nil, ErrCancel
		}
	}
}

func listOrNone(items []string) string {
	if len(items) == 0 {
		return "keine"
	}
	return strings.Join(items, ", ")
}

// Preview zeigt Text und bietet Aktionen an.
func (u *UI) Preview(title, text string, actions []Option, def int) (int, error) {
	if u.Accessible {
		fmt.Fprintf(u.Out, "%s\n%s\n", title, text)
		return u.lineSelect("Aktion", "", actions, def)
	}
	io.WriteString(u.Out, bold+title+reset+"\r\n")
	for _, l := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		io.WriteString(u.Out, "  "+l+"\r\n")
	}
	u.lines = 0
	return u.Select("Aktion", "", actions, def)
}

// Note gibt einen Hinweis aus.
func (u *UI) Note(s string) {
	if u.Accessible {
		fmt.Fprintln(u.Out, s)
		return
	}
	io.WriteString(u.Out, strings.ReplaceAll(s, "\n", "\r\n")+"\r\n")
}

func (u *UI) readLine() (string, error) {
	line, err := u.In.ReadString('\n')
	if err != nil && line == "" {
		return "", ErrCancel
	}
	return strings.TrimSpace(line), nil
}

func (u *UI) lineSelect(title, help string, opts []Option, def int) (int, error) {
	for {
		fmt.Fprintf(u.Out, "%s\n", title)
		if help != "" {
			fmt.Fprintf(u.Out, "%s\n", help)
		}
		for i, o := range opts {
			d := ""
			if o.Desc != "" {
				d = " – " + o.Desc
			}
			fmt.Fprintf(u.Out, "  %d) %s%s\n", i+1, o.Label, d)
		}
		fmt.Fprintf(u.Out, "Auswahl [%d] (< zurück, q abbrechen): ", def+1)
		line, err := u.readLine()
		if err != nil {
			return 0, err
		}
		switch line {
		case "":
			return def, nil
		case "<":
			return 0, ErrBack
		case "q":
			return 0, ErrCancel
		}
		if n, err := strconv.Atoi(line); err == nil && n >= 1 && n <= len(opts) {
			return n - 1, nil
		}
		fmt.Fprintln(u.Out, "Ungültige Auswahl.")
	}
}

func (u *UI) lineMulti(title, help string, opts []Option, sel []bool) ([]bool, error) {
	for {
		fmt.Fprintf(u.Out, "%s\n", title)
		if help != "" {
			fmt.Fprintf(u.Out, "%s\n", help)
		}
		var def []string
		for i, o := range opts {
			x := " "
			if sel[i] {
				x = "x"
				def = append(def, strconv.Itoa(i+1))
			}
			fmt.Fprintf(u.Out, "  %d) [%s] %s\n", i+1, x, o.Label)
		}
		fmt.Fprintf(u.Out, "Nummern durch Komma, 0 = keine [%s] (< zurück, q abbrechen): ", strings.Join(def, ","))
		line, err := u.readLine()
		if err != nil {
			return nil, err
		}
		switch line {
		case "":
			return sel, nil
		case "<":
			return nil, ErrBack
		case "q":
			return nil, ErrCancel
		case "0":
			return make([]bool, len(opts)), nil
		}
		out := make([]bool, len(opts))
		ok := true
		for _, f := range strings.Split(line, ",") {
			n, err := strconv.Atoi(strings.TrimSpace(f))
			if err != nil || n < 1 || n > len(opts) {
				ok = false
				break
			}
			out[n-1] = true
		}
		if ok {
			return out, nil
		}
		fmt.Fprintln(u.Out, "Ungültige Auswahl.")
	}
}

func (u *UI) lineInput(title, help, def string, validate func(string) error) (string, error) {
	for {
		fmt.Fprintf(u.Out, "%s\n", title)
		if help != "" {
			fmt.Fprintf(u.Out, "%s\n", help)
		}
		fmt.Fprintf(u.Out, "[%s] (< zurück): ", def)
		line, err := u.readLine()
		if err != nil {
			return "", err
		}
		if line == "<" {
			return "", ErrBack
		}
		if line == "" {
			line = def
		}
		if validate != nil {
			if err := validate(line); err != nil {
				fmt.Fprintf(u.Out, "Fehler: %v\n", err)
				continue
			}
		}
		return line, nil
	}
}

// VisibleLen liefert die sichtbare Länge (ohne ANSI-Sequenzen).
func VisibleLen(s string) int {
	n := 0
	inEsc := false
	for _, r := range s {
		switch {
		case r == 0x1b:
			inEsc = true
		case inEsc && (r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z'):
			inEsc = false
		case !inEsc:
			n++
		}
	}
	return n
}
