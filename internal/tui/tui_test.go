package tui

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func keys(s string) *UI {
	return New(strings.NewReader(s), &bytes.Buffer{}, false)
}

const (
	up    = "\x1b[A"
	down  = "\x1b[B"
	enter = "\r"
	esc   = "\x1b"
)

func TestSelect(t *testing.T) {
	opts := []Option{{Label: "a"}, {Label: "b"}, {Label: "c"}}
	if i, err := keys(down+down+enter).Select("T", "", opts, 0); err != nil || i != 2 {
		t.Errorf("down down: %d %v", i, err)
	}
	if i, _ := keys(up+enter).Select("T", "", opts, 0); i != 2 {
		t.Errorf("Umlauf nach oben: %d", i)
	}
	if i, _ := keys("2"+enter).Select("T", "", opts, 0); i != 1 {
		t.Errorf("Zifferntaste: %d", i)
	}
	u := keys(esc + down + enter)
	if _, err := u.Select("T", "", opts, 0); !errors.Is(err, ErrBack) {
		t.Errorf("Esc vor Pfeiltaste: %v", err)
	}
	if i, _ := u.Select("T", "", opts, 0); i != 1 {
		t.Errorf("Pfeiltaste nach Esc verschluckt: %d", i)
	}
	if _, err := keys(esc).Select("T", "", opts, 0); !errors.Is(err, ErrBack) {
		t.Errorf("Esc: %v", err)
	}
	if _, err := keys("\x03").Select("T", "", opts, 0); !errors.Is(err, ErrCancel) {
		t.Errorf("Ctrl-C: %v", err)
	}
	if _, err := keys("").Select("T", "", opts, 0); !errors.Is(err, ErrCancel) {
		t.Errorf("EOF: %v", err)
	}
}

func TestMultiSelect(t *testing.T) {
	opts := []Option{{Label: "a"}, {Label: "b"}, {Label: "c"}}
	sel, err := keys(" "+down+down+" "+enter).MultiSelect("T", "", opts, []bool{false, true, false})
	if err != nil || !sel[0] || !sel[1] || !sel[2] {
		t.Errorf("Auswahl: %v %v", sel, err)
	}
}

func TestInputAndValidation(t *testing.T) {
	u := keys("ab\x7fc" + enter + "ok" + enter)
	calls := 0
	v, err := u.Input("T", "", "", func(s string) error {
		calls++
		if s == "ac" {
			return errors.New("nein")
		}
		return nil
	})
	if err != nil || v != "acok" || calls != 2 {
		t.Errorf("Input: %q %v %d", v, err, calls)
	}
	if v, _ := keys(enter).Input("T", "", "vorgabe", nil); v != "vorgabe" {
		t.Errorf("Vorgabe: %q", v)
	}
}

func TestListInput(t *testing.T) {
	items, err := keys("x.com"+enter+"y.com"+enter+"\x7f"+enter).ListInput("T", "", []string{"a.com"}, nil)
	if err != nil || strings.Join(items, ",") != "a.com,x.com" {
		t.Errorf("Liste: %v %v", items, err)
	}
}

func TestAccessible(t *testing.T) {
	var out bytes.Buffer
	u := New(strings.NewReader("9\n2\n1,3\nhallo\n<\n"), &out, true)
	opts := []Option{{Label: "a"}, {Label: "b"}, {Label: "c"}}
	i, err := u.Select("T", "", opts, 0)
	if err != nil || i != 1 || !strings.Contains(out.String(), "Ungültige Auswahl") {
		t.Errorf("Select: %d %v", i, err)
	}
	sel, _ := u.MultiSelect("T", "", opts, nil)
	if !sel[0] || sel[1] || !sel[2] {
		t.Errorf("Multi: %v", sel)
	}
	if v, _ := u.Input("T", "", "", nil); v != "hallo" {
		t.Errorf("Input: %q", v)
	}
	if _, err := u.Input("T", "", "", nil); !errors.Is(err, ErrBack) {
		t.Errorf("zurück: %v", err)
	}
	if strings.Contains(out.String(), "\x1b[") {
		t.Error("barrierearmer Modus darf keine Steuersequenzen ausgeben")
	}
}

func TestVisibleLen(t *testing.T) {
	if n := VisibleLen("\x1b[1mabc\x1b[0m"); n != 3 {
		t.Errorf("%d", n)
	}
}
