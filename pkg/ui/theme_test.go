package ui

import (
	"testing"

	"github.com/rivo/tview"
	"github.com/perplext/nsd/pkg/netcap"
)

func TestSetThemeValid(t *testing.T) {
	nm := netcap.NewNetworkMonitor()
	u := NewUI(nm)
	for name, want := range Themes {
		u2 := u.SetTheme(name)
		if u2.theme != want {
			t.Errorf("SetTheme(%q) = %v; want %v", name, u2.theme, want)
		}
	}
}

func TestSetThemeInvalidDefaults(t *testing.T) {
	nm := netcap.NewNetworkMonitor()
	u := NewUI(nm)
	u2 := u.SetTheme("nonexistent")
	want := Themes["Dark+"]
	if u2.theme != want {
		t.Errorf("SetTheme(invalid) = %v; want default %v", u2.theme, want)
	}
}

func TestSetStyleValid(t *testing.T) {
	nm := netcap.NewNetworkMonitor()
	u := NewUI(nm)
	for name, def := range Styles {
		u2 := u.SetStyle(name)
		if u2.styleName != name {
			t.Errorf("SetStyle(%q) styleName = %q; want %q", name, u2.styleName, name)
		}
		if tview.Borders.TopLeft != def.BorderTL || tview.Borders.TopRight != def.BorderTR ||
			tview.Borders.BottomLeft != def.BorderBL || tview.Borders.BottomRight != def.BorderBR ||
			tview.Borders.Horizontal != def.BorderH || tview.Borders.Vertical != def.BorderV {
			t.Errorf("SetStyle(%q) borders = %+v; want %+v", name,
				 tview.Borders, def)
		}
	}
}

func TestSetStyleInvalidDefaults(t *testing.T) {
	nm := netcap.NewNetworkMonitor()
	u := NewUI(nm)
	// capture current Standard definition
	std := Styles["Standard"]
	u2 := u.SetStyle("invalid")
	if u2.styleName != "Standard" {
		t.Errorf("SetStyle(invalid) styleName = %q; want Standard", u2.styleName)
	}
	if tview.Borders.TopLeft != std.BorderTL {
		t.Errorf("SetStyle(invalid) TopLeft = %c; want %c", tview.Borders.TopLeft, std.BorderTL)
	}
}
