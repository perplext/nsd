package ui

import "testing"

func TestStylesStandard(t *testing.T) {
	def, ok := Styles["Standard"]
	if !ok {
		t.Fatal("Standard style missing")
	}
	if def.BorderTL != '+' || def.BorderTR != '+' || def.BorderBL != '+' || def.BorderBR != '+' ||
		def.BorderH != '-' || def.BorderV != '|' {
		t.Errorf("Standard borders = %+v; want TL '+', TR '+', BL '+', BR '+', H '-', V '|'", def)
	}
}

func TestStylesBtop(t *testing.T) {
	def, ok := Styles["btop"]
	if !ok {
		t.Fatal("btop style missing")
	}
	if def.BorderTL != '╭' || def.BorderTR != '╮' || def.BorderBL != '╰' || def.BorderBR != '╯' ||
		def.BorderH != '─' || def.BorderV != '│' {
		t.Errorf("btop borders = %+v; want TL '╭', TR '╮', BL '╰', BR '╯', H '─', V '│'", def)
	}
}
