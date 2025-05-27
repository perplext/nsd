package ui

import (
	"os"
	"testing"

	"github.com/gdamore/tcell/v2"
)

// TestLoadThemesJSON verifies JSON theme loading
func TestLoadThemesJSON(t *testing.T) {
	// prepare a temp JSON theme file
	jsonData := `{
		"CustomJSON": {
			"BorderColor": "#112233",
			"TitleColor": "#445566",
			"PrimaryColor": "#778899",
			"SecondaryColor": "#AABBCC",
			"PieBorderColor": "#DDEEFF",
			"PieTitleColor": "#001122",
			"StatusBarTextColor": "#334455",
			"StatusBarBgColor": "#667788"
		}
	}`
	f, err := os.CreateTemp("", "theme_*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(jsonData); err != nil {
		t.Fatal(err)
	}
	f.Close()

	if err := LoadThemes(f.Name()); err != nil {
		t.Fatalf("LoadThemes JSON failed: %v", err)
	}
	want := Theme{
		BorderColor:        tcell.NewRGBColor(0x11, 0x22, 0x33),
		TitleColor:         tcell.NewRGBColor(0x44, 0x55, 0x66),
		PrimaryColor:       tcell.NewRGBColor(0x77, 0x88, 0x99),
		SecondaryColor:     tcell.NewRGBColor(0xAA, 0xBB, 0xCC),
		PieBorderColor:     tcell.NewRGBColor(0xDD, 0xEE, 0xFF),
		PieTitleColor:      tcell.NewRGBColor(0x00, 0x11, 0x22),
		StatusBarTextColor: tcell.NewRGBColor(0x33, 0x44, 0x55),
		StatusBarBgColor:   tcell.NewRGBColor(0x66, 0x77, 0x88),
	}
	got, ok := Themes["CustomJSON"]
	if !ok {
		t.Fatalf("Themes missing CustomJSON key")
	}
	if got != want {
		t.Errorf("Got %+v; want %+v", got, want)
	}
}

// TestLoadThemesYAML verifies YAML theme loading
func TestLoadThemesYAML(t *testing.T) {
	// prepare a temp YAML theme file
	yamlData := `
CustomYAML:
  BorderColor: "#FFEEDD"
  TitleColor: "#CCBBAA"
  PrimaryColor: "#998877"
  SecondaryColor: "#665544"
  PieBorderColor: "#332211"
  PieTitleColor: "#A1B2C3"
  StatusBarTextColor: "#C3B2A1"
  StatusBarBgColor: "#998877"
`
	f, err := os.CreateTemp("", "theme_*.yml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(yamlData); err != nil {
		t.Fatal(err)
	}
	f.Close()

	if err := LoadThemes(f.Name()); err != nil {
		t.Fatalf("LoadThemes YAML failed: %v", err)
	}
	want := Theme{
		BorderColor:        tcell.NewRGBColor(0xFF, 0xEE, 0xDD),
		TitleColor:         tcell.NewRGBColor(0xCC, 0xBB, 0xAA),
		PrimaryColor:       tcell.NewRGBColor(0x99, 0x88, 0x77),
		SecondaryColor:     tcell.NewRGBColor(0x66, 0x55, 0x44),
		PieBorderColor:     tcell.NewRGBColor(0x33, 0x22, 0x11),
		PieTitleColor:      tcell.NewRGBColor(0xA1, 0xB2, 0xC3),
		StatusBarTextColor: tcell.NewRGBColor(0xC3, 0xB2, 0xA1),
		StatusBarBgColor:   tcell.NewRGBColor(0x99, 0x88, 0x77),
	}
	got, ok := Themes["CustomYAML"]
	if !ok {
		t.Fatalf("Themes missing CustomYAML key")
	}
	if got != want {
		t.Errorf("Got %+v; want %+v", got, want)
	}
}
