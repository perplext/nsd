package main

import (
	"flag"
	"testing"
)

func TestCLIFlags(t *testing.T) {
	// Backup original flag.CommandLine
	orig := flag.CommandLine
	defer func() { flag.CommandLine = orig }()

	// Create new FlagSet
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	var i, theme, style string
	fs.StringVar(&i, "i", "", "interface")
	fs.StringVar(&theme, "theme", "Dark+", "theme")
	fs.StringVar(&style, "style", "Standard", "style")

	// Simulate args
	err := fs.Parse([]string{"-i", "eth0", "-theme", "Solarized", "-style", "btop"})
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if i != "eth0" {
		t.Errorf("i = %q; want %q", i, "eth0")
	}
	if theme != "Solarized" {
		t.Errorf("theme = %q; want %q", theme, "Solarized")
	}
	if style != "btop" {
		t.Errorf("style = %q; want %q", style, "btop")
	}
}
