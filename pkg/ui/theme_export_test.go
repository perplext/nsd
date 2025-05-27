package ui

import (
    "encoding/json"
    "os"
    "testing"

    "gopkg.in/yaml.v3"
)

func TestExportThemeJSON(t *testing.T) {
    name := "Dark+"
    f, err := os.CreateTemp("", "export_theme_*.json")
    if err != nil {
        t.Fatalf("failed to create temp file: %v", err)
    }
    defer os.Remove(f.Name())

    if err := ExportTheme(name, f.Name()); err != nil {
        t.Fatalf("ExportTheme JSON failed: %v", err)
    }
    data, err := os.ReadFile(f.Name())
    if err != nil {
        t.Fatalf("failed to read file: %v", err)
    }
    var raw map[string]themeConfig
    if err := json.Unmarshal(data, &raw); err != nil {
        t.Fatalf("invalid JSON: %v", err)
    }
    if _, ok := raw[name]; !ok {
        t.Errorf("exported JSON missing key %s", name)
    }
    want := colorToHex(Themes[name].BorderColor)
    if raw[name].BorderColor != want {
        t.Errorf("got BorderColor %s; want %s", raw[name].BorderColor, want)
    }
}

func TestExportThemeYAML(t *testing.T) {
    name := "Light+"
    f, err := os.CreateTemp("", "export_theme_*.yml")
    if err != nil {
        t.Fatalf("failed to create temp file: %v", err)
    }
    defer os.Remove(f.Name())

    if err := ExportTheme(name, f.Name()); err != nil {
        t.Fatalf("ExportTheme YAML failed: %v", err)
    }
    data, err := os.ReadFile(f.Name())
    if err != nil {
        t.Fatalf("failed to read file: %v", err)
    }
    var raw map[string]themeConfig
    if err := yaml.Unmarshal(data, &raw); err != nil {
        t.Fatalf("invalid YAML: %v", err)
    }
    if _, ok := raw[name]; !ok {
        t.Errorf("exported YAML missing key %s", name)
    }
    want := colorToHex(Themes[name].PrimaryColor)
    if raw[name].PrimaryColor != want {
        t.Errorf("got PrimaryColor %s; want %s", raw[name].PrimaryColor, want)
    }
}
