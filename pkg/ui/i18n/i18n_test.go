package i18n

import (
    "os"
    "testing"
)

func TestLoadTranslations(t *testing.T) {
    // prepare a temp JSON translation file
    jsonData := `{ "test_key": "translated", "requires_root": "Please run as root (translated)" }`
    f, err := os.CreateTemp("", "trans_*.json")
    if err != nil {
        t.Fatalf("failed to create temp file: %v", err)
    }
    defer os.Remove(f.Name())
    if _, err := f.WriteString(jsonData); err != nil {
        t.Fatalf("failed to write translations: %v", err)
    }
    f.Close()

    // fallback to key if missing
    if v := T("unknown"); v != "unknown" {
        t.Errorf("expected fallback to key; got %q", v)
    }

    // load translations
    if err := LoadTranslations(f.Name()); err != nil {
        t.Fatalf("LoadTranslations failed: %v", err)
    }
    if v := T("test_key"); v != "translated" {
        t.Errorf("expected translated; got %q", v)
    }
    // override default
    if v := T("requires_root"); v != "Please run as root (translated)" {
        t.Errorf("expected overridden requires_root; got %q", v)
    }
}
