package plugin

import (
    "os"
    "testing"
)

func TestLoadNonExistent(t *testing.T) {
    _, err := Load("nonexistent.so")
    if err == nil {
        t.Fatal("expected error loading nonexistent plugin, got nil")
    }
}

func TestLoadInvalidFile(t *testing.T) {
    // create an empty temporary file
    f, err := os.CreateTemp("", "invalid*.so")
    if err != nil {
        t.Fatalf("failed to create temp file: %v", err)
    }
    f.Close()
    defer os.Remove(f.Name())

    _, err = Load(f.Name())
    if err == nil {
        t.Fatalf("expected error loading invalid plugin file %s, got nil", f.Name())
    }
}
