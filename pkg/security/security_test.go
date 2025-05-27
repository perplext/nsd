package security

import (
	"testing"
)

func TestSnortEngineBasic(t *testing.T) {
	engine := NewSnortEngine()
	if engine == nil {
		t.Fatal("Expected SnortEngine to be created")
	}
}

func TestSuricataEngineBasic(t *testing.T) {
	engine := NewSuricataEngine(false)
	if engine == nil {
		t.Fatal("Expected SuricataEngine to be created")
	}
}

func TestZeekEngineBasic(t *testing.T) {
	engine := NewZeekEngine()
	if engine == nil {
		t.Fatal("Expected ZeekEngine to be created")
	}
}

func TestYARAEngineBasic(t *testing.T) {
	engine := NewYARAEngine()
	if engine == nil {
		t.Fatal("Expected YARAEngine to be created")
	}
}

func TestSigmaEngineBasic(t *testing.T) {
	engine := NewSigmaEngine()
	if engine == nil {
		t.Fatal("Expected SigmaEngine to be created")
	}
}

func TestNetworkAttackDetectorBasic(t *testing.T) {
	detector := NewNetworkAttackDetector()
	if detector == nil {
		t.Fatal("Expected NetworkAttackDetector to be created")
	}
}