package security

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateAndCleanPath(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir := t.TempDir()
	
	tests := []struct {
		name        string
		path        string
		allowedDir  string
		wantErr     bool
		errContains string
		expectPath  string
	}{
		{
			name:       "Valid relative path",
			path:       "test.txt",
			allowedDir: tmpDir,
			wantErr:    false,
			expectPath: filepath.Join(tmpDir, "test.txt"),
		},
		{
			name:       "Valid nested path",
			path:       "subdir/test.txt",
			allowedDir: tmpDir,
			wantErr:    false,
			expectPath: filepath.Join(tmpDir, "subdir/test.txt"),
		},
		{
			name:        "Path with null bytes",
			path:        "test\x00.txt",
			allowedDir:  tmpDir,
			wantErr:     true,
			errContains: "null bytes",
		},
		{
			name:        "Path too long",
			path:        strings.Repeat("a", 5000),
			allowedDir:  tmpDir,
			wantErr:     true,
			errContains: "too long",
		},
		{
			name:        "Directory traversal attack",
			path:        "../../../etc/passwd",
			allowedDir:  tmpDir,
			wantErr:     true,
			errContains: "directory traversal",
		},
		{
			name:        "Hidden directory traversal",
			path:        "subdir/../../../etc/passwd",
			allowedDir:  tmpDir,
			wantErr:     true,
			errContains: "directory traversal",
		},
		{
			name:        "Absolute path outside allowed directory",
			path:        "/etc/passwd",
			allowedDir:  tmpDir,
			wantErr:     true,
			errContains: "outside allowed directory",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ValidateAndCleanPath(tt.path, tt.allowedDir)
			
			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error but got none")
					return
				}
				if tt.errContains != "" && !containsString(err.Error(), tt.errContains) {
					t.Errorf("Expected error to contain '%s', got: %v", tt.errContains, err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
					return
				}
				if result != tt.expectPath {
					t.Errorf("Expected path '%s', got '%s'", tt.expectPath, result)
				}
			}
		})
	}
}

func TestSafeFileOperations(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	testContent := []byte("test content")
	
	// Write test content to file
	err := os.WriteFile(testFile, testContent, 0600)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	
	t.Run("SafeReadFile", func(t *testing.T) {
		// Test reading valid file
		content, err := SafeReadFile("test.txt", tmpDir)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if string(content) != string(testContent) {
			t.Errorf("Expected content '%s', got '%s'", string(testContent), string(content))
		}
		
		// Test reading file outside allowed directory
		_, err = SafeReadFile("../../../etc/passwd", tmpDir)
		if err == nil {
			t.Error("Expected error for directory traversal attack")
		}
	})
	
	t.Run("SafeOpenFile", func(t *testing.T) {
		// Test opening valid file
		file, err := SafeOpenFile("test.txt", tmpDir)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if file != nil {
			file.Close()
		}
		
		// Test opening file outside allowed directory
		_, err = SafeOpenFile("../../../etc/passwd", tmpDir)
		if err == nil {
			t.Error("Expected error for directory traversal attack")
		}
	})
	
	t.Run("SafeWriteFile", func(t *testing.T) {
		newContent := []byte("new test content")
		
		// Test writing to valid file
		err := SafeWriteFile("newtest.txt", newContent, tmpDir)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		
		// Verify content was written
		written, err := os.ReadFile(filepath.Join(tmpDir, "newtest.txt"))
		if err != nil {
			t.Errorf("Failed to read written file: %v", err)
		}
		if string(written) != string(newContent) {
			t.Errorf("Expected content '%s', got '%s'", string(newContent), string(written))
		}
		
		// Test writing file outside allowed directory
		err = SafeWriteFile("../../../tmp/malicious.txt", newContent, tmpDir)
		if err == nil {
			t.Error("Expected error for directory traversal attack")
		}
	})
	
	t.Run("SafeCreateFile", func(t *testing.T) {
		// Test creating valid file
		file, err := SafeCreateFile("created.txt", tmpDir)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if file != nil {
			file.Close()
		}
		
		// Test creating file outside allowed directory
		_, err = SafeCreateFile("../../../tmp/malicious.txt", tmpDir) 
		if err == nil {
			t.Error("Expected error for directory traversal attack")
		}
	})
}

// Helper function to check if a string contains a substring
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || 
		(len(s) > len(substr) && func() bool {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
			return false
		}()))
}