package security

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ValidatePath validates a file path to prevent directory traversal attacks
func ValidatePath(path string, allowedDir string) error {
	// Clean the path to remove any ../ or ./ elements
	cleanPath := filepath.Clean(path)
	
	// Get absolute paths for comparison
	absPath, err := filepath.Abs(cleanPath)
	if err != nil {
		return fmt.Errorf("invalid path: %v", err)
	}
	
	absAllowedDir, err := filepath.Abs(allowedDir)
	if err != nil {
		return fmt.Errorf("invalid allowed directory: %v", err)
	}
	
	// Ensure the path is within the allowed directory
	if !strings.HasPrefix(absPath, absAllowedDir) {
		return fmt.Errorf("path '%s' is outside allowed directory", path)
	}
	
	// Check if path contains suspicious patterns
	if strings.Contains(path, "..") {
		return fmt.Errorf("path contains directory traversal pattern")
	}
	
	return nil
}

// SafeOpenFile opens a file after validating the path
func SafeOpenFile(path string, allowedDir string) (*os.File, error) {
	if err := ValidatePath(path, allowedDir); err != nil {
		return nil, err
	}
	
	return os.Open(path)
}

// SafeReadFile reads a file after validating the path
func SafeReadFile(path string, allowedDir string) ([]byte, error) {
	if err := ValidatePath(path, allowedDir); err != nil {
		return nil, err
	}
	
	return os.ReadFile(path)
}

// SafeCreateFile creates a file after validating the path with secure permissions
func SafeCreateFile(path string, allowedDir string) (*os.File, error) {
	if err := ValidatePath(path, allowedDir); err != nil {
		return nil, err
	}
	
	// Create file with secure permissions (0600)
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
}

// SafeWriteFile writes data to a file with secure permissions
func SafeWriteFile(path string, data []byte, allowedDir string) error {
	if err := ValidatePath(path, allowedDir); err != nil {
		return err
	}
	
	// Write file with secure permissions (0600)
	return os.WriteFile(path, data, 0600)
}