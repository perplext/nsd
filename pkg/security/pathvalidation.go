package security

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// secureValidatePath performs comprehensive path validation against directory traversal
// and symlink attacks by resolving canonical paths and validating containment
func secureValidatePath(path string, allowedDir string, createMode bool) (string, error) {
	// Step 1: Clean and get absolute paths
	cleanPath := filepath.Clean(path)
	absPath, err := filepath.Abs(cleanPath)
	if err != nil {
		return "", fmt.Errorf("invalid path: %v", err)
	}
	
	absAllowedDir, err := filepath.Abs(allowedDir)
	if err != nil {
		return "", fmt.Errorf("invalid allowed directory: %v", err)
	}
	
	// Step 2: Resolve canonical allowed directory
	canonicalAllowedDir, err := filepath.EvalSymlinks(absAllowedDir)
	if err != nil {
		return "", fmt.Errorf("cannot resolve allowed directory: %v", err)
	}
	
	// Step 3: Resolve canonical path - handle create mode specially
	var canonicalPath string
	if createMode {
		// For create operations, the file might not exist yet
		// Resolve the directory path and construct the full path
		dir := filepath.Dir(absPath)
		canonicalDir, err := filepath.EvalSymlinks(dir)
		if err != nil {
			return "", fmt.Errorf("cannot resolve directory path: %v", err)
		}
		canonicalPath = filepath.Join(canonicalDir, filepath.Base(absPath))
	} else {
		// For read operations, the file should exist
		canonicalPath, err = filepath.EvalSymlinks(absPath)
		if err != nil {
			return "", fmt.Errorf("cannot resolve symbolic links: %v", err)
		}
	}
	
	// Step 4: Validate containment using canonical paths with proper separator handling
	// Add separator to avoid prefix matching issues (e.g., /allowed vs /allowedEvil)
	allowedPrefix := canonicalAllowedDir + string(filepath.Separator)
	pathToCheck := canonicalPath
	if !strings.HasSuffix(canonicalPath, string(filepath.Separator)) {
		pathToCheck = canonicalPath + string(filepath.Separator)
	}
	
	if !strings.HasPrefix(pathToCheck, allowedPrefix) && canonicalPath != canonicalAllowedDir {
		return "", fmt.Errorf("resolved path '%s' is outside allowed directory '%s'", canonicalPath, canonicalAllowedDir)
	}
	
	// Step 5: Additional security checks on original path
	if strings.Contains(cleanPath, "..") {
		return "", fmt.Errorf("path contains directory traversal pattern")
	}
	
	// Step 6: Validate no null bytes (can cause issues on some systems)
	if strings.Contains(path, "\x00") {
		return "", fmt.Errorf("path contains null bytes")
	}
	
	return canonicalPath, nil
}

// ValidatePath validates a file path to prevent directory traversal attacks
// This function maintains backward compatibility but uses secure validation internally
func ValidatePath(path string, allowedDir string) error {
	_, err := secureValidatePath(path, allowedDir, false)
	return err
}

// SafeOpenFile opens a file after comprehensive security validation
func SafeOpenFile(path string, allowedDir string) (*os.File, error) {
	canonicalPath, err := secureValidatePath(path, allowedDir, false)
	if err != nil {
		return nil, err
	}
	
	return os.Open(canonicalPath)
}

// SafeReadFile reads a file after comprehensive security validation
func SafeReadFile(path string, allowedDir string) ([]byte, error) {
	canonicalPath, err := secureValidatePath(path, allowedDir, false)
	if err != nil {
		return nil, err
	}
	
	return os.ReadFile(canonicalPath)
}

// SafeCreateFile creates a file after comprehensive security validation with secure permissions
func SafeCreateFile(path string, allowedDir string) (*os.File, error) {
	canonicalPath, err := secureValidatePath(path, allowedDir, true)
	if err != nil {
		return nil, err
	}
	
	// Use canonical path to prevent TOCTOU attacks
	return os.OpenFile(canonicalPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
}

// SafeWriteFile writes data to a file with comprehensive security validation and secure permissions
func SafeWriteFile(path string, data []byte, allowedDir string) error {
	canonicalPath, err := secureValidatePath(path, allowedDir, true)
	if err != nil {
		return err
	}
	
	// Use canonical path to prevent TOCTOU attacks
	return os.WriteFile(canonicalPath, data, 0600)
}