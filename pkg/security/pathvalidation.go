package security

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ValidateAndCleanPath validates a file path and returns the cleaned, secure path
func ValidateAndCleanPath(path string, allowedDir string) (string, error) {
	// Check for null bytes which can be used for path injection
	if strings.Contains(path, "\x00") {
		return "", errors.New("path contains null bytes")
	}
	
	// Check for overly long paths
	if len(path) > 4096 {
		return "", errors.New("path too long")
	}
	
	// Clean the path to remove any ../ or ./ elements
	cleanPath := filepath.Clean(path)
	
	// If path is absolute, we need to make it relative to the allowed directory
	if filepath.IsAbs(cleanPath) {
		// Convert absolute path to relative by removing the allowed directory prefix
		absAllowedDir, err := filepath.Abs(allowedDir)
		if err != nil {
			return "", fmt.Errorf("invalid allowed directory: %v", err)
		}
		
		if !strings.HasPrefix(cleanPath, absAllowedDir) {
			return "", fmt.Errorf("absolute path '%s' is outside allowed directory", path)
		}
		
		// Make it relative to the allowed directory
		relPath, err := filepath.Rel(absAllowedDir, cleanPath)
		if err != nil {
			return "", fmt.Errorf("failed to make path relative: %v", err)
		}
		cleanPath = relPath
	}
	
	// Additional checks for suspicious patterns
	if strings.Contains(cleanPath, "..") {
		return "", errors.New("path contains directory traversal pattern")
	}
	
	// Construct the final secure path within the allowed directory
	finalPath := filepath.Join(allowedDir, cleanPath)
	
	// Get absolute paths for final validation
	absFinalPath, err := filepath.Abs(finalPath)
	if err != nil {
		return "", fmt.Errorf("invalid final path: %v", err)
	}
	
	absAllowedDir, err := filepath.Abs(allowedDir)
	if err != nil {
		return "", fmt.Errorf("invalid allowed directory: %v", err)
	}
	
	// Ensure the final path is still within the allowed directory
	if !strings.HasPrefix(absFinalPath, absAllowedDir) {
		return "", fmt.Errorf("path '%s' is outside allowed directory", path)
	}
	
	return absFinalPath, nil
}

// secureValidatePath performs enhanced validation with symlink resolution
// to prevent TOCTOU attacks and symlink-based directory traversal
func secureValidatePath(path string, allowedDir string, forCreate bool) (string, error) {
	// Basic validation first
	if strings.Contains(path, "\x00") {
		return "", errors.New("path contains null bytes")
	}
	
	if len(path) > 4096 {
		return "", errors.New("path too long")
	}
	
	if path == "" {
		return "", errors.New("empty path")
	}
	
	// Get canonical path for the allowed directory
	absAllowedDir, err := filepath.Abs(allowedDir)
	if err != nil {
		return "", fmt.Errorf("invalid allowed directory: %v", err)
	}
	
	// Resolve allowed directory symlinks
	canonicalAllowedDir, err := filepath.EvalSymlinks(absAllowedDir)
	if err != nil {
		return "", fmt.Errorf("failed to resolve allowed directory symlinks: %v", err)
	}
	
	// Clean and construct the target path
	cleanPath := filepath.Clean(path)
	var targetPath string
	
	if filepath.IsAbs(cleanPath) {
		targetPath = cleanPath
	} else {
		targetPath = filepath.Join(canonicalAllowedDir, cleanPath)
	}
	
	// For existing files, resolve symlinks to get canonical path
	var canonicalPath string
	if forCreate {
		// For file creation, we validate the parent directory
		parentDir := filepath.Dir(targetPath)
		canonicalParent, err := filepath.EvalSymlinks(parentDir)
		if err != nil {
			return "", fmt.Errorf("failed to resolve parent directory symlinks: %v", err)
		}
		canonicalPath = filepath.Join(canonicalParent, filepath.Base(targetPath))
	} else {
		// For existing files, resolve all symlinks
		canonicalPath, err = filepath.EvalSymlinks(targetPath)
		if err != nil {
			return "", fmt.Errorf("failed to resolve target path symlinks: %v", err)
		}
	}
	
	// Ensure the canonical path is within the canonical allowed directory
	if !strings.HasPrefix(canonicalPath, canonicalAllowedDir+string(filepath.Separator)) &&
		canonicalPath != canonicalAllowedDir {
		return "", fmt.Errorf("path '%s' is outside allowed directory after symlink resolution", path)
	}
	
	return canonicalPath, nil
}

// ValidatePath validates a file path to prevent directory traversal attacks (legacy function)
func ValidatePath(path string, allowedDir string) error {
	_, err := ValidateAndCleanPath(path, allowedDir)
	return err
}

// SafeOpenFile opens a file after validating the path with enhanced security
func SafeOpenFile(path string, allowedDir string) (*os.File, error) {
	safePath, err := secureValidatePath(path, allowedDir, false)
	if err != nil {
		return nil, err
	}
	
	return os.Open(safePath)
}

// SafeReadFile reads a file after validating the path with enhanced security
func SafeReadFile(path string, allowedDir string) ([]byte, error) {
	safePath, err := secureValidatePath(path, allowedDir, false)
	if err != nil {
		return nil, err
	}
	
	return os.ReadFile(safePath)
}

// SafeCreateFile creates a file after validating the path with secure permissions
func SafeCreateFile(path string, allowedDir string) (*os.File, error) {
	safePath, err := secureValidatePath(path, allowedDir, true)
	if err != nil {
		return nil, err
	}
	
	// Create file with secure permissions (0600)
	return os.OpenFile(safePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
}

// SafeWriteFile writes data to a file with secure permissions
func SafeWriteFile(path string, data []byte, allowedDir string) error {
	safePath, err := secureValidatePath(path, allowedDir, true)
	if err != nil {
		return err
	}
	
	// Write file with secure permissions (0600)
	return os.WriteFile(safePath, data, 0600)
}