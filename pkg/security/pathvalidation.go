package security

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ValidatedPath represents a path that has been validated and is safe to use
type ValidatedPath struct {
	original string
	clean    string
	absolute string
}

// ValidatePath validates a file path to prevent directory traversal attacks
func ValidatePath(path string, allowedDir string) (*ValidatedPath, error) {
	// Input validation
	if path == "" {
		return nil, fmt.Errorf("empty path provided")
	}
	if allowedDir == "" {
		return nil, fmt.Errorf("empty allowed directory provided")
	}
	
	// Clean the path to remove any ../ or ./ elements
	cleanPath := filepath.Clean(path)
	
	// Check for null bytes and other suspicious characters
	if strings.ContainsAny(path, "\x00") {
		return nil, fmt.Errorf("path contains null bytes")
	}
	
	// Get absolute paths for comparison
	absPath, err := filepath.Abs(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("invalid path: %v", err)
	}
	
	absAllowedDir, err := filepath.Abs(allowedDir)
	if err != nil {
		return nil, fmt.Errorf("invalid allowed directory: %v", err)
	}
	
	// Resolve symlinks to prevent symlink attacks
	resolvedPath, err := filepath.EvalSymlinks(absPath)
	if err != nil {
		// If symlink resolution fails, it might be a non-existent file, which is ok for creation
		// But we still use the absolute path for validation
		resolvedPath = absPath
	}
	
	// Ensure the resolved path is within the allowed directory
	if !strings.HasPrefix(resolvedPath, absAllowedDir+string(filepath.Separator)) && resolvedPath != absAllowedDir {
		return nil, fmt.Errorf("path '%s' resolves outside allowed directory", path)
	}
	
	// Additional checks for directory traversal patterns
	if strings.Contains(cleanPath, "..") {
		return nil, fmt.Errorf("path contains directory traversal pattern")
	}
	
	// Check for suspicious file extensions that shouldn't be accessed
	ext := strings.ToLower(filepath.Ext(cleanPath))
	prohibitedExts := []string{".exe", ".bat", ".cmd", ".com", ".scr", ".pif"}
	for _, prohibitedExt := range prohibitedExts {
		if ext == prohibitedExt {
			return nil, fmt.Errorf("prohibited file extension: %s", ext)
		}
	}
	
	return &ValidatedPath{
		original: path,
		clean:    cleanPath,
		absolute: resolvedPath,
	}, nil
}

// GetSafePath returns the safe, validated path to use for file operations
func (vp *ValidatedPath) GetSafePath() string {
	return vp.absolute
}

// GetCleanPath returns the cleaned path
func (vp *ValidatedPath) GetCleanPath() string {
	return vp.clean
}

// GetOriginalPath returns the original path (for logging/debugging only)
func (vp *ValidatedPath) GetOriginalPath() string {
	return vp.original
}

// SafeOpenFile opens a file after validating the path
func SafeOpenFile(path string, allowedDir string) (*os.File, error) {
	validatedPath, err := ValidatePath(path, allowedDir)
	if err != nil {
		return nil, err
	}
	
	// Use the validated, safe path instead of the original user input
	return os.Open(validatedPath.GetSafePath())
}

// SafeReadFile reads a file after validating the path
func SafeReadFile(path string, allowedDir string) ([]byte, error) {
	validatedPath, err := ValidatePath(path, allowedDir)
	if err != nil {
		return nil, err
	}
	
	// Use the validated, safe path instead of the original user input
	return os.ReadFile(validatedPath.GetSafePath())
}

// SafeCreateFile creates a file after validating the path with secure permissions
func SafeCreateFile(path string, allowedDir string) (*os.File, error) {
	validatedPath, err := ValidatePath(path, allowedDir)
	if err != nil {
		return nil, err
	}
	
	// Create file with secure permissions (0600) using validated path
	return os.OpenFile(validatedPath.GetSafePath(), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
}

// SafeWriteFile writes data to a file with secure permissions
func SafeWriteFile(path string, data []byte, allowedDir string) error {
	validatedPath, err := ValidatePath(path, allowedDir)
	if err != nil {
		return err
	}
	
	// Write file with secure permissions (0600) using validated path
	return os.WriteFile(validatedPath.GetSafePath(), data, 0600)
}