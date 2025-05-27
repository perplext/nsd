package security

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
)

// Validator provides input validation functions
type Validator struct {
	// Configurable limits
	MaxInterfaceNameLen int
	MaxFilterLen        int
	MaxPathLen          int
	MaxThemeNameLen     int
	AllowedThemeChars   *regexp.Regexp
	AllowedPathChars    *regexp.Regexp
}

// NewValidator creates a new validator with secure defaults
func NewValidator() *Validator {
	return &Validator{
		MaxInterfaceNameLen: 256,
		MaxFilterLen:        1024,
		MaxPathLen:          4096,
		MaxThemeNameLen:     64,
		AllowedThemeChars:   regexp.MustCompile(`^[a-zA-Z0-9_\-+]+$`),
		AllowedPathChars:    regexp.MustCompile(`^[a-zA-Z0-9_\-./]+$`),
	}
}

// ValidateInterfaceName validates a network interface name
func (v *Validator) ValidateInterfaceName(name string) error {
	if name == "" {
		return fmt.Errorf("interface name cannot be empty")
	}
	
	if len(name) > v.MaxInterfaceNameLen {
		return fmt.Errorf("interface name too long: %d > %d", len(name), v.MaxInterfaceNameLen)
	}
	
	// Check for null bytes
	if strings.Contains(name, "\x00") {
		return fmt.Errorf("interface name contains null bytes")
	}
	
	// Check for shell metacharacters
	if containsShellMetachars(name) {
		return fmt.Errorf("interface name contains shell metacharacters")
	}
	
	// Validate it's a reasonable interface name
	if !isValidInterfaceName(name) {
		return fmt.Errorf("invalid interface name format")
	}
	
	return nil
}

// ValidateBPFFilter validates a BPF filter expression
func (v *Validator) ValidateBPFFilter(filter string) error {
	if filter == "" {
		return nil // Empty filter is valid
	}
	
	if len(filter) > v.MaxFilterLen {
		return fmt.Errorf("filter too long: %d > %d", len(filter), v.MaxFilterLen)
	}
	
	// Check for null bytes
	if strings.Contains(filter, "\x00") {
		return fmt.Errorf("filter contains null bytes")
	}
	
	// Basic syntax validation
	if err := validateBPFSyntax(filter); err != nil {
		return fmt.Errorf("invalid BPF syntax: %w", err)
	}
	
	return nil
}

// ValidateFilePath validates a file path
func (v *Validator) ValidateFilePath(path string) error {
	if path == "" {
		return fmt.Errorf("file path cannot be empty")
	}
	
	if len(path) > v.MaxPathLen {
		return fmt.Errorf("path too long: %d > %d", len(path), v.MaxPathLen)
	}
	
	// Check for null bytes
	if strings.Contains(path, "\x00") {
		return fmt.Errorf("path contains null bytes")
	}
	
	// Clean the path
	cleaned := filepath.Clean(path)
	
	// Check for directory traversal
	if strings.Contains(cleaned, "..") {
		return fmt.Errorf("path contains directory traversal")
	}
	
	// Check if absolute path is trying to access system directories
	if filepath.IsAbs(cleaned) {
		if err := validateAbsolutePath(cleaned); err != nil {
			return err
		}
	}
	
	return nil
}

// ValidateThemeName validates a theme name
func (v *Validator) ValidateThemeName(name string) error {
	if name == "" {
		return fmt.Errorf("theme name cannot be empty")
	}
	
	if len(name) > v.MaxThemeNameLen {
		return fmt.Errorf("theme name too long: %d > %d", len(name), v.MaxThemeNameLen)
	}
	
	if !v.AllowedThemeChars.MatchString(name) {
		return fmt.Errorf("theme name contains invalid characters")
	}
	
	return nil
}

// ValidatePort validates a port number
func (v *Validator) ValidatePort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid port number: %d", port)
	}
	return nil
}

// ValidateIPAddress validates an IP address
func (v *Validator) ValidateIPAddress(ip string) error {
	if ip == "" {
		return fmt.Errorf("IP address cannot be empty")
	}
	
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}
	
	return nil
}

// ValidateCIDR validates a CIDR notation
func (v *Validator) ValidateCIDR(cidr string) error {
	if cidr == "" {
		return fmt.Errorf("CIDR cannot be empty")
	}
	
	_, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %w", err)
	}
	
	return nil
}

// SanitizeString removes potentially dangerous characters
func SanitizeString(s string, maxLen int) string {
	// Remove null bytes
	s = strings.ReplaceAll(s, "\x00", "")
	
	// Remove non-printable characters
	var result strings.Builder
	for _, r := range s {
		if unicode.IsPrint(r) || unicode.IsSpace(r) {
			result.WriteRune(r)
		}
	}
	
	s = result.String()
	
	// Truncate if too long
	if len(s) > maxLen {
		s = s[:maxLen]
	}
	
	return s
}

// containsShellMetachars checks for shell metacharacters
func containsShellMetachars(s string) bool {
	metachars := []string{
		";", "&", "|", "$", "`", "\\", "\"", "'",
		"<", ">", "(", ")", "{", "}", "[", "]",
		"*", "?", "~", "!", "\n", "\r",
	}
	
	for _, char := range metachars {
		if strings.Contains(s, char) {
			return true
		}
	}
	
	return false
}

// isValidInterfaceName checks if the name looks like a valid interface
func isValidInterfaceName(name string) bool {
	// Common patterns: eth0, wlan0, ens33, docker0, lo, etc.
	validPattern := regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9\-_.]*[0-9]*$`)
	return validPattern.MatchString(name)
}

// validateBPFSyntax performs basic BPF syntax validation
func validateBPFSyntax(filter string) error {
	// Check for balanced parentheses
	parenCount := 0
	for _, ch := range filter {
		switch ch {
		case '(':
			parenCount++
		case ')':
			parenCount--
			if parenCount < 0 {
				return fmt.Errorf("unmatched closing parenthesis")
			}
		}
	}
	
	if parenCount != 0 {
		return fmt.Errorf("unmatched parentheses")
	}
	
	// Check for dangerous keywords that might indicate injection
	dangerous := []string{
		"system", "exec", "sh", "bash", "cmd",
		"eval", "open", "read", "write",
	}
	
	lowerFilter := strings.ToLower(filter)
	for _, keyword := range dangerous {
		if strings.Contains(lowerFilter, keyword) {
			return fmt.Errorf("potentially dangerous keyword: %s", keyword)
		}
	}
	
	return nil
}

// validateAbsolutePath validates absolute paths
func validateAbsolutePath(path string) error {
	// Restricted system paths
	restrictedPaths := []string{
		"/etc",
		"/sys",
		"/proc",
		"/dev",
		"/boot",
		"/root",
		"/bin",
		"/sbin",
		"/usr/bin",
		"/usr/sbin",
		"/var/log/secure",
		"/var/log/auth",
	}
	
	for _, restricted := range restrictedPaths {
		if strings.HasPrefix(path, restricted) {
			return fmt.Errorf("access to system path denied: %s", path)
		}
	}
	
	// Check if path exists and is accessible
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Path doesn't exist, which might be OK for output files
			return nil
		}
		return fmt.Errorf("cannot access path: %w", err)
	}
	
	// Don't allow writing to directories
	if info.IsDir() {
		return fmt.Errorf("path is a directory, not a file")
	}
	
	return nil
}

// InputSanitizer provides methods to sanitize various inputs
type InputSanitizer struct {
	validator *Validator
}

// NewInputSanitizer creates a new input sanitizer
func NewInputSanitizer() *InputSanitizer {
	return &InputSanitizer{
		validator: NewValidator(),
	}
}

// SanitizeInterfaceName sanitizes and validates an interface name
func (is *InputSanitizer) SanitizeInterfaceName(name string) (string, error) {
	// Trim whitespace
	name = strings.TrimSpace(name)
	
	// Validate
	if err := is.validator.ValidateInterfaceName(name); err != nil {
		return "", err
	}
	
	return name, nil
}

// SanitizeBPFFilter sanitizes and validates a BPF filter
func (is *InputSanitizer) SanitizeBPFFilter(filter string) (string, error) {
	// Trim whitespace
	filter = strings.TrimSpace(filter)
	
	// Normalize whitespace
	filter = regexp.MustCompile(`\s+`).ReplaceAllString(filter, " ")
	
	// Validate
	if err := is.validator.ValidateBPFFilter(filter); err != nil {
		return "", err
	}
	
	return filter, nil
}

// SanitizeFilePath sanitizes and validates a file path
func (is *InputSanitizer) SanitizeFilePath(path string) (string, error) {
	// Trim whitespace
	path = strings.TrimSpace(path)
	
	// Clean the path
	path = filepath.Clean(path)
	
	// Validate
	if err := is.validator.ValidateFilePath(path); err != nil {
		return "", err
	}
	
	return path, nil
}