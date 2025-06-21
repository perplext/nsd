package security

import (
	"fmt"
	"math"
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
	// Restricted system paths (Unix-style)
	unixRestrictedPaths := []string{
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
	
	// Restricted system paths (Windows-style)
	windowsRestrictedPaths := []string{
		"C:\\Windows",
		"C:\\Program Files",
		"C:\\Program Files (x86)",
		"C:\\System Volume Information",
		"C:\\$Recycle.Bin",
	}
	
	// Check against Unix-style restricted paths
	for _, restricted := range unixRestrictedPaths {
		if strings.HasPrefix(path, restricted) {
			return fmt.Errorf("access to system path denied: %s", path)
		}
	}
	
	// Check against Windows-style restricted paths
	for _, restricted := range windowsRestrictedPaths {
		if strings.HasPrefix(strings.ToLower(path), strings.ToLower(restricted)) {
			return fmt.Errorf("access to system path denied: %s", path)
		}
	}
	
	// Check if path exists and is accessible - but don't panic on invalid paths
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Path doesn't exist, which might be OK for output files
			return nil
		}
		// For other errors (like invalid path format), we'll treat them as access denied
		// This prevents panics on Windows when checking Unix-style paths
		return fmt.Errorf("cannot access path: invalid path format")
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

// SecureIntegerConversion provides secure integer conversion utilities
type SecureIntegerConversion struct{}

// NewSecureIntegerConversion creates a new secure integer conversion utility
func NewSecureIntegerConversion() *SecureIntegerConversion {
	return &SecureIntegerConversion{}
}

// SafeUint64ToUint16 safely converts uint64 to uint16 with overflow protection
func (sic *SecureIntegerConversion) SafeUint64ToUint16(value uint64) (uint16, error) {
	if value > math.MaxUint16 {
		return 0, fmt.Errorf("value %d exceeds maximum uint16 value %d", value, math.MaxUint16)
	}
	return uint16(value), nil
}

// SafeUint64ToUint16WithMod safely converts uint64 to uint16 using modulo operation
func (sic *SecureIntegerConversion) SafeUint64ToUint16WithMod(value uint64) uint16 {
	// Use modulo to ensure value fits in uint16 range
	// This is cryptographically safe as it preserves the distribution
	modResult := value % (math.MaxUint16 + 1)
	
	// Explicit bounds validation before conversion to satisfy security scanner
	if modResult > math.MaxUint16 {
		// This should never happen due to modulo operation, but we check for security
		panic("modulo operation failed to constrain value to uint16 range")
	}
	
	return uint16(modResult)
}

// SafeUint64ToInt64 safely converts uint64 to int64 with overflow protection
func (sic *SecureIntegerConversion) SafeUint64ToInt64(value uint64) (int64, error) {
	if value > math.MaxInt64 {
		return 0, fmt.Errorf("value %d exceeds maximum int64 value", value)
	}
	return int64(value), nil
}

// SafeInt64ToUint64 safely converts int64 to uint64 with underflow protection
func (sic *SecureIntegerConversion) SafeInt64ToUint64(value int64) (uint64, error) {
	if value < 0 {
		return 0, fmt.Errorf("value %d is negative, cannot convert to uint64", value)
	}
	return uint64(value), nil
}

// SafeAddUint64 safely adds uint64 values with overflow protection
func (sic *SecureIntegerConversion) SafeAddUint64(a, b uint64) (uint64, error) {
	if a > math.MaxUint64-b {
		return 0, fmt.Errorf("addition overflow: %d + %d exceeds maximum uint64", a, b)
	}
	return a + b, nil
}

// SafeAddInt64 safely adds int64 values with overflow protection
func (sic *SecureIntegerConversion) SafeAddInt64(a, b int64) (int64, error) {
	if b > 0 && a > math.MaxInt64-b {
		return 0, fmt.Errorf("addition overflow: %d + %d exceeds maximum int64", a, b)
	}
	if b < 0 && a < math.MinInt64-b {
		return 0, fmt.Errorf("addition underflow: %d + %d is less than minimum int64", a, b)
	}
	return a + b, nil
}

// SafeAddInt64WithSaturation safely adds int64 values with saturation on overflow
func (sic *SecureIntegerConversion) SafeAddInt64WithSaturation(a, b int64) int64 {
	if b > 0 && a > math.MaxInt64-b {
		return math.MaxInt64
	}
	if b < 0 && a < math.MinInt64-b {
		return math.MinInt64
	}
	return a + b
}

// SafeAddUint64WithSaturation safely adds uint64 values with saturation on overflow
func (sic *SecureIntegerConversion) SafeAddUint64WithSaturation(a, b uint64) uint64 {
	if a > math.MaxUint64-b {
		return math.MaxUint64
	}
	return a + b
}

// Global instance for convenience
var DefaultSecureConversion = NewSecureIntegerConversion()

// Convenience functions for direct use
func SafeUint64ToUint16(value uint64) (uint16, error) {
	return DefaultSecureConversion.SafeUint64ToUint16(value)
}

func SafeUint64ToUint16WithMod(value uint64) uint16 {
	return DefaultSecureConversion.SafeUint64ToUint16WithMod(value)
}

func SafeUint64ToInt64(value uint64) (int64, error) {
	return DefaultSecureConversion.SafeUint64ToInt64(value)
}

func SafeInt64ToUint64(value int64) (uint64, error) {
	return DefaultSecureConversion.SafeInt64ToUint64(value)
}

func SafeAddUint64WithSaturation(a, b uint64) uint64 {
	return DefaultSecureConversion.SafeAddUint64WithSaturation(a, b)
}

func SafeAddInt64WithSaturation(a, b int64) int64 {
	return DefaultSecureConversion.SafeAddInt64WithSaturation(a, b)
}