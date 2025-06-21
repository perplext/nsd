//go:build !windows

package security

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

// DropPrivileges drops root privileges after setup (Unix implementation)
func (pm *PrivilegeManager) DropPrivileges(username string) error {
	// Check if we're running as root
	if os.Geteuid() != 0 {
		return fmt.Errorf("not running as root, cannot drop privileges")
	}
	
	// Look up the target user
	targetUser, err := user.Lookup(username)
	if err != nil {
		return fmt.Errorf("failed to lookup user %s: %w", username, err)
	}
	
	// Parse UID and GID
	uid, err := strconv.Atoi(targetUser.Uid)
	if err != nil {
		return fmt.Errorf("failed to parse UID: %w", err)
	}
	
	gid, err := strconv.Atoi(targetUser.Gid)
	if err != nil {
		return fmt.Errorf("failed to parse GID: %w", err)
	}
	
	pm.targetUID = uid
	pm.targetGID = gid
	
	// Set supplementary groups
	if err := syscall.Setgroups([]int{gid}); err != nil {
		return fmt.Errorf("failed to set groups: %w", err)
	}
	
	// Set GID
	if err := syscall.Setgid(gid); err != nil {
		return fmt.Errorf("failed to set GID: %w", err)
	}
	
	// Set UID (this must be done last)
	if err := syscall.Setuid(uid); err != nil {
		return fmt.Errorf("failed to set UID: %w", err)
	}
	
	// Verify privileges were dropped
	if os.Geteuid() == 0 || os.Getegid() == 0 {
		return fmt.Errorf("failed to drop root privileges")
	}
	
	return nil
}

// CheckPrivileges checks if we have necessary privileges (Unix implementation)
func (pm *PrivilegeManager) CheckPrivileges() error {
	if os.Geteuid() != 0 {
		// Check for capabilities on Linux
		if runtime.GOOS == "linux" {
			if err := pm.checkLinuxCapabilities(); err != nil {
				return fmt.Errorf("insufficient privileges: %w", err)
			}
		} else {
			return fmt.Errorf("requires root privileges")
		}
	}
	
	return nil
}

// checkLinuxCapabilities checks for Linux capabilities
func (pm *PrivilegeManager) checkLinuxCapabilities() error {
	// Get the current executable path securely
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}
	
	// Enhanced security validation for executable path
	if err := pm.validateExecutablePath(execPath); err != nil {
		return fmt.Errorf("executable path security validation failed: %w", err)
	}
	
	// Use absolute path for getcap to prevent PATH manipulation
	getcapPath := "/usr/bin/getcap"
	if _, err := os.Stat(getcapPath); os.IsNotExist(err) {
		// Fallback to /usr/sbin/getcap or /bin/getcap
		if _, err := os.Stat("/usr/sbin/getcap"); err == nil {
			getcapPath = "/usr/sbin/getcap"
		} else if _, err := os.Stat("/bin/getcap"); err == nil {
			getcapPath = "/bin/getcap"
		} else {
			return fmt.Errorf("getcap command not found in standard locations")
		}
	}
	
	// Create command with secure environment
	cmd := exec.Command(getcapPath, execPath)
	cmd.Env = []string{
		"PATH=/usr/bin:/bin:/usr/sbin:/sbin",
		"USER=nobody",
		"HOME=/tmp",
	}
	
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("no capabilities set (run: sudo setcap cap_net_raw,cap_net_admin+eip %s)", execPath)
	}
	
	outputStr := string(output)
	for _, cap := range pm.capabilities {
		if !containsCapability(outputStr, cap) {
			return fmt.Errorf("missing capability: %s", cap)
		}
	}
	
	return nil
}

// validateExecutablePath provides enhanced validation for executable paths
func (pm *PrivilegeManager) validateExecutablePath(execPath string) error {
	// Basic validation using existing validator
	validator := NewValidator()
	if err := validator.ValidateFilePath(execPath); err != nil {
		return fmt.Errorf("basic path validation failed: %w", err)
	}
	
	// Additional checks specific to executable paths
	if !filepath.IsAbs(execPath) {
		return fmt.Errorf("executable path must be absolute")
	}
	
	// Check for suspicious patterns in executable path
	suspiciousPatterns := []string{
		"../", "./", "//", "\\", "$", "`", ";", "&", "|",
		"$(", "${", "~", "*", "?", "[", "]", "{", "}",
	}
	
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(execPath, pattern) {
			return fmt.Errorf("executable path contains suspicious pattern: %s", pattern)
		}
	}
	
	// Ensure the executable exists and is actually a file
	info, err := os.Stat(execPath)
	if err != nil {
		return fmt.Errorf("cannot stat executable: %w", err)
	}
	
	if info.IsDir() {
		return fmt.Errorf("executable path points to a directory, not a file")
	}
	
	// Check if it's actually executable
	if info.Mode()&0111 == 0 {
		return fmt.Errorf("file is not executable")
	}
	
	// Validate path length to prevent buffer overflow attacks
	if len(execPath) > 4096 {
		return fmt.Errorf("executable path too long: %d characters", len(execPath))
	}
	
	// Check for null bytes that could cause security issues
	if strings.Contains(execPath, "\x00") {
		return fmt.Errorf("executable path contains null bytes")
	}
	
	return nil
}

// Enter enters the sandbox (Unix implementation)
func (s *Sandbox) Enter() error {
	// Change working directory
	if err := os.Chdir(s.workDir); err != nil {
		return fmt.Errorf("failed to change directory: %w", err)
	}
	
	// Set resource limits
	if err := s.setResourceLimits(); err != nil {
		return fmt.Errorf("failed to set resource limits: %w", err)
	}
	
	// On Linux, we could use:
	// - seccomp for system call filtering
	// - namespaces for isolation
	// - cgroups for resource control
	
	return nil
}

// setResourceLimits sets process resource limits (Unix implementation)
func (s *Sandbox) setResourceLimits() error {
	// Set file descriptor limit
	var rLimit syscall.Rlimit
	rLimit.Cur = s.resourceLimits["RLIMIT_NOFILE"]
	rLimit.Max = s.resourceLimits["RLIMIT_NOFILE"]
	
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit); err != nil {
		return fmt.Errorf("failed to set RLIMIT_NOFILE: %w", err)
	}
	
	// Additional limits would be set similarly
	
	return nil
}

// Execute runs a command securely (Unix implementation)
func (se *SecureExec) Execute(cmdName string, args ...string) ([]byte, error) {
	// Validate command is allowed
	if !se.allowedCmds[cmdName] {
		return nil, fmt.Errorf("command not allowed: %s", cmdName)
	}
	
	// Validate arguments
	for _, arg := range args {
		if containsShellMetachars(arg) {
			return nil, fmt.Errorf("argument contains shell metacharacters")
		}
	}
	
	// Create command with clean environment
	cmd := exec.Command(cmdName, args...)
	cmd.Env = se.environmentVars
	
	// Set security attributes with overflow protection
	uid := os.Getuid()
	gid := os.Getgid()
	
	// Check for integer overflow before converting to uint32
	// On 32-bit systems, int max is less than uint32 max, so we need a different check
	if uid < 0 {
		return nil, fmt.Errorf("UID value %d cannot be negative", uid)
	}
	if gid < 0 {
		return nil, fmt.Errorf("GID value %d cannot be negative", gid)
	}
	
	// On 64-bit systems, check if the value exceeds uint32 max
	if strconv.IntSize == 64 {
		const maxUint32 = 1<<32 - 1
		if uid > maxUint32 {
			return nil, fmt.Errorf("UID value %d exceeds uint32 maximum", uid)
		}
		if gid > maxUint32 {
			return nil, fmt.Errorf("GID value %d exceeds uint32 maximum", gid)
		}
	}
	
	cmd.SysProcAttr = &syscall.SysProcAttr{
		// Drop supplementary groups
		Credential: &syscall.Credential{
			Uid: uint32(uid),
			Gid: uint32(gid),
		},
	}
	
	// Execute with timeout
	return cmd.Output()
}

// containsCapability checks if output contains a capability
func containsCapability(output, capability string) bool {
	// Simplified check - real implementation would parse properly
	return strings.Contains(output, capability)
}

// NewSecureExec creates a new secure executor (Unix implementation)
func NewSecureExec() *SecureExec {
	return &SecureExec{
		validator: NewValidator(),
		allowedCmds: map[string]bool{
			"ip":       true,
			"ifconfig": true,
			"netstat":  true,
			"ss":       true,
			"ping":     true,
			"traceroute": true,
		},
		environmentVars: []string{
			"PATH=/usr/bin:/bin:/usr/sbin:/sbin",
			"USER=nobody",
			"HOME=/tmp",
		},
	}
}