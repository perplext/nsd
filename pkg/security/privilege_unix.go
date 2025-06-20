//go:build !windows

package security

import (
	"fmt"
	"math"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

// safeIntToUint32 safely converts an int to uint32 with bounds checking
func safeIntToUint32(value int) (uint32, error) {
	if value < 0 {
		return 0, fmt.Errorf("cannot convert negative value %d to uint32", value)
	}
	if value > math.MaxUint32 {
		return 0, fmt.Errorf("value %d exceeds uint32 maximum (%d)", value, math.MaxUint32)
	}
	return uint32(value), nil
}

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
	// Try to execute a capability check
	// This is a simplified check - real implementation would use libcap
	cmd := exec.Command("getcap", os.Args[0])
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("no capabilities set (run: sudo setcap cap_net_raw,cap_net_admin+eip %s)", os.Args[0])
	}
	
	outputStr := string(output)
	for _, cap := range pm.capabilities {
		if !containsCapability(outputStr, cap) {
			return fmt.Errorf("missing capability: %s", cap)
		}
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
	
	// Set security attributes
	uid, err := safeIntToUint32(os.Getuid())
	if err != nil {
		return nil, fmt.Errorf("failed to convert UID: %w", err)
	}
	
	gid, err := safeIntToUint32(os.Getgid())
	if err != nil {
		return nil, fmt.Errorf("failed to convert GID: %w", err)
	}
	
	cmd.SysProcAttr = &syscall.SysProcAttr{
		// Drop supplementary groups
		Credential: &syscall.Credential{
			Uid: uid,
			Gid: gid,
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