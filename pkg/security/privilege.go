package security

import (
	"os"
	"runtime"
)

// PrivilegeManager handles privilege separation and dropping
type PrivilegeManager struct {
	originalUID  int
	originalGID  int
	targetUID    int
	targetGID    int
	capabilities []string
}

// NewPrivilegeManager creates a new privilege manager
func NewPrivilegeManager() *PrivilegeManager {
	return &PrivilegeManager{
		originalUID: os.Getuid(),
		originalGID: os.Getgid(),
		capabilities: []string{"CAP_NET_RAW", "CAP_NET_ADMIN"},
	}
}

// DropPrivileges drops root privileges after setup
// Implementation is platform-specific and found in privilege_unix.go and privilege_windows.go

// SetupCapabilities sets Linux capabilities for packet capture
func (pm *PrivilegeManager) SetupCapabilities() error {
	if runtime.GOOS != "linux" {
		return nil
	}
	
	// This would require libcap bindings
	// For now, we'll document the required command:
	// setcap cap_net_raw,cap_net_admin+eip /path/to/nsd
	
	return nil
}

// CheckPrivileges checks if we have necessary privileges
// Implementation is platform-specific and found in privilege_unix.go and privilege_windows.go



// Sandbox provides process sandboxing
type Sandbox struct {
	workDir       string
	allowedPaths  []string
	deniedPaths   []string
	resourceLimits map[string]uint64
}

// NewSandbox creates a new sandbox
func NewSandbox(workDir string) *Sandbox {
	return &Sandbox{
		workDir: workDir,
		allowedPaths: []string{
			workDir,
			"/tmp",
			"/var/tmp",
		},
		deniedPaths: []string{
			"/etc",
			"/sys",
			"/proc",
			"/root",
			"/home",
		},
		resourceLimits: map[string]uint64{
			"RLIMIT_NOFILE": 1024,     // Max open files
			"RLIMIT_NPROC":  100,      // Max processes
			"RLIMIT_AS":     1 << 30,  // Max memory (1GB)
		},
	}
}

// Enter enters the sandbox
// Implementation is platform-specific and found in privilege_unix.go and privilege_windows.go

// setResourceLimits sets process resource limits
// Implementation is platform-specific and found in privilege_unix.go and privilege_windows.go

// SecureExec provides secure command execution
type SecureExec struct {
	validator      *Validator
	allowedCmds    map[string]bool
	environmentVars []string
}

// NewSecureExec creates a new secure executor
// Implementation is platform-specific and found in privilege_unix.go and privilege_windows.go

// Execute runs a command securely
// Implementation is platform-specific and found in privilege_unix.go and privilege_windows.go

// SecureDefaults provides secure default configurations
type SecureDefaults struct {
	// Network settings
	MaxConnections      int
	ConnectionTimeout   int
	MaxPacketSize       int
	
	// File settings
	MaxFileSize         int64
	AllowedFileTypes    []string
	
	// UI settings
	MaxUIRefreshRate    int
	DisableAutoConnect  bool
	
	// Security settings
	RequireAuth         bool
	EncryptStorage      bool
	SecureMode          bool
}

// GetSecureDefaults returns secure default settings
func GetSecureDefaults() *SecureDefaults {
	return &SecureDefaults{
		// Conservative network limits
		MaxConnections:    1000,
		ConnectionTimeout: 30,
		MaxPacketSize:     65535,
		
		// File restrictions
		MaxFileSize:      100 * 1024 * 1024, // 100MB
		AllowedFileTypes: []string{".json", ".yaml", ".yml", ".conf"},
		
		// UI safety
		MaxUIRefreshRate:   10, // Hz
		DisableAutoConnect: true,
		
		// Security first
		RequireAuth:    false, // Would be true in production
		EncryptStorage: false, // Would be true for sensitive data
		SecureMode:     true,  // Restrictive by default
	}
}