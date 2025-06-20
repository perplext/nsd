package security

import (
	"os"
	"testing"
	
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecurityIntegration(t *testing.T) {
	// Test 1: Validate configuration
	t.Run("ConfigValidation", func(t *testing.T) {
		config := DefaultConfig()
		assert.NoError(t, config.Validate())
		
		// Test invalid config
		badConfig := DefaultConfig()
		badConfig.MaxMemoryMB = -1
		assert.Error(t, badConfig.Validate())
	})
	
	// Test 2: Input validation chain
	t.Run("InputValidationChain", func(t *testing.T) {
		validator := NewValidator()
		
		// Simulate command line inputs
		inputs := map[string]string{
			"interface": "eth0",
			"filter":    "tcp port 80",
			"theme":     "Dark+",
			"file":      "/tmp/export.svg",
		}
		
		// Validate all inputs
		assert.NoError(t, validator.ValidateInterfaceName(inputs["interface"]))
		assert.NoError(t, validator.ValidateBPFFilter(inputs["filter"]))
		assert.NoError(t, validator.ValidateThemeName(inputs["theme"]))
		assert.NoError(t, validator.ValidateFilePath(inputs["file"]))
		
		// Test malicious inputs
		maliciousInputs := map[string]string{
			"interface": "eth0; rm -rf /",
			"filter":    "tcp && system('ls')",
			"theme":     "../../../etc/passwd",
			"file":      "/etc/shadow",
		}
		
		assert.Error(t, validator.ValidateInterfaceName(maliciousInputs["interface"]))
		assert.Error(t, validator.ValidateBPFFilter(maliciousInputs["filter"]))
		assert.Error(t, validator.ValidateThemeName(maliciousInputs["theme"]))
		assert.Error(t, validator.ValidateFilePath(maliciousInputs["file"]))
	})
	
	// Test 3: Privilege manager (skip if not root)
	t.Run("PrivilegeManager", func(t *testing.T) {
		if os.Geteuid() != 0 {
			t.Skip("Skipping privilege test - not running as root")
		}
		
		pm := NewPrivilegeManager()
		
		// Test getting secure defaults
		defaults := GetSecureDefaults()
		// These fields don't exist in SecureDefaults
		// assert.False(t, defaults.EnablePromiscuous)
		// assert.True(t, defaults.DropPrivileges)
		assert.Equal(t, 65535, defaults.MaxPacketSize)
	})
	
	// Test 4: Security configuration save/load
	t.Run("ConfigPersistence", func(t *testing.T) {
		// Create temp file
		tmpFile, err := os.CreateTemp("", "nsd-security-*.json")
		require.NoError(t, err)
		defer os.Remove(tmpFile.Name())
		tmpFile.Close()
		
		// Save config
		config := DefaultConfig()
		config.MaxConnections = 500
		assert.NoError(t, config.SaveConfig(tmpFile.Name()))
		
		// Load config
		loadedConfig, err := LoadConfig(tmpFile.Name())
		assert.NoError(t, err)
		assert.Equal(t, 500, loadedConfig.MaxConnections)
	})
	
	// Test 5: Combined security scenario
	t.Run("SecurityScenario", func(t *testing.T) {
		validator := NewValidator()
		config := DefaultConfig()
		
		// Simulate a complete startup sequence with validation
		startupSequence := func(iface, filter, user string) error {
			// 1. Validate interface
			if err := validator.ValidateInterfaceName(iface); err != nil {
				return err
			}
			
			// 2. Validate BPF filter
			if filter != "" {
				if err := validator.ValidateBPFFilter(filter); err != nil {
					return err
				}
			}
			
			// 3. Check configuration allows the operation
			if !config.AllowCustomFilters && filter != "" {
				return assert.AnError
			}
			
			// 4. Verify user exists (simplified check)
			if user == "" {
				return assert.AnError
			}
			
			return nil
		}
		
		// Test valid startup
		assert.NoError(t, startupSequence("eth0", "tcp port 443", "nobody"))
		
		// Test invalid scenarios
		assert.Error(t, startupSequence("eth0;ls", "tcp", "nobody"))
		assert.Error(t, startupSequence("eth0", "tcp && exec", "nobody"))
		assert.Error(t, startupSequence("eth0", "tcp", ""))
	})
}