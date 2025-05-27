package security

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Config holds security configuration settings
type Config struct {
	// Privilege settings
	DropPrivileges   bool   `json:"drop_privileges" yaml:"drop_privileges"`
	UnprivilegedUser string `json:"unprivileged_user" yaml:"unprivileged_user"`
	
	// Network capture settings
	MaxPacketSize      int           `json:"max_packet_size" yaml:"max_packet_size"`
	CaptureTimeout     time.Duration `json:"capture_timeout" yaml:"capture_timeout"`
	EnablePromiscuous  bool          `json:"enable_promiscuous" yaml:"enable_promiscuous"`
	AllowedInterfaces  []string      `json:"allowed_interfaces" yaml:"allowed_interfaces"`
	
	// BPF filter settings
	DefaultBPFFilter   string   `json:"default_bpf_filter" yaml:"default_bpf_filter"`
	AllowCustomFilters bool     `json:"allow_custom_filters" yaml:"allow_custom_filters"`
	FilterWhitelist    []string `json:"filter_whitelist" yaml:"filter_whitelist"`
	
	// Plugin settings
	EnablePlugins      bool     `json:"enable_plugins" yaml:"enable_plugins"`
	PluginDirectory    string   `json:"plugin_directory" yaml:"plugin_directory"`
	AllowedPlugins     []string `json:"allowed_plugins" yaml:"allowed_plugins"`
	PluginSandbox      bool     `json:"plugin_sandbox" yaml:"plugin_sandbox"`
	
	// File access settings
	AllowFileExport    bool     `json:"allow_file_export" yaml:"allow_file_export"`
	ExportDirectory    string   `json:"export_directory" yaml:"export_directory"`
	MaxExportSize      int64    `json:"max_export_size" yaml:"max_export_size"`
	AllowedExportTypes []string `json:"allowed_export_types" yaml:"allowed_export_types"`
	
	// UI settings
	AllowThemeFiles    bool     `json:"allow_theme_files" yaml:"allow_theme_files"`
	ThemeDirectory     string   `json:"theme_directory" yaml:"theme_directory"`
	AllowedThemes      []string `json:"allowed_themes" yaml:"allowed_themes"`
	
	// Rate limiting
	EnableRateLimiting bool    `json:"enable_rate_limiting" yaml:"enable_rate_limiting"`
	MaxPacketsPerSec   float64 `json:"max_packets_per_sec" yaml:"max_packets_per_sec"`
	MaxBytesPerSec     float64 `json:"max_bytes_per_sec" yaml:"max_bytes_per_sec"`
	MaxConnections     int     `json:"max_connections" yaml:"max_connections"`
	
	// Logging and auditing
	EnableAuditLog     bool   `json:"enable_audit_log" yaml:"enable_audit_log"`
	AuditLogPath       string `json:"audit_log_path" yaml:"audit_log_path"`
	LogSensitiveData   bool   `json:"log_sensitive_data" yaml:"log_sensitive_data"`
	
	// Resource limits
	MaxMemoryMB        int64   `json:"max_memory_mb" yaml:"max_memory_mb"`
	MaxCPUPercent      float64 `json:"max_cpu_percent" yaml:"max_cpu_percent"`
	MaxGoroutines      int     `json:"max_goroutines" yaml:"max_goroutines"`
}

// DefaultConfig returns a secure default configuration
func DefaultConfig() *Config {
	return &Config{
		// Privilege settings - secure by default
		DropPrivileges:   true,
		UnprivilegedUser: "nobody",
		
		// Network capture settings
		MaxPacketSize:     65535,
		CaptureTimeout:    time.Millisecond,
		EnablePromiscuous: false, // Secure default: no promiscuous mode
		AllowedInterfaces: []string{}, // Empty = all interfaces allowed
		
		// BPF filter settings
		DefaultBPFFilter:   "", // No default filter
		AllowCustomFilters: true,
		FilterWhitelist:    []string{}, // Empty = all filters allowed
		
		// Plugin settings - restrictive by default
		EnablePlugins:   false,
		PluginDirectory: "/usr/local/lib/nsd/plugins",
		AllowedPlugins:  []string{},
		PluginSandbox:   true,
		
		// File access settings - restrictive by default
		AllowFileExport:    false,
		ExportDirectory:    "/tmp/nsd-export",
		MaxExportSize:      10 * 1024 * 1024, // 10MB
		AllowedExportTypes: []string{"svg", "png", "json"},
		
		// UI settings
		AllowThemeFiles: true,
		ThemeDirectory:  "/usr/local/share/nsd/themes",
		AllowedThemes:   []string{}, // Empty = all themes allowed
		
		// Rate limiting - enabled by default
		EnableRateLimiting: true,
		MaxPacketsPerSec:   10000,
		MaxBytesPerSec:     100 * 1024 * 1024, // 100MB/s
		MaxConnections:     1000,
		
		// Logging and auditing
		EnableAuditLog:   true,
		AuditLogPath:     "/var/log/nsd/audit.log",
		LogSensitiveData: false, // Never log sensitive data by default
		
		// Resource limits
		MaxMemoryMB:   512,
		MaxCPUPercent: 50.0,
		MaxGoroutines: 100,
	}
}

// LoadConfig loads security configuration from a file
func LoadConfig(path string) (*Config, error) {
	validator := NewValidator()
	if err := validator.ValidateFilePath(path); err != nil {
		return nil, fmt.Errorf("invalid config path: %w", err)
	}
	
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}
	
	config := DefaultConfig() // Start with defaults
	if err := json.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}
	
	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}
	
	return config, nil
}

// Validate checks if the configuration is valid and secure
func (c *Config) Validate() error {
	validator := NewValidator()
	
	// Validate user
	if c.DropPrivileges && c.UnprivilegedUser == "" {
		return fmt.Errorf("unprivileged user must be specified when dropping privileges")
	}
	
	// Validate directories
	if c.EnablePlugins && c.PluginDirectory != "" {
		if err := validator.ValidateFilePath(c.PluginDirectory); err != nil {
			return fmt.Errorf("invalid plugin directory: %w", err)
		}
	}
	
	if c.AllowFileExport && c.ExportDirectory != "" {
		if err := validator.ValidateFilePath(c.ExportDirectory); err != nil {
			return fmt.Errorf("invalid export directory: %w", err)
		}
	}
	
	if c.AllowThemeFiles && c.ThemeDirectory != "" {
		if err := validator.ValidateFilePath(c.ThemeDirectory); err != nil {
			return fmt.Errorf("invalid theme directory: %w", err)
		}
	}
	
	// Validate resource limits
	if c.MaxMemoryMB <= 0 {
		return fmt.Errorf("max memory must be positive")
	}
	
	if c.MaxCPUPercent <= 0 || c.MaxCPUPercent > 100 {
		return fmt.Errorf("max CPU percent must be between 0 and 100")
	}
	
	if c.MaxGoroutines <= 0 {
		return fmt.Errorf("max goroutines must be positive")
	}
	
	// Validate rate limits
	if c.EnableRateLimiting {
		if c.MaxPacketsPerSec <= 0 {
			return fmt.Errorf("max packets per second must be positive")
		}
		if c.MaxBytesPerSec <= 0 {
			return fmt.Errorf("max bytes per second must be positive")
		}
		if c.MaxConnections <= 0 {
			return fmt.Errorf("max connections must be positive")
		}
	}
	
	// Validate packet size
	if c.MaxPacketSize <= 0 || c.MaxPacketSize > 65535 {
		return fmt.Errorf("max packet size must be between 1 and 65535")
	}
	
	return nil
}

// SaveConfig saves the configuration to a file
func (c *Config) SaveConfig(path string) error {
	validator := NewValidator()
	if err := validator.ValidateFilePath(path); err != nil {
		return fmt.Errorf("invalid config path: %w", err)
	}
	
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}
	
	return nil
}