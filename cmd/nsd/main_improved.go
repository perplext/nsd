//go:build improved
// +build improved

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	
	"github.com/perplext/nsd/pkg/errors"
	"github.com/perplext/nsd/pkg/netcap"
	"github.com/perplext/nsd/pkg/plugin"
	"github.com/perplext/nsd/pkg/ui"
	"github.com/perplext/nsd/pkg/ui/i18n"
)

// Config holds all configuration options
type Config struct {
	// Network options
	InterfaceName    string
	FilterExpression string
	
	// UI options
	ThemeName       string
	StyleName       string
	ThemeFile       string
	AutoTheme       bool
	GradientEnabled bool
	
	// Export options
	ExportSVGPath   string
	ExportPNGPath   string
	ExportThemeName string
	ExportThemePath string
	
	// Plugin options
	PluginFiles string
	
	// Localization
	TranslationFile string
	
	// Advanced options
	ProfileName      string
	VisualizationID  string
	DashboardName    string
	Fullscreen       bool
	ListInterfaces   bool
	ValidateConfig   bool
	Debug            bool
}

// parseFlags parses command line flags into Config
func parseFlags() (*Config, error) {
	cfg := &Config{}
	
	// Define flags
	flag.StringVar(&cfg.InterfaceName, "i", "", i18n.T("flag_i_desc"))
	flag.StringVar(&cfg.FilterExpression, "f", "", "BPF filter expression")
	flag.StringVar(&cfg.ThemeName, "theme", "Dark+", i18n.T("flag_theme_desc"))
	flag.StringVar(&cfg.ThemeFile, "theme-file", "", i18n.T("flag_theme_file_desc"))
	flag.BoolVar(&cfg.AutoTheme, "auto-theme", false, i18n.T("flag_auto_theme_desc"))
	flag.StringVar(&cfg.StyleName, "style", "Standard", i18n.T("flag_style_desc"))
	flag.BoolVar(&cfg.GradientEnabled, "gradient", true, i18n.T("flag_gradient_desc"))
	flag.StringVar(&cfg.ExportSVGPath, "export-svg", "", i18n.T("flag_export_svg_desc"))
	flag.StringVar(&cfg.ExportPNGPath, "export-png", "", i18n.T("flag_export_png_desc"))
	flag.StringVar(&cfg.PluginFiles, "plugins", "", i18n.T("flag_plugins_desc"))
	flag.StringVar(&cfg.ExportThemeName, "export-theme", "", i18n.T("flag_export_theme_desc"))
	flag.StringVar(&cfg.ExportThemePath, "export-theme-file", "", i18n.T("flag_export_theme_file_desc"))
	flag.StringVar(&cfg.TranslationFile, "i18n-file", "", i18n.T("flag_i18n_file_desc"))
	flag.StringVar(&cfg.ProfileName, "profile", "", "Load UI profile on startup")
	flag.StringVar(&cfg.VisualizationID, "viz", "", "Start with specific visualization")
	flag.StringVar(&cfg.DashboardName, "dashboard", "", "Start with specific dashboard")
	flag.BoolVar(&cfg.Fullscreen, "fullscreen", false, "Start in fullscreen mode")
	flag.BoolVar(&cfg.ListInterfaces, "list-interfaces", false, "List available network interfaces")
	flag.BoolVar(&cfg.ValidateConfig, "validate-config", false, "Validate configuration and exit")
	flag.BoolVar(&cfg.Debug, "debug", false, "Enable debug logging")
	
	flag.Parse()
	
	// Validate flags
	if cfg.ExportThemeName != "" && cfg.ExportThemePath == "" {
		return nil, errors.WrapConfigError("export-theme", cfg.ExportThemeName, 
			fmt.Errorf("--export-theme-file required when using --export-theme"))
	}
	
	return cfg, nil
}

// runImproved is the improved main function with error handling
func runImproved() error {
	// Set up error handling
	setupErrorHandling()
	
	// Parse configuration
	cfg, err := parseFlags()
	if err != nil {
		return errors.WrapConfigError("flags", nil, err)
	}
	
	// Load translations if provided
	if cfg.TranslationFile != "" {
		if err := i18n.LoadTranslations(cfg.TranslationFile); err != nil {
			return errors.WrapConfigError("translation", cfg.TranslationFile, err)
		}
	}
	
	// Handle special modes
	if cfg.ListInterfaces {
		return listInterfaces()
	}
	
	if cfg.ExportThemeName != "" {
		return exportTheme(cfg.ExportThemeName, cfg.ExportThemePath)
	}
	
	// Validate environment
	if err := validateEnvironment(); err != nil {
		return err
	}
	
	// Check privileges
	if err := checkPrivileges(); err != nil {
		return err
	}
	
	// Auto-detect theme if requested
	if cfg.AutoTheme {
		cfg.ThemeName = ui.DetectAutoTheme()
	}
	
	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	
	// Create network monitor with improved error handling
	monitor := netcap.NewImprovedNetworkMonitor()
	
	// Start capture if interface specified
	if cfg.InterfaceName != "" {
		// Validate and set filter if provided
		if cfg.FilterExpression != "" {
			if err := netcap.ValidateBPFFilter(cfg.FilterExpression); err != nil {
				return errors.WrapNetworkError(cfg.InterfaceName, "validate filter", err)
			}
			monitor.SetFilter(cfg.FilterExpression)
		}
		
		// Start capture with validation
		if err := monitor.StartCaptureWithValidation(cfg.InterfaceName); err != nil {
			return err
		}
		
		defer func() {
			// Graceful shutdown
			if err := monitor.StopAllCapturesGracefully(5 * time.Second); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
			}
		}()
	}
	
	// Load custom themes if provided
	if cfg.ThemeFile != "" {
		if err := ui.LoadThemes(cfg.ThemeFile); err != nil {
			return errors.WrapConfigError("theme-file", cfg.ThemeFile, err)
		}
	}
	
	// Load plugins with error recovery
	if cfg.PluginFiles != "" {
		if err := loadPluginsSafe(cfg.PluginFiles); err != nil {
			// Don't fail completely on plugin errors
			fmt.Fprintf(os.Stderr, "Warning: Plugin loading failed: %v\n", err)
		}
	}
	
	// Create UI with error handler
	uiConfig := &ui.Config{
		Theme:          cfg.ThemeName,
		Style:          cfg.StyleName,
		Gradient:       cfg.GradientEnabled,
		ProfileName:    cfg.ProfileName,
		Visualization:  cfg.VisualizationID,
		Dashboard:      cfg.DashboardName,
		Fullscreen:     cfg.Fullscreen,
		Debug:          cfg.Debug,
	}
	
	userInterface, err := ui.NewUIWithConfig(monitor.NetworkMonitor, uiConfig)
	if err != nil {
		return errors.WrapUIError("main", "create UI", err)
	}
	
	// Run UI in goroutine
	uiDone := make(chan error, 1)
	go func() {
		uiDone <- userInterface.Run()
	}()
	
	// Wait for shutdown signal or UI exit
	select {
	case <-sigChan:
		fmt.Println("\nShutting down...")
		userInterface.Stop()
		<-uiDone
		
	case err := <-uiDone:
		if err != nil {
			return errors.WrapUIError("main", "UI runtime", err)
		}
	}
	
	return nil
}

// checkPrivileges checks if the user has necessary privileges
func checkPrivileges() error {
	if os.Geteuid() != 0 {
		return errors.ErrPermissionDenied
	}
	return nil
}

// listInterfaces lists available network interfaces
func listInterfaces() error {
	interfaces, err := netcap.GetInterfaces()
	if err != nil {
		return errors.WrapNetworkError("", "list interfaces", err)
	}
	
	fmt.Println("Available network interfaces:")
	for _, iface := range interfaces {
		status := "down"
		if iface.Flags&0x1 != 0 { // IFF_UP
			status = "up"
		}
		fmt.Printf("  %s (%s)\n", iface.Name, status)
		for _, addr := range iface.Addresses {
			fmt.Printf("    %s\n", addr.IP)
		}
	}
	
	return nil
}

// exportTheme exports a theme to a file
func exportTheme(name, path string) error {
	if err := ui.ExportTheme(name, path); err != nil {
		return errors.WrapConfigError("export-theme", name, err)
	}
	fmt.Printf("Exported theme %s to %s\n", name, path)
	return nil
}

// loadPluginsSafe loads plugins with error recovery
func loadPluginsSafe(pluginFiles string) error {
	files := strings.Split(pluginFiles, ",")
	loader := plugin.NewLoader()
	
	var loadErrors []error
	for _, file := range files {
		file = strings.TrimSpace(file)
		if file == "" {
			continue
		}
		
		if err := loader.LoadPlugin(file); err != nil {
			loadErrors = append(loadErrors, fmt.Errorf("plugin %s: %w", file, err))
		} else {
			fmt.Printf("Loaded plugin: %s\n", file)
		}
	}
	
	if len(loadErrors) > 0 {
		return fmt.Errorf("plugin loading errors: %v", loadErrors)
	}
	
	return nil
}

// improved main function
func mainImproved() {
	if err := runImproved(); err != nil {
		handleStartupError("runtime", err)
	}
}