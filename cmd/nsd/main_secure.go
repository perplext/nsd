package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"strings"
	"time"

	"github.com/user/nsd/pkg/netcap"
	"github.com/user/nsd/pkg/ui"
	"github.com/user/nsd/pkg/plugin"
	"github.com/user/nsd/pkg/ui/i18n"
	"github.com/user/nsd/pkg/security"
)

// Configuration holds validated application settings
type Configuration struct {
	InterfaceName      string
	ThemeName         string
	StyleName         string
	ThemeFile         string
	AutoTheme         bool
	GradientEnabled   bool
	ExportSVGPath     string
	ExportPNGPath     string
	PluginFiles       []string
	ExportThemeName   string
	ExportThemePath   string
	TranslationFile   string
	ProfileName       string
	VisualizationID   string
	DashboardName     string
	Fullscreen        bool
	DropPrivileges    bool
	UnprivilegedUser  string
	BPFFilter         string
}

func parseAndValidateFlags() (*Configuration, error) {
	config := &Configuration{}
	validator := security.NewValidator()
	
	// Parse command line flags
	var pluginFiles string
	var bpfFilter string
	var dropPrivs bool
	var unprivUser string
	
	flag.StringVar(&config.InterfaceName, "i", "", i18n.T("flag_i_desc"))
	flag.StringVar(&config.ThemeName, "theme", "Dark+", i18n.T("flag_theme_desc"))
	flag.StringVar(&config.ThemeFile, "theme-file", "", i18n.T("flag_theme_file_desc"))
	flag.BoolVar(&config.AutoTheme, "auto-theme", false, i18n.T("flag_auto_theme_desc"))
	flag.StringVar(&config.StyleName, "style", "Standard", i18n.T("flag_style_desc"))
	flag.BoolVar(&config.GradientEnabled, "gradient", true, i18n.T("flag_gradient_desc"))
	flag.StringVar(&config.ExportSVGPath, "export-svg", "", i18n.T("flag_export_svg_desc"))
	flag.StringVar(&config.ExportPNGPath, "export-png", "", i18n.T("flag_export_png_desc"))
	flag.StringVar(&pluginFiles, "plugins", "", i18n.T("flag_plugins_desc"))
	flag.StringVar(&config.ExportThemeName, "export-theme", "", i18n.T("flag_export_theme_desc"))
	flag.StringVar(&config.ExportThemePath, "export-theme-file", "", i18n.T("flag_export_theme_file_desc"))
	flag.StringVar(&config.TranslationFile, "i18n-file", "", i18n.T("flag_i18n_file_desc"))
	flag.StringVar(&config.ProfileName, "profile", "", "Load UI profile on startup")
	flag.StringVar(&config.VisualizationID, "viz", "", "Start with specific visualization")
	flag.StringVar(&config.DashboardName, "dashboard", "", "Start with specific dashboard")
	flag.BoolVar(&config.Fullscreen, "fullscreen", false, "Start in fullscreen mode")
	flag.StringVar(&bpfFilter, "filter", "", "BPF filter expression")
	flag.BoolVar(&dropPrivs, "drop-privileges", true, "Drop privileges after initialization")
	flag.StringVar(&unprivUser, "user", "nobody", "User to drop privileges to")
	flag.Parse()
	
	config.DropPrivileges = dropPrivs
	config.UnprivilegedUser = unprivUser
	config.BPFFilter = bpfFilter
	
	// Validate all inputs
	if config.InterfaceName != "" {
		if err := validator.ValidateInterfaceName(config.InterfaceName); err != nil {
			return nil, fmt.Errorf("invalid interface name: %w", err)
		}
	}
	
	if config.ThemeFile != "" {
		if err := validator.ValidateFilePath(config.ThemeFile); err != nil {
			return nil, fmt.Errorf("invalid theme file path: %w", err)
		}
	}
	
	if config.TranslationFile != "" {
		if err := validator.ValidateFilePath(config.TranslationFile); err != nil {
			return nil, fmt.Errorf("invalid translation file path: %w", err)
		}
	}
	
	if config.ExportSVGPath != "" {
		if err := validator.ValidateFilePath(config.ExportSVGPath); err != nil {
			return nil, fmt.Errorf("invalid SVG export path: %w", err)
		}
	}
	
	if config.ExportPNGPath != "" {
		if err := validator.ValidateFilePath(config.ExportPNGPath); err != nil {
			return nil, fmt.Errorf("invalid PNG export path: %w", err)
		}
	}
	
	if config.ExportThemePath != "" {
		if err := validator.ValidateFilePath(config.ExportThemePath); err != nil {
			return nil, fmt.Errorf("invalid theme export path: %w", err)
		}
	}
	
	if config.BPFFilter != "" {
		if err := validator.ValidateBPFFilter(config.BPFFilter); err != nil {
			return nil, fmt.Errorf("invalid BPF filter: %w", err)
		}
	}
	
	// Validate and split plugin files
	if pluginFiles != "" {
		config.PluginFiles = strings.Split(pluginFiles, ",")
		for _, ppath := range config.PluginFiles {
			if err := validator.ValidateFilePath(ppath); err != nil {
				return nil, fmt.Errorf("invalid plugin path %s: %w", ppath, err)
			}
		}
	}
	
	// Validate theme name
	if err := validator.ValidateThemeName(config.ThemeName); err != nil {
		return nil, fmt.Errorf("invalid theme name: %w", err)
	}
	
	return config, nil
}

func main() {
	// Parse and validate configuration
	config, err := parseAndValidateFlags()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Configuration error: %v\n", err)
		os.Exit(1)
	}
	
	// Load translations if provided
	if config.TranslationFile != "" {
		if err := i18n.LoadTranslations(config.TranslationFile); err != nil {
			fmt.Printf("Error loading translations file %s: %v\n", config.TranslationFile, err)
			os.Exit(1)
		}
	}
	
	// Auto-detect theme if requested
	if config.AutoTheme {
		config.ThemeName = ui.DetectAutoTheme()
	}
	
	// Check for root/admin privileges
	if os.Geteuid() != 0 {
		fmt.Println(i18n.T("requires_root"))
		fmt.Println(i18n.T("run_as_root"))
		os.Exit(1)
	}
	
	// Initialize privilege manager
	privManager := security.NewPrivilegeManager()
	
	// Create the network monitor with security controls
	networkMonitor := netcap.NewNetworkMonitor()
	
	// If interface is specified, start capturing
	if config.InterfaceName != "" {
		// Apply BPF filter if provided
		if config.BPFFilter != "" {
			networkMonitor.SetBPFFilter(config.BPFFilter)
		}
		
		err := networkMonitor.StartCapture(config.InterfaceName)
		if err != nil {
			fmt.Printf("Error starting capture on %s: %v\n", config.InterfaceName, err)
			os.Exit(1)
		}
	}
	
	// Drop privileges after initialization if requested
	if config.DropPrivileges && os.Geteuid() == 0 {
		if err := privManager.DropPrivileges(config.UnprivilegedUser); err != nil {
			fmt.Printf("Warning: Could not drop privileges: %v\n", err)
			// Continue running but log the warning
		} else {
			fmt.Printf("Successfully dropped privileges to user: %s\n", config.UnprivilegedUser)
		}
	}
	
	// Load custom themes if provided
	if config.ThemeFile != "" {
		if err := ui.LoadThemes(config.ThemeFile); err != nil {
			fmt.Printf("Error loading theme file %s: %v\n", config.ThemeFile, err)
			os.Exit(1)
		}
	}
	
	// Export theme if requested
	if config.ExportThemeName != "" {
		if config.ExportThemePath == "" {
			fmt.Println("Please specify --export-theme-file when using --export-theme")
			os.Exit(1)
		}
		if err := ui.ExportTheme(config.ExportThemeName, config.ExportThemePath); err != nil {
			fmt.Printf("Error exporting theme %s: %v\n", config.ExportThemeName, err)
			os.Exit(1)
		}
		fmt.Printf("Exported theme %s to %s\n", config.ExportThemeName, config.ExportThemePath)
		os.Exit(0)
	}
	
	// Create and run the UI
	userInterface := ui.NewUI(networkMonitor).
		SetTheme(config.ThemeName).
		SetStyle(config.StyleName).
		SetGradientEnabled(config.GradientEnabled)
	
	// Load profile if specified
	if config.ProfileName != "" {
		if err := userInterface.LoadProfile(config.ProfileName); err != nil {
			fmt.Printf("Warning: Could not load profile %s: %v\n", config.ProfileName, err)
		}
	}
	
	// Set startup mode
	if config.VisualizationID != "" {
		userInterface.SetStartupVisualization(config.VisualizationID, config.Fullscreen)
	} else if config.DashboardName != "" {
		userInterface.SetStartupDashboard(config.DashboardName, config.Fullscreen)
	}
	
	// Load plugins with validation
	for _, ppath := range config.PluginFiles {
		// Validate plugin path
		validator := security.NewValidator()
		if err := validator.ValidateFilePath(ppath); err != nil {
			fmt.Printf("Error: invalid plugin path %s: %v\n", ppath, err)
			continue
		}
		
		plug, err := plugin.Load(ppath)
		if err != nil {
			fmt.Printf("Error loading plugin %s: %v\n", ppath, err)
			continue // Don't exit, just skip this plugin
		}
		
		if err := plug.Init(networkMonitor); err != nil {
			fmt.Printf("Error initializing plugin %s: %v\n", ppath, err)
			continue
		}
		
		fmt.Printf("Loaded plugin: %s\n", plug.Name())
		
		// Register plugin with UI
		description := "No description available"
		if uiHandler, ok := plug.(plugin.UIHandler); ok {
			description = uiHandler.GetDescription()
		}
		userInterface.RegisterPlugin(plug.Name(), description)
		
		// Start goroutine to update plugin output in UI
		if uiHandler, ok := plug.(plugin.UIHandler); ok {
			go func(name string, handler plugin.UIHandler) {
				for {
					time.Sleep(5 * time.Second)
					output := handler.GetOutput()
					if len(output) > 0 {
						// Update UI with latest output
						for _, line := range output {
							userInterface.UpdatePluginOutput(name, line)
						}
					}
				}
			}(plug.Name(), uiHandler)
		}
	}
	
	// Handle export flags
	if config.ExportSVGPath != "" {
		if err := userInterface.ExportSVG(config.ExportSVGPath); err != nil {
			fmt.Printf("Error exporting SVG: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	if config.ExportPNGPath != "" {
		if err := userInterface.ExportPNG(config.ExportPNGPath); err != nil {
			fmt.Printf("Error exporting PNG: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	
	// Handle termination signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	
	go func() {
		<-sigChan
		userInterface.Stop()
	}()
	
	// Run the UI (this blocks until the UI is closed)
	if err := userInterface.Run(); err != nil {
		fmt.Printf("Error running UI: %v\n", err)
		os.Exit(1)
	}
}