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
)

func main() {
	// Parse command line flags
	var interfaceName string
	var themeName string
	var styleName string
	var themeFile string
	var autoTheme bool
	var gradientEnabled bool
	var exportSVGPath string
	var exportPNGPath string
	var pluginFiles string
	var exportThemeName string
	var exportThemePath string
	var translationFile string
	var profileName string
	var visualizationID string
	var dashboardName string
	var fullscreen bool
	var sslKeyPath string
	var sslCertPath string
	var sslKeyLogFile string
	var enableSSLDecrypt bool
	var extractFiles bool
	var extractDir string
	var securityMode bool
	var threatIntelFeeds string
	var maxFileSize int64
	var enableProtocolAnalysis bool
	var protocolFilters string
	flag.StringVar(&interfaceName, "i", "", i18n.T("flag_i_desc"))
	flag.StringVar(&themeName, "theme", "Dark+", i18n.T("flag_theme_desc"))
	flag.StringVar(&themeFile, "theme-file", "", i18n.T("flag_theme_file_desc"))
	flag.BoolVar(&autoTheme, "auto-theme", false, i18n.T("flag_auto_theme_desc"))
	flag.StringVar(&styleName, "style", "Standard", i18n.T("flag_style_desc"))
	flag.BoolVar(&gradientEnabled, "gradient", true, i18n.T("flag_gradient_desc"))
	flag.StringVar(&exportSVGPath, "export-svg", "", i18n.T("flag_export_svg_desc"))
	flag.StringVar(&exportPNGPath, "export-png", "", i18n.T("flag_export_png_desc"))
	flag.StringVar(&pluginFiles, "plugins", "", i18n.T("flag_plugins_desc"))
	flag.StringVar(&exportThemeName, "export-theme", "", i18n.T("flag_export_theme_desc"))
	flag.StringVar(&exportThemePath, "export-theme-file", "", i18n.T("flag_export_theme_file_desc"))
	flag.StringVar(&translationFile, "i18n-file", "", i18n.T("flag_i18n_file_desc"))
	flag.StringVar(&profileName, "profile", "", "Load UI profile on startup")
	flag.StringVar(&visualizationID, "viz", "", "Start with specific visualization (e.g., speedometer, matrix)")
	flag.StringVar(&dashboardName, "dashboard", "", "Start with specific dashboard (e.g., overview, security)")
	flag.BoolVar(&fullscreen, "fullscreen", false, "Start in fullscreen mode")
	
	// Advanced features
	flag.StringVar(&sslKeyPath, "ssl-key", "", "Path to SSL private key for traffic decryption")
	flag.StringVar(&sslCertPath, "ssl-cert", "", "Path to SSL certificate for traffic decryption") 
	flag.StringVar(&sslKeyLogFile, "ssl-keylog", "", "Path to SSL key log file (Chrome/Firefox SSLKEYLOGFILE)")
	flag.BoolVar(&enableSSLDecrypt, "ssl-decrypt", false, "Enable SSL/TLS traffic decryption")
	flag.BoolVar(&extractFiles, "extract-files", false, "Enable real-time file extraction from network traffic")
	flag.StringVar(&extractDir, "extract-dir", "./extracted", "Directory to save extracted files")
	flag.BoolVar(&securityMode, "security-mode", false, "Enable advanced security monitoring and threat detection")
	flag.StringVar(&threatIntelFeeds, "threat-intel", "", "Comma-separated list of threat intelligence feed URLs")
	flag.Int64Var(&maxFileSize, "max-file-size", 50*1024*1024, "Maximum file size for extraction (bytes)")
	flag.BoolVar(&enableProtocolAnalysis, "protocol-analysis", false, "Enable deep protocol analysis for FTP, SSH, POP3, IMAP")
	flag.StringVar(&protocolFilters, "protocol-filters", "ftp,ssh,pop3,imap", "Comma-separated list of protocols to analyze")
	flag.Parse()

	// Load translations if provided
	if translationFile != "" {
		if err := i18n.LoadTranslations(translationFile); err != nil {
			fmt.Printf("Error loading translations file %s: %v\n", translationFile, err)
			os.Exit(1)
		}
	}

	// Auto-detect theme if requested
	if autoTheme {
		themeName = ui.DetectAutoTheme()
	}

	// Check for root/admin privileges
	if os.Geteuid() != 0 {
		fmt.Println(i18n.T("requires_root"))
		fmt.Println(i18n.T("run_as_root"))
		os.Exit(1)
	}

	// Create the network monitor
	networkMonitor := netcap.NewNetworkMonitor()

	// If interface is specified, start capturing
	if interfaceName != "" {
		err := networkMonitor.StartCapture(interfaceName)
		if err != nil {
			fmt.Printf("Error starting capture on %s: %v\n", interfaceName, err)
			os.Exit(1)
		}
	}

	// Load custom themes if provided
	if themeFile != "" {
		if err := ui.LoadThemes(themeFile); err != nil {
			fmt.Printf("Error loading theme file %s: %v\n", themeFile, err)
			os.Exit(1)
		}
	}

	// Export theme if requested
	if exportThemeName != "" {
		if exportThemePath == "" {
			fmt.Println("Please specify --export-theme-file when using --export-theme")
			os.Exit(1)
		}
		if err := ui.ExportTheme(exportThemeName, exportThemePath); err != nil {
			fmt.Printf("Error exporting theme %s: %v\n", exportThemeName, err)
			os.Exit(1)
		}
		fmt.Printf("Exported theme %s to %s\n", exportThemeName, exportThemePath)
		os.Exit(0)
	}

	// Create and run the UI
	userInterface := ui.NewUI(networkMonitor).SetTheme(themeName).SetStyle(styleName).SetGradientEnabled(gradientEnabled)
	
	// Load profile if specified
	if profileName != "" {
		if err := userInterface.LoadProfile(profileName); err != nil {
			fmt.Printf("Warning: Could not load profile %s: %v\n", profileName, err)
		}
	}
	
	// Set startup mode
	if visualizationID != "" {
		userInterface.SetStartupVisualization(visualizationID, fullscreen)
	} else if dashboardName != "" {
		userInterface.SetStartupDashboard(dashboardName, fullscreen)
	}

	// Load plugins
	if pluginFiles != "" {
		for _, ppath := range strings.Split(pluginFiles, ",") {
			plug, err := plugin.Load(ppath)
			if err != nil {
				fmt.Printf("Error loading plugin %s: %v\n", ppath, err)
				os.Exit(1)
			}
			if err := plug.Init(networkMonitor); err != nil {
				fmt.Printf("Error initializing plugin %s: %v\n", ppath, err)
				os.Exit(1)
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
	}

	// Handle export flags
	if exportSVGPath != "" {
		if err := userInterface.ExportSVG(exportSVGPath); err != nil {
			fmt.Printf("Error exporting SVG: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	if exportPNGPath != "" {
		if err := userInterface.ExportPNG(exportPNGPath); err != nil {
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
