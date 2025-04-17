package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/user/netmon/pkg/netcap"
	"github.com/user/netmon/pkg/ui"
)

func main() {
	// Parse command line flags
	var interfaceName string
	var themeName string
	flag.StringVar(&interfaceName, "i", "", "Network interface to monitor")
	flag.StringVar(&themeName, "theme", "Dark+", "Color theme to use (Dark+, Light+, Monokai, Solarized Dark, Dracula)")
	flag.Parse()

	// Check for root/admin privileges
	if os.Geteuid() != 0 {
		fmt.Println("This application requires root/administrator privileges to capture packets.")
		fmt.Println("Please run with sudo or as administrator.")
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

	// Create and run the UI
	userInterface := ui.NewUI(networkMonitor).SetTheme(themeName)

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
