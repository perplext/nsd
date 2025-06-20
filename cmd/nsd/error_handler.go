package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"runtime"
	"runtime/debug"
	
	pkgerrors "github.com/perplext/nsd/pkg/errors"
)

// setupErrorHandling configures global error handling
func setupErrorHandling() {
	// Set up panic recovery
	defer func() {
		if r := recover(); r != nil {
			handlePanic(r)
		}
	}()
	
	// Configure logging
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	
	// Set up custom panic handler
	debug.SetPanicOnFault(true)
}

// handlePanic handles panics gracefully
func handlePanic(r interface{}) {
	// Log panic details
	log.Printf("PANIC: %v\n", r)
	log.Printf("Stack trace:\n%s", debug.Stack())
	
	// Try to save state if possible
	saveEmergencyState()
	
	// Exit with error code
	os.Exit(2)
}

// handleStartupError handles errors during startup
func handleStartupError(phase string, err error) {
	if err == nil {
		return
	}
	
	// Format error message based on type
	var message string
	switch {
	case errors.Is(err, pkgerrors.ErrPermissionDenied):
		message = fmt.Sprintf("Permission denied during %s. Please run as root/administrator.", phase)
	case errors.Is(err, pkgerrors.ErrInterfaceNotFound):
		message = fmt.Sprintf("Network interface not found during %s. Please check the interface name.", phase)
	case errors.Is(err, pkgerrors.ErrInvalidConfig):
		message = fmt.Sprintf("Invalid configuration during %s: %v", phase, err)
	case errors.Is(err, pkgerrors.ErrPluginLoadFailed):
		message = fmt.Sprintf("Failed to load plugin during %s: %v", phase, err)
	default:
		message = fmt.Sprintf("Error during %s: %v", phase, err)
	}
	
	fmt.Fprintf(os.Stderr, "Error: %s\n", message)
	
	// Provide helpful suggestions
	suggestRecovery(phase, err)
	
	os.Exit(1)
}

// suggestRecovery provides recovery suggestions based on the error
func suggestRecovery(phase string, err error) {
	fmt.Fprintln(os.Stderr, "\nSuggestions:")
	
	switch {
	case errors.Is(err, pkgerrors.ErrPermissionDenied):
		fmt.Fprintln(os.Stderr, "  - Run with sudo or as administrator")
		fmt.Fprintln(os.Stderr, "  - Check if the binary has the necessary capabilities")
		
	case errors.Is(err, pkgerrors.ErrInterfaceNotFound):
		fmt.Fprintln(os.Stderr, "  - List available interfaces with: nsd --list-interfaces")
		fmt.Fprintln(os.Stderr, "  - Use -i flag to specify an interface")
		
	case errors.Is(err, pkgerrors.ErrInvalidConfig):
		fmt.Fprintln(os.Stderr, "  - Check your configuration file syntax")
		fmt.Fprintln(os.Stderr, "  - Run with --validate-config to check configuration")
		
	case errors.Is(err, pkgerrors.ErrPluginLoadFailed):
		fmt.Fprintln(os.Stderr, "  - Verify the plugin file exists and is readable")
		fmt.Fprintln(os.Stderr, "  - Ensure the plugin was compiled with the same Go version")
		fmt.Fprintln(os.Stderr, "  - Check plugin compatibility with --plugin-info")
	}
}

// saveEmergencyState tries to save application state during a crash
func saveEmergencyState() {
	// Try to create crash dump file
	crashFile := fmt.Sprintf("nsd_crash_%d.log", os.Getpid())
	
	f, err := os.Create(crashFile)
	if err != nil {
		log.Printf("Failed to create crash file: %v", err)
		return
	}
	defer f.Close()
	
	// Write crash information
	fmt.Fprintf(f, "NetMon Crash Report\n")
	fmt.Fprintf(f, "Time: %s\n", log.Flags())
	fmt.Fprintf(f, "Stack:\n%s\n", debug.Stack())
	
	log.Printf("Crash information saved to %s", crashFile)
}

// validateEnvironment checks if the environment is suitable for running
func validateEnvironment() error {
	// Check OS support
	switch runtime.GOOS {
	case "linux", "darwin", "windows":
		// Supported
	default:
		return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
	
	// Check for required capabilities on Linux
	if runtime.GOOS == "linux" {
		if os.Geteuid() != 0 {
			// Check for CAP_NET_RAW capability
			// This is a simplified check - real implementation would use libcap
			return pkgerrors.ErrPermissionDenied
		}
	}
	
	return nil
}