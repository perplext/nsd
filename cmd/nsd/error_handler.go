package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"time"
	
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
	
	if _, err := fmt.Fprintf(os.Stderr, "Error: %s\n", message); err != nil {
		// Last resort - try to at least log it
		log.Printf("Failed to write to stderr: %v", err)
	}
	
	// Provide helpful suggestions
	suggestRecovery(phase, err)
	
	os.Exit(1)
}

// suggestRecovery provides recovery suggestions based on the error
func suggestRecovery(phase string, err error) {
	if _, err := fmt.Fprintln(os.Stderr, "\nSuggestions:"); err != nil {
		log.Printf("Failed to write suggestions header: %v", err)
		return
	}
	
	switch {
	case errors.Is(err, pkgerrors.ErrPermissionDenied):
		if _, err := fmt.Fprintln(os.Stderr, "  - Run with sudo or as administrator"); err != nil {
			log.Printf("Failed to write suggestion: %v", err)
		}
		if _, err := fmt.Fprintln(os.Stderr, "  - Check if the binary has the necessary capabilities"); err != nil {
			log.Printf("Failed to write suggestion: %v", err)
		}
		
	case errors.Is(err, pkgerrors.ErrInterfaceNotFound):
		if _, err := fmt.Fprintln(os.Stderr, "  - List available interfaces with: nsd --list-interfaces"); err != nil {
			log.Printf("Failed to write suggestion: %v", err)
		}
		if _, err := fmt.Fprintln(os.Stderr, "  - Use -i flag to specify an interface"); err != nil {
			log.Printf("Failed to write suggestion: %v", err)
		}
		
	case errors.Is(err, pkgerrors.ErrInvalidConfig):
		if _, err := fmt.Fprintln(os.Stderr, "  - Check your configuration file syntax"); err != nil {
			log.Printf("Failed to write suggestion: %v", err)
		}
		if _, err := fmt.Fprintln(os.Stderr, "  - Run with --validate-config to check configuration"); err != nil {
			log.Printf("Failed to write suggestion: %v", err)
		}
		
	case errors.Is(err, pkgerrors.ErrPluginLoadFailed):
		if _, err := fmt.Fprintln(os.Stderr, "  - Verify the plugin file exists and is readable"); err != nil {
			log.Printf("Failed to write suggestion: %v", err)
		}
		if _, err := fmt.Fprintln(os.Stderr, "  - Ensure the plugin was compiled with the same Go version"); err != nil {
			log.Printf("Failed to write suggestion: %v", err)
		}
		if _, err := fmt.Fprintln(os.Stderr, "  - Check plugin compatibility with --plugin-info"); err != nil {
			log.Printf("Failed to write suggestion: %v", err)
		}
	}
}

// saveEmergencyState tries to save application state during a crash
func saveEmergencyState() {
	// Try to create crash dump file in temp directory
	crashFile := filepath.Join(os.TempDir(), fmt.Sprintf("nsd_crash_%d.log", os.Getpid()))
	
	// Use OpenFile with secure permissions
	f, err := os.OpenFile(crashFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		log.Printf("Failed to create crash file: %v", err)
		return
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Printf("Failed to close crash file: %v", err)
		}
	}()
	
	// Write crash information
	if _, err := fmt.Fprintf(f, "NetMon Crash Report\n"); err != nil {
		log.Printf("Failed to write crash header: %v", err)
		return
	}
	if _, err := fmt.Fprintf(f, "Time: %s\n", time.Now().Format(time.RFC3339)); err != nil {
		log.Printf("Failed to write timestamp: %v", err)
		return
	}
	if _, err := fmt.Fprintf(f, "Stack:\n%s\n", debug.Stack()); err != nil {
		log.Printf("Failed to write stack trace: %v", err)
		return
	}
	
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