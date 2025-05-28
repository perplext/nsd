package netcap

import (
	"fmt"
	"log"
	"time"
	
	"github.com/google/gopacket/pcap"
	"github.com/perplext/nsd/pkg/errors"
)

// ErrorHandler handles errors with configurable behavior
type ErrorHandler struct {
	MaxRetries    int
	RetryDelay    time.Duration
	OnError       func(error)
	OnFatalError  func(error)
	Logger        *log.Logger
}

// NewErrorHandler creates a new error handler with defaults
func NewErrorHandler() *ErrorHandler {
	return &ErrorHandler{
		MaxRetries:   3,
		RetryDelay:   time.Second,
		OnError:      func(err error) { log.Printf("Error: %v", err) },
		OnFatalError: func(err error) { log.Fatalf("Fatal error: %v", err) },
		Logger:       log.Default(),
	}
}

// Handle processes an error with retry logic
func (eh *ErrorHandler) Handle(operation func() error) error {
	var lastErr error
	
	for attempt := 0; attempt <= eh.MaxRetries; attempt++ {
		if attempt > 0 {
			eh.Logger.Printf("Retrying operation (attempt %d/%d)", attempt, eh.MaxRetries)
			time.Sleep(eh.RetryDelay)
		}
		
		err := operation()
		if err == nil {
			return nil
		}
		
		lastErr = err
		
		// Check if error is retryable
		if !errors.IsRetryable(err) {
			eh.OnError(err)
			return err
		}
		
		eh.Logger.Printf("Retryable error occurred: %v", err)
	}
	
	// Max retries exceeded
	eh.OnError(fmt.Errorf("max retries exceeded: %w", lastErr))
	return lastErr
}

// ValidateInterface checks if an interface exists and is valid
func ValidateInterface(name string) error {
	if name == "" {
		return errors.ErrNoInterface
	}
	
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return errors.WrapNetworkError(name, "list devices", err)
	}
	
	for _, device := range devices {
		if device.Name == name {
			// Check if interface is up
			handle, err := pcap.OpenLive(name, 1, false, pcap.BlockForever)
			if err != nil {
				return errors.WrapNetworkError(name, "validate", err)
			}
			handle.Close()
			return nil
		}
	}
	
	return errors.ErrInterfaceNotFound
}

// RecoverFromPanic recovers from panics in goroutines
func RecoverFromPanic(component string, onRecover func(interface{})) {
	if r := recover(); r != nil {
		log.Printf("Panic recovered in %s: %v", component, r)
		if onRecover != nil {
			onRecover(r)
		}
	}
}

// SafeClose safely closes a pcap handle
func SafeClose(handle *pcap.Handle, name string) {
	if handle != nil {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("Panic while closing handle for %s: %v", name, r)
			}
		}()
		handle.Close()
	}
}

// ValidateBPFFilter validates a BPF filter expression
func ValidateBPFFilter(filter string) error {
	if filter == "" {
		return nil // Empty filter is valid
	}
	
	// Create a dummy handle to test the filter
	handle, err := pcap.OpenOffline("dummy")
	if err != nil {
		// Try with a live interface instead
		devices, err := pcap.FindAllDevs()
		if err != nil || len(devices) == 0 {
			// Can't validate without a handle, assume it's valid
			return nil
		}
		
		handle, err = pcap.OpenLive(devices[0].Name, 1, false, pcap.BlockForever)
		if err != nil {
			return nil // Can't validate, assume valid
		}
		defer handle.Close()
	} else {
		defer handle.Close()
	}
	
	err = handle.SetBPFFilter(filter)
	if err != nil {
		return fmt.Errorf("%w: %s", errors.ErrInvalidBPF, err)
	}
	
	return nil
}