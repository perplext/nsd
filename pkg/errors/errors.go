package errors

import (
	"errors"
	"fmt"
)

// Error types for different components
var (
	// Network capture errors
	ErrNoInterface        = errors.New("no network interface specified")
	ErrInterfaceNotFound  = errors.New("network interface not found")
	ErrPermissionDenied   = errors.New("permission denied (requires root/admin)")
	ErrCaptureTimeout     = errors.New("packet capture timeout")
	ErrInvalidBPF        = errors.New("invalid BPF filter expression")
	
	// UI errors
	ErrUIInitFailed      = errors.New("failed to initialize UI")
	ErrInvalidTheme      = errors.New("invalid theme")
	ErrInvalidStyle      = errors.New("invalid border style")
	ErrVisualizationNotFound = errors.New("visualization not found")
	
	// Configuration errors
	ErrInvalidConfig     = errors.New("invalid configuration")
	ErrConfigNotFound    = errors.New("configuration file not found")
	ErrInvalidFormat     = errors.New("invalid file format")
	
	// Plugin errors
	ErrPluginLoadFailed  = errors.New("failed to load plugin")
	ErrPluginInitFailed  = errors.New("failed to initialize plugin")
	
	// Resource errors
	ErrOutOfMemory       = errors.New("out of memory")
	ErrRateLimitExceeded = errors.New("rate limit exceeded")
)

// NetworkError represents network-related errors
type NetworkError struct {
	Interface string
	Operation string
	Err       error
}

func (e *NetworkError) Error() string {
	return fmt.Sprintf("network error on %s during %s: %v", e.Interface, e.Operation, e.Err)
}

func (e *NetworkError) Unwrap() error {
	return e.Err
}

// UIError represents UI-related errors
type UIError struct {
	Component string
	Operation string
	Err       error
}

func (e *UIError) Error() string {
	return fmt.Sprintf("UI error in %s during %s: %v", e.Component, e.Operation, e.Err)
}

func (e *UIError) Unwrap() error {
	return e.Err
}

// ConfigError represents configuration errors
type ConfigError struct {
	Field string
	Value interface{}
	Err   error
}

func (e *ConfigError) Error() string {
	return fmt.Sprintf("config error for field %s with value %v: %v", e.Field, e.Value, e.Err)
}

func (e *ConfigError) Unwrap() error {
	return e.Err
}

// WrapNetworkError wraps an error with network context
func WrapNetworkError(iface, operation string, err error) error {
	if err == nil {
		return nil
	}
	return &NetworkError{
		Interface: iface,
		Operation: operation,
		Err:       err,
	}
}

// WrapUIError wraps an error with UI context
func WrapUIError(component, operation string, err error) error {
	if err == nil {
		return nil
	}
	return &UIError{
		Component: component,
		Operation: operation,
		Err:       err,
	}
}

// WrapConfigError wraps an error with config context
func WrapConfigError(field string, value interface{}, err error) error {
	if err == nil {
		return nil
	}
	return &ConfigError{
		Field: field,
		Value: value,
		Err:   err,
	}
}

// IsRetryable determines if an error is retryable
func IsRetryable(err error) bool {
	if err == nil {
		return false
	}
	
	// Check for specific retryable errors
	switch {
	case errors.Is(err, ErrCaptureTimeout):
		return true
	case errors.Is(err, ErrRateLimitExceeded):
		return true
	case errors.Is(err, ErrOutOfMemory):
		return false // Don't retry on OOM
	case errors.Is(err, ErrPermissionDenied):
		return false // Don't retry permission errors
	default:
		// Check if it's a temporary network error
		if netErr, ok := err.(*NetworkError); ok {
			return netErr.Operation == "capture" || netErr.Operation == "read"
		}
		return false
	}
}