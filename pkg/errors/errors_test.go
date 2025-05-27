package errors

import (
	"errors"
	"fmt"
	"testing"
	
	"github.com/stretchr/testify/assert"
)

func TestErrorTypes(t *testing.T) {
	// Test predefined errors
	assert.Error(t, ErrNoInterface)
	assert.Error(t, ErrInterfaceNotFound)
	assert.Error(t, ErrPermissionDenied)
	assert.Error(t, ErrCaptureTimeout)
	assert.Error(t, ErrInvalidBPF)
	
	// Test error messages
	assert.Contains(t, ErrNoInterface.Error(), "no network interface")
	assert.Contains(t, ErrPermissionDenied.Error(), "permission denied")
}

func TestNetworkError(t *testing.T) {
	baseErr := fmt.Errorf("connection failed")
	netErr := &NetworkError{
		Interface: "eth0",
		Operation: "capture",
		Err:       baseErr,
	}
	
	// Test error message
	assert.Contains(t, netErr.Error(), "eth0")
	assert.Contains(t, netErr.Error(), "capture")
	assert.Contains(t, netErr.Error(), "connection failed")
	
	// Test unwrap
	assert.Equal(t, baseErr, netErr.Unwrap())
	
	// Test with errors.Is
	assert.True(t, errors.Is(netErr, baseErr))
}

func TestUIError(t *testing.T) {
	baseErr := fmt.Errorf("render failed")
	uiErr := &UIError{
		Component: "graph",
		Operation: "draw",
		Err:       baseErr,
	}
	
	// Test error message
	assert.Contains(t, uiErr.Error(), "graph")
	assert.Contains(t, uiErr.Error(), "draw")
	assert.Contains(t, uiErr.Error(), "render failed")
	
	// Test unwrap
	assert.Equal(t, baseErr, uiErr.Unwrap())
}

func TestConfigError(t *testing.T) {
	baseErr := fmt.Errorf("invalid value")
	cfgErr := &ConfigError{
		Field: "theme",
		Value: "invalid-theme",
		Err:   baseErr,
	}
	
	// Test error message
	assert.Contains(t, cfgErr.Error(), "theme")
	assert.Contains(t, cfgErr.Error(), "invalid-theme")
	assert.Contains(t, cfgErr.Error(), "invalid value")
	
	// Test unwrap
	assert.Equal(t, baseErr, cfgErr.Unwrap())
}

func TestWrappers(t *testing.T) {
	// Test WrapNetworkError
	t.Run("WrapNetworkError", func(t *testing.T) {
		err := fmt.Errorf("base error")
		wrapped := WrapNetworkError("eth0", "test", err)
		
		assert.NotNil(t, wrapped)
		netErr, ok := wrapped.(*NetworkError)
		assert.True(t, ok)
		assert.Equal(t, "eth0", netErr.Interface)
		assert.Equal(t, "test", netErr.Operation)
		
		// Test nil error
		assert.Nil(t, WrapNetworkError("eth0", "test", nil))
	})
	
	// Test WrapUIError
	t.Run("WrapUIError", func(t *testing.T) {
		err := fmt.Errorf("ui error")
		wrapped := WrapUIError("button", "click", err)
		
		assert.NotNil(t, wrapped)
		uiErr, ok := wrapped.(*UIError)
		assert.True(t, ok)
		assert.Equal(t, "button", uiErr.Component)
		assert.Equal(t, "click", uiErr.Operation)
		
		// Test nil error
		assert.Nil(t, WrapUIError("button", "click", nil))
	})
	
	// Test WrapConfigError
	t.Run("WrapConfigError", func(t *testing.T) {
		err := fmt.Errorf("config error")
		wrapped := WrapConfigError("port", 8080, err)
		
		assert.NotNil(t, wrapped)
		cfgErr, ok := wrapped.(*ConfigError)
		assert.True(t, ok)
		assert.Equal(t, "port", cfgErr.Field)
		assert.Equal(t, 8080, cfgErr.Value)
		
		// Test nil error
		assert.Nil(t, WrapConfigError("port", 8080, nil))
	})
}

func TestIsRetryable(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "capture timeout",
			err:      ErrCaptureTimeout,
			expected: true,
		},
		{
			name:     "rate limit exceeded",
			err:      ErrRateLimitExceeded,
			expected: true,
		},
		{
			name:     "out of memory",
			err:      ErrOutOfMemory,
			expected: false,
		},
		{
			name:     "permission denied",
			err:      ErrPermissionDenied,
			expected: false,
		},
		{
			name: "network capture error",
			err: &NetworkError{
				Operation: "capture",
				Err:       fmt.Errorf("timeout"),
			},
			expected: true,
		},
		{
			name: "network read error",
			err: &NetworkError{
				Operation: "read",
				Err:       fmt.Errorf("timeout"),
			},
			expected: true,
		},
		{
			name: "network other error",
			err: &NetworkError{
				Operation: "configure",
				Err:       fmt.Errorf("failed"),
			},
			expected: false,
		},
		{
			name:     "generic error",
			err:      fmt.Errorf("generic error"),
			expected: false,
		},
		{
			name:     "wrapped retryable error",
			err:      fmt.Errorf("wrapped: %w", ErrCaptureTimeout),
			expected: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsRetryable(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestErrorChaining(t *testing.T) {
	// Test error chaining with Is
	baseErr := ErrPermissionDenied
	wrapped := WrapNetworkError("eth0", "open", baseErr)
	wrapped2 := fmt.Errorf("failed to start: %w", wrapped)
	
	assert.True(t, errors.Is(wrapped2, ErrPermissionDenied))
	assert.True(t, errors.Is(wrapped2, baseErr))
	
	// Test error type checking with As
	var netErr *NetworkError
	assert.True(t, errors.As(wrapped2, &netErr))
	assert.Equal(t, "eth0", netErr.Interface)
}