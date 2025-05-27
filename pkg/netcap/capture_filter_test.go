package netcap

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestFilterExpressionBasic tests basic filter expression functionality
func TestFilterExpressionBasic(t *testing.T) {
	nm := NewNetworkMonitor()
	
	// Initially no filter
	assert.Equal(t, "", nm.GetFilterExpression())
	
	// Set a filter (without actual capture)
	nm.mutex.Lock()
	nm.filterExpression = "tcp port 80"
	nm.mutex.Unlock()
	
	assert.Equal(t, "tcp port 80", nm.GetFilterExpression())
	
	// Change filter
	nm.mutex.Lock()
	nm.filterExpression = "udp port 53"
	nm.mutex.Unlock()
	
	assert.Equal(t, "udp port 53", nm.GetFilterExpression())
}

// TestSetBpfFilterErrors tests error cases for SetBpfFilter
func TestSetBpfFilterErrors(t *testing.T) {
	nm := NewNetworkMonitor()
	
	// Test with no active capture
	err := nm.SetBpfFilter("eth0", "tcp port 80")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not capturing")
	
	// Test with nil handle is not necessary as we should never have nil handles in ActiveHandles
	// The implementation should prevent this from happening
}

// TestLocalAddressDetection tests local address identification
func TestLocalAddressDetection(t *testing.T) {
	nm := NewNetworkMonitor()
	
	// Set up test local addresses
	nm.mutex.Lock()
	nm.localAddresses = map[string]bool{
		"192.168.1.100": true,
		"10.0.0.1":      true,
		"::1":           true,
		"127.0.0.1":     true,
		"fe80::1":       true,
	}
	nm.mutex.Unlock()
	
	// Test IPv4 addresses
	assert.True(t, nm.IsLocalAddress("192.168.1.100"))
	assert.True(t, nm.IsLocalAddress("10.0.0.1"))
	assert.True(t, nm.IsLocalAddress("127.0.0.1"))
	assert.False(t, nm.IsLocalAddress("8.8.8.8"))
	assert.False(t, nm.IsLocalAddress("1.1.1.1"))
	
	// Test IPv6 addresses
	assert.True(t, nm.IsLocalAddress("::1"))
	assert.True(t, nm.IsLocalAddress("fe80::1"))
	assert.False(t, nm.IsLocalAddress("2001:4860:4860::8888"))
	
	// Test empty/invalid addresses
	assert.False(t, nm.IsLocalAddress(""))
	assert.False(t, nm.IsLocalAddress("not-an-ip"))
}

// TestConcurrentLocalAddressUpdate tests concurrent access to local addresses
func TestConcurrentLocalAddressUpdate(t *testing.T) {
	nm := NewNetworkMonitor()
	
	// Initialize
	nm.mutex.Lock()
	nm.localAddresses = map[string]bool{
		"192.168.1.1": true,
	}
	nm.mutex.Unlock()
	
	done := make(chan bool)
	
	// Reader goroutine
	go func() {
		for i := 0; i < 1000; i++ {
			_ = nm.IsLocalAddress("192.168.1.1")
			_ = nm.IsLocalAddress("192.168.1.2")
		}
		done <- true
	}()
	
	// Writer goroutine
	go func() {
		for i := 0; i < 1000; i++ {
			nm.updateLocalAddresses()
		}
		done <- true
	}()
	
	// Wait for both
	<-done
	<-done
	
	// Should complete without race conditions
	assert.True(t, true)
}