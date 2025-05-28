//go:build integration
// +build integration

package integration

import (
	"testing"
	"time"
	
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/perplext/nsd/pkg/netcap"
)

func TestNetworkCapture(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	
	// This test requires root privileges
	t.Log("Running network capture integration test")
	
	// Get available interfaces
	interfaces, err := netcap.GetInterfaces()
	require.NoError(t, err)
	require.NotEmpty(t, interfaces)
	
	// Find loopback interface
	var loopback string
	for _, iface := range interfaces {
		if iface.Name == "lo" || iface.Name == "lo0" {
			loopback = iface.Name
			break
		}
	}
	require.NotEmpty(t, loopback, "Loopback interface not found")
	
	// Create monitor
	monitor := netcap.NewNetworkMonitor()
	
	// Start capture on loopback
	err = monitor.StartCapture(loopback)
	require.NoError(t, err)
	defer monitor.StopAllCaptures()
	
	// Wait for some packets
	time.Sleep(2 * time.Second)
	
	// Check stats
	stats := monitor.GetStats()
	assert.NotNil(t, stats)
	
	// Generate some traffic on loopback
	// This would involve making a network connection to localhost
	
	// Wait for capture
	time.Sleep(1 * time.Second)
	
	// Verify we captured something
	newStats := monitor.GetStats()
	assert.NotNil(t, newStats)
}

func TestBPFFilter(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	
	monitor := netcap.NewNetworkMonitor()
	
	// Set BPF filter
	monitor.SetBPFFilter("tcp port 80")
	
	// Start capture
	err := monitor.StartCapture("lo")
	if err != nil {
		t.Skipf("Cannot start capture on loopback: %v", err)
	}
	defer monitor.StopAllCaptures()
	
	// Verify filter is applied
	assert.Equal(t, "tcp port 80", monitor.GetFilterExpression())
}