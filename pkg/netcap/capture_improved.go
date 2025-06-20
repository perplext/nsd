package netcap

import (
	"context"
	"fmt"
	"sync"
	"time"
	
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	neterrors "github.com/perplext/nsd/pkg/errors"
)

// ImprovedNetworkMonitor is an enhanced version with better error handling
type ImprovedNetworkMonitor struct {
	*NetworkMonitor
	errorHandler   *ErrorHandler
	ctx            context.Context
	cancel         context.CancelFunc
	wg             sync.WaitGroup
	maxPacketSize  int32
	captureTimeout time.Duration
}

// NewImprovedNetworkMonitor creates a new monitor with error handling
func NewImprovedNetworkMonitor() *ImprovedNetworkMonitor {
	ctx, cancel := context.WithCancel(context.Background())
	return &ImprovedNetworkMonitor{
		NetworkMonitor: NewNetworkMonitor(),
		errorHandler:   NewErrorHandler(),
		ctx:           ctx,
		cancel:        cancel,
		maxPacketSize: 65535, // Maximum packet size
		captureTimeout: 30 * time.Second,
	}
}

// StartCaptureWithValidation starts capture with proper validation and error handling
func (nm *ImprovedNetworkMonitor) StartCaptureWithValidation(interfaceName string) error {
	// Validate interface first
	if err := ValidateInterface(interfaceName); err != nil {
		return neterrors.WrapNetworkError(interfaceName, "validate", err)
	}
	
	// Validate BPF filter if set
	if nm.filterExpression != "" {
		if err := ValidateBPFFilter(nm.filterExpression); err != nil {
			return neterrors.WrapNetworkError(interfaceName, "validate filter", err)
		}
	}
	
	// Use error handler for capture start
	return nm.errorHandler.Handle(func() error {
		return nm.startCaptureInternal(interfaceName)
	})
}

// startCaptureInternal performs the actual capture start
func (nm *ImprovedNetworkMonitor) startCaptureInternal(interfaceName string) error {
	nm.mutex.Lock()
	// Check if already capturing on this interface
	if _, exists := nm.ActiveHandles[interfaceName]; exists {
		nm.mutex.Unlock()
		return fmt.Errorf("already capturing on interface %s", interfaceName)
	}
	
	// Initialize interface stats
	if _, exists := nm.Interfaces[interfaceName]; !exists {
		nm.Interfaces[interfaceName] = &InterfaceStats{
			Name:        interfaceName,
			Connections: make(map[ConnectionKey]*Connection),
		}
	}
	nm.mutex.Unlock()
	
	// Update local addresses with error handling
	if err := nm.updateLocalAddressesWithTimeout(5 * time.Second); err != nil {
		nm.errorHandler.Logger.Printf("Warning: failed to update local addresses: %v", err)
		// Continue anyway - not critical
	}
	
	// Open device with timeout
	handle, err := nm.openDeviceWithTimeout(interfaceName, nm.captureTimeout)
	if err != nil {
		return neterrors.WrapNetworkError(interfaceName, "open device", err)
	}
	
	// Set BPF filter if specified
	if nm.filterExpression != "" {
		if err := handle.SetBPFFilter(nm.filterExpression); err != nil {
			SafeClose(handle, interfaceName)
			return neterrors.WrapNetworkError(interfaceName, "set filter", err)
		}
	}
	
	// Store handle
	nm.mutex.Lock()
	nm.ActiveHandles[interfaceName] = handle
	nm.mutex.Unlock()
	
	// Start packet processing with panic recovery
	nm.wg.Add(1)
	go nm.processPacketsWithRecovery(interfaceName, handle)
	
	nm.errorHandler.Logger.Printf("Started capture on interface %s", interfaceName)
	return nil
}

// openDeviceWithTimeout opens device with a timeout
func (nm *ImprovedNetworkMonitor) openDeviceWithTimeout(interfaceName string, timeout time.Duration) (*pcap.Handle, error) {
	type result struct {
		handle *pcap.Handle
		err    error
	}
	
	resultChan := make(chan result, 1)
	
	go func() {
		handle, err := pcap.OpenLive(
			interfaceName,
			nm.maxPacketSize,
			true, // promiscuous mode
			pcap.BlockForever,
		)
		resultChan <- result{handle, err}
	}()
	
	select {
	case res := <-resultChan:
		return res.handle, res.err
	case <-time.After(timeout):
		return nil, fmt.Errorf("timeout opening device %s", interfaceName)
	}
}

// updateLocalAddressesWithTimeout updates local addresses with timeout
func (nm *ImprovedNetworkMonitor) updateLocalAddressesWithTimeout(timeout time.Duration) error {
	done := make(chan error, 1)
	
	go func() {
		nm.updateLocalAddresses()
		done <- nil
	}()
	
	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		return fmt.Errorf("timeout updating local addresses")
	}
}

// processPacketsWithRecovery processes packets with panic recovery
func (nm *ImprovedNetworkMonitor) processPacketsWithRecovery(interfaceName string, handle *pcap.Handle) {
	defer nm.wg.Done()
	defer RecoverFromPanic("packet processor", func(r interface{}) {
		nm.errorHandler.OnError(fmt.Errorf("panic in packet processor for %s: %v", interfaceName, r))
	})
	defer SafeClose(handle, interfaceName)
	
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.DecodeOptions = gopacket.DecodeOptions{
		Lazy:   true,
		NoCopy: true,
	}
	
	errorCount := 0
	const maxConsecutiveErrors = 10
	
	for {
		select {
		case <-nm.ctx.Done():
			nm.errorHandler.Logger.Printf("Stopping capture on %s: context cancelled", interfaceName)
			return
			
		case <-nm.StopCapture:
			nm.errorHandler.Logger.Printf("Stopping capture on %s: stop signal received", interfaceName)
			return
			
		case packet, ok := <-packetSource.Packets():
			if !ok {
				nm.errorHandler.OnError(fmt.Errorf("packet source closed for %s", interfaceName))
				return
			}
			
			// Process packet with error recovery
			if err := nm.processPacketSafe(interfaceName, packet); err != nil {
				errorCount++
				nm.errorHandler.Logger.Printf("Error processing packet on %s: %v", interfaceName, err)
				
				if errorCount >= maxConsecutiveErrors {
					nm.errorHandler.OnError(fmt.Errorf("too many consecutive errors on %s", interfaceName))
					return
				}
			} else {
				errorCount = 0 // Reset on success
			}
		}
	}
}

// processPacketSafe processes a packet with error recovery
func (nm *ImprovedNetworkMonitor) processPacketSafe(interfaceName string, packet gopacket.Packet) (err error) {
	// Recover from any panics during packet processing
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic processing packet: %v", r)
		}
	}()
	
	// Validate packet
	if packet == nil {
		return fmt.Errorf("nil packet")
	}
	
	if len(packet.Data()) == 0 {
		return fmt.Errorf("empty packet")
	}
	
	// Process packet
	nm.processPacket(interfaceName, packet)
	return nil
}

// StopAllCapturesGracefully stops all captures gracefully
func (nm *ImprovedNetworkMonitor) StopAllCapturesGracefully(timeout time.Duration) error {
	nm.errorHandler.Logger.Println("Stopping all captures gracefully...")
	
	// Cancel context
	nm.cancel()
	
	// Close stop channel
	nm.mutex.Lock()
	if nm.StopCapture != nil {
		close(nm.StopCapture)
	}
	nm.mutex.Unlock()
	
	// Wait for goroutines with timeout
	done := make(chan struct{})
	go func() {
		nm.wg.Wait()
		close(done)
	}()
	
	select {
	case <-done:
		nm.errorHandler.Logger.Println("All captures stopped successfully")
		return nil
	case <-time.After(timeout):
		nm.errorHandler.Logger.Println("Timeout waiting for captures to stop, forcing closure")
		nm.forceCloseAllHandles()
		return fmt.Errorf("timeout stopping captures")
	}
}

// forceCloseAllHandles forcefully closes all handles
func (nm *ImprovedNetworkMonitor) forceCloseAllHandles() {
	nm.mutex.Lock()
	defer nm.mutex.Unlock()
	
	for name, handle := range nm.ActiveHandles {
		SafeClose(handle, name)
		delete(nm.ActiveHandles, name)
	}
}

// GetCaptureStatistics returns capture statistics with error info
func (nm *ImprovedNetworkMonitor) GetCaptureStatistics(interfaceName string) (*pcap.Stats, error) {
	nm.mutex.RLock()
	handle, exists := nm.ActiveHandles[interfaceName]
	nm.mutex.RUnlock()
	
	if !exists {
		return nil, fmt.Errorf("no active capture on interface %s", interfaceName)
	}
	
	stats, err := handle.Stats()
	if err != nil {
		return nil, neterrors.WrapNetworkError(interfaceName, "get stats", err)
	}
	
	return stats, nil
}