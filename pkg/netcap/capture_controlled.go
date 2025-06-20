package netcap

import (
	"fmt"
	"log"
	"sync"
	"time"
	
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/perplext/nsd/pkg/ratelimit"
	"github.com/perplext/nsd/pkg/resource"
)

// ControlledMonitor is a network monitor with rate limiting and resource controls
type ControlledMonitor struct {
	*ImprovedNetworkMonitor
	
	// Rate limiting
	rateLimiter *ratelimit.AdaptiveLimiter
	
	// Resource control
	resourceController *resource.Controller
	memoryPool         *resource.MemoryPool
	
	// Packet buffer management
	packetQueue      chan gopacket.Packet
	maxQueueSize     int
	dropWhenFull     bool
	
	// Statistics
	processedPackets uint64
	droppedPackets   uint64
	throttledPackets uint64
	
	// Control flags
	adaptiveMode     bool
	emergencyMode    bool
	
	statsMu sync.RWMutex
}

// ControlledConfig holds configuration for controlled monitor
type ControlledConfig struct {
	// Rate limiting
	RateLimitConfig *ratelimit.Config
	
	// Resource control
	ResourceConfig *resource.Config
	
	// Buffer management
	MaxQueueSize int
	DropWhenFull bool
	
	// Features
	AdaptiveMode bool
}

// DefaultControlledConfig returns default configuration
func DefaultControlledConfig() *ControlledConfig {
	return &ControlledConfig{
		RateLimitConfig: ratelimit.DefaultConfig(),
		ResourceConfig:  resource.DefaultConfig(),
		MaxQueueSize:    10000,
		DropWhenFull:    true,
		AdaptiveMode:    true,
	}
}

// NewControlledMonitor creates a new controlled network monitor
func NewControlledMonitor(cfg *ControlledConfig) (*ControlledMonitor, error) {
	// Create resource controller
	resController, err := resource.NewController(cfg.ResourceConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource controller: %w", err)
	}
	
	cm := &ControlledMonitor{
		ImprovedNetworkMonitor: NewImprovedNetworkMonitor(),
		resourceController:     resController,
		memoryPool:            resource.NewMemoryPool(),
		packetQueue:           make(chan gopacket.Packet, cfg.MaxQueueSize),
		maxQueueSize:          cfg.MaxQueueSize,
		dropWhenFull:          cfg.DropWhenFull,
		adaptiveMode:          cfg.AdaptiveMode,
	}
	
	// Create adaptive rate limiter
	cm.rateLimiter = ratelimit.NewAdaptiveLimiter(cfg.RateLimitConfig, cm)
	
	// Set resource callbacks
	resController.SetCallbacks(
		func(reason string) { cm.handleThrottle(reason) },
		func(reason string) { cm.handleEmergency(reason) },
		func(reason string) { cm.handleRecovery(reason) },
	)
	
	// Start resource monitoring
	resController.Start()
	
	// Start packet processor
	cm.wg.Add(1)
	go cm.processPacketQueue()
	
	return cm, nil
}

// StartCaptureControlled starts capture with rate limiting and resource control
func (cm *ControlledMonitor) StartCaptureControlled(interfaceName string) error {
	// Check resources before starting
	usage := cm.resourceController.GetUsage()
	if usage.EmergencyMode {
		return fmt.Errorf("cannot start capture: system in emergency mode")
	}
	
	// Start capture with validation
	if err := cm.StartCaptureWithValidation(interfaceName); err != nil {
		return err
	}
	
	return nil
}

// processPacketsControlled processes packets with rate limiting
func (cm *ControlledMonitor) processPacketsControlled(interfaceName string, handle *pcap.Handle) {
	defer cm.wg.Done()
	defer RecoverFromPanic("controlled packet processor", func(r interface{}) {
		cm.errorHandler.OnError(fmt.Errorf("panic in controlled processor: %v", r))
	})
	defer SafeClose(handle, interfaceName)
	
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.DecodeOptions = gopacket.DecodeOptions{
		Lazy:   true,
		NoCopy: true,
	}
	
	for {
		select {
		case <-cm.ctx.Done():
			return
			
		case <-cm.StopCapture:
			return
			
		case packet, ok := <-packetSource.Packets():
			if !ok {
				return
			}
			
			// Check if in emergency mode
			if cm.emergencyMode {
				cm.statsMu.Lock()
				cm.droppedPackets++
				cm.statsMu.Unlock()
				continue
			}
			
			// Apply rate limiting
			packetSize := len(packet.Data())
			
			// Check packet rate
			if !cm.rateLimiter.AllowPacket() {
				cm.statsMu.Lock()
				cm.throttledPackets++
				cm.statsMu.Unlock()
				continue
			}
			
			// Check byte rate
			if !cm.rateLimiter.AllowBytes(packetSize) {
				cm.statsMu.Lock()
				cm.throttledPackets++
				cm.statsMu.Unlock()
				continue
			}
			
			// Queue packet for processing
			select {
			case cm.packetQueue <- packet:
				// Update buffer size for resource controller
				cm.resourceController.SetPacketBufferSize(len(cm.packetQueue))
				
			default:
				// Queue full
				if cm.dropWhenFull {
					cm.statsMu.Lock()
					cm.droppedPackets++
					cm.statsMu.Unlock()
				} else {
					// Wait with timeout
					select {
					case cm.packetQueue <- packet:
					case <-time.After(10 * time.Millisecond):
						cm.statsMu.Lock()
						cm.droppedPackets++
						cm.statsMu.Unlock()
					}
				}
			}
			
			// Adaptive adjustment
			if cm.adaptiveMode {
				cm.rateLimiter.Adjust()
			}
		}
	}
}

// processPacketQueue processes queued packets
func (cm *ControlledMonitor) processPacketQueue() {
	defer cm.wg.Done()
	defer RecoverFromPanic("packet queue processor", nil)
	
	for {
		select {
		case <-cm.ctx.Done():
			return
			
		case packet := <-cm.packetQueue:
			// Get buffer from pool
			buf := cm.memoryPool.Get(len(packet.Data()))
			copy(buf, packet.Data())
			
			// Process packet
			cm.processPacketPooled(packet)
			
			// Return buffer to pool
			cm.memoryPool.Put(buf)
			
			// Update statistics
			cm.statsMu.Lock()
			cm.processedPackets++
			cm.statsMu.Unlock()
			
			// Update buffer size
			cm.resourceController.SetPacketBufferSize(len(cm.packetQueue))
		}
	}
}

// processPacketPooled processes a packet using pooled memory
func (cm *ControlledMonitor) processPacketPooled(packet gopacket.Packet) {
	// This is a placeholder - implement actual packet processing
	// using pooled memory to reduce allocations
}

// handleThrottle handles throttling activation
func (cm *ControlledMonitor) handleThrottle(reason string) {
	log.Printf("Throttling activated: %s", reason)
	
	// Let the adaptive limiter adjust itself based on current conditions
	if cm.rateLimiter != nil {
		cm.rateLimiter.Adjust()
	}
}

// handleEmergency handles emergency mode
func (cm *ControlledMonitor) handleEmergency(reason string) {
	log.Printf("Emergency mode activated: %s", reason)
	cm.emergencyMode = true
	
	// Drop all new packets
	// Clear packet queue
	for len(cm.packetQueue) > 0 {
		<-cm.packetQueue
	}
}

// handleRecovery handles recovery from throttling/emergency
func (cm *ControlledMonitor) handleRecovery(reason string) {
	log.Printf("Recovered from resource constraints")
	cm.emergencyMode = false
	
	// Let the adaptive limiter adjust itself based on improved conditions
	if cm.rateLimiter != nil {
		cm.rateLimiter.Adjust()
	}
}

// GetStatistics returns capture statistics
func (cm *ControlledMonitor) GetStatistics() ControlledStats {
	cm.statsMu.RLock()
	defer cm.statsMu.RUnlock()
	
	rlStats := cm.rateLimiter.GetStats()
	usage := cm.resourceController.GetUsage()
	
	return ControlledStats{
		ProcessedPackets:  cm.processedPackets,
		DroppedPackets:    cm.droppedPackets,
		ThrottledPackets:  cm.throttledPackets,
		QueueSize:         len(cm.packetQueue),
		RateLimitStats:    rlStats,
		ResourceUsage:     usage,
	}
}

// ControlledStats holds statistics for controlled capture
type ControlledStats struct {
	ProcessedPackets  uint64
	DroppedPackets    uint64
	ThrottledPackets  uint64
	QueueSize         int
	RateLimitStats    ratelimit.Stats
	ResourceUsage     resource.Usage
}

// Implement ResourceMonitor interface for adaptive rate limiting
func (cm *ControlledMonitor) GetCPUUsage() float64 {
	usage := cm.resourceController.GetUsage()
	return usage.CPUPercent
}

func (cm *ControlledMonitor) GetMemoryUsage() float64 {
	usage := cm.resourceController.GetUsage()
	return usage.MemoryPercent / 100.0
}

func (cm *ControlledMonitor) GetDroppedPackets() uint64 {
	cm.statsMu.RLock()
	defer cm.statsMu.RUnlock()
	return cm.droppedPackets
}

// StopGracefully stops the controlled monitor gracefully
func (cm *ControlledMonitor) StopGracefully(timeout time.Duration) error {
	// Stop resource controller
	cm.resourceController.Stop()
	
	// Stop captures
	return cm.StopAllCapturesGracefully(timeout)
}