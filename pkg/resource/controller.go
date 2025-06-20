package resource

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"
	
	"github.com/shirou/gopsutil/v3/process"
)

// Controller manages resource usage and enforces limits
type Controller struct {
	// Limits
	maxMemoryMB      int64
	maxCPUPercent    float64
	maxGoroutines    int
	maxPacketBuffer  int
	
	// Current usage tracking
	currentMemoryMB  int64
	currentCPU       float64
	currentGoroutines int32
	packetBufferSize int32
	
	// Control mechanisms
	gcTriggerMB     int64
	throttleActive  int32
	emergencyMode   int32
	
	// Monitoring
	process         *process.Process
	lastCheck       time.Time
	checkInterval   time.Duration
	
	// Callbacks
	onThrottle      func(reason string)
	onEmergency     func(reason string)
	onRecover       func()
	
	mu              sync.RWMutex
	ctx             context.Context
	cancel          context.CancelFunc
}

// Config holds resource controller configuration
type Config struct {
	MaxMemoryMB      int64   // Maximum memory usage in MB
	MaxCPUPercent    float64 // Maximum CPU usage percentage (0-100)
	MaxGoroutines    int     // Maximum number of goroutines
	MaxPacketBuffer  int     // Maximum packet buffer size
	GCTriggerPercent float64 // Trigger GC at this % of max memory
	CheckInterval    time.Duration
}

// DefaultConfig returns default resource limits
func DefaultConfig() *Config {
	return &Config{
		MaxMemoryMB:      1024,  // 1 GB
		MaxCPUPercent:    80.0,  // 80% CPU
		MaxGoroutines:    10000, // 10k goroutines
		MaxPacketBuffer:  100000, // 100k packets
		GCTriggerPercent: 0.8,   // GC at 80% memory
		CheckInterval:    time.Second,
	}
}

// NewController creates a new resource controller
func NewController(cfg *Config) (*Controller, error) {
	pid := int32(runtime.GOMAXPROCS(0))
	proc, err := process.NewProcess(pid)
	if err != nil {
		// Try current process
		proc, err = process.NewProcess(int32(os.Getpid()))
		if err != nil {
			return nil, fmt.Errorf("failed to get process info: %w", err)
		}
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	rc := &Controller{
		maxMemoryMB:     cfg.MaxMemoryMB,
		maxCPUPercent:   cfg.MaxCPUPercent,
		maxGoroutines:   cfg.MaxGoroutines,
		maxPacketBuffer: cfg.MaxPacketBuffer,
		gcTriggerMB:     int64(float64(cfg.MaxMemoryMB) * cfg.GCTriggerPercent),
		process:         proc,
		checkInterval:   cfg.CheckInterval,
		ctx:             ctx,
		cancel:          cancel,
	}
	
	// Set default callbacks
	rc.onThrottle = func(reason string) {
		fmt.Printf("Resource throttling activated: %s\n", reason)
	}
	rc.onEmergency = func(reason string) {
		fmt.Printf("Emergency mode activated: %s\n", reason)
	}
	rc.onRecover = func() {
		fmt.Println("Resource usage recovered to normal levels")
	}
	
	return rc, nil
}

// Start begins resource monitoring
func (rc *Controller) Start() {
	go rc.monitorLoop()
}

// Stop stops resource monitoring
func (rc *Controller) Stop() {
	rc.cancel()
}

// monitorLoop continuously monitors resources
func (rc *Controller) monitorLoop() {
	ticker := time.NewTicker(rc.checkInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-rc.ctx.Done():
			return
		case <-ticker.C:
			rc.checkResources()
		}
	}
}

// checkResources checks current resource usage
func (rc *Controller) checkResources() {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	
	// Update current usage
	rc.updateMemoryUsage()
	rc.updateCPUUsage()
	rc.updateGoroutineCount()
	
	// Check limits
	violations := rc.checkViolations()
	
	if len(violations) > 0 {
		rc.handleViolations(violations)
	} else if rc.IsThrottled() || rc.IsInEmergencyMode() {
		// Check if we can recover
		if rc.canRecover() {
			rc.recover()
		}
	}
	
	rc.lastCheck = time.Now()
}

// updateMemoryUsage updates current memory usage
func (rc *Controller) updateMemoryUsage() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	rc.currentMemoryMB = int64(m.Alloc / 1024 / 1024)
	
	// Trigger GC if needed
	if rc.currentMemoryMB > rc.gcTriggerMB {
		runtime.GC()
		debug.FreeOSMemory()
	}
}

// updateCPUUsage updates current CPU usage
func (rc *Controller) updateCPUUsage() {
	if rc.process != nil {
		percent, err := rc.process.CPUPercent()
		if err == nil {
			rc.currentCPU = percent
		}
	}
}

// updateGoroutineCount updates current goroutine count
func (rc *Controller) updateGoroutineCount() {
	atomic.StoreInt32(&rc.currentGoroutines, int32(runtime.NumGoroutine()))
}

// Violation represents a resource limit violation
type Violation struct {
	Type    string
	Current interface{}
	Limit   interface{}
	Severity int // 1=warning, 2=throttle, 3=emergency
}

// checkViolations checks for resource limit violations
func (rc *Controller) checkViolations() []Violation {
	var violations []Violation
	
	// Check memory
	memPercent := float64(rc.currentMemoryMB) / float64(rc.maxMemoryMB) * 100
	if memPercent > 90 {
		violations = append(violations, Violation{
			Type:     "memory",
			Current:  rc.currentMemoryMB,
			Limit:    rc.maxMemoryMB,
			Severity: 3, // Emergency
		})
	} else if memPercent > 80 {
		violations = append(violations, Violation{
			Type:     "memory",
			Current:  rc.currentMemoryMB,
			Limit:    rc.maxMemoryMB,
			Severity: 2, // Throttle
		})
	}
	
	// Check CPU
	if rc.currentCPU > rc.maxCPUPercent*1.1 {
		violations = append(violations, Violation{
			Type:     "cpu",
			Current:  rc.currentCPU,
			Limit:    rc.maxCPUPercent,
			Severity: 3, // Emergency
		})
	} else if rc.currentCPU > rc.maxCPUPercent {
		violations = append(violations, Violation{
			Type:     "cpu",
			Current:  rc.currentCPU,
			Limit:    rc.maxCPUPercent,
			Severity: 2, // Throttle
		})
	}
	
	// Check goroutines
	if int(rc.currentGoroutines) > rc.maxGoroutines {
		violations = append(violations, Violation{
			Type:     "goroutines",
			Current:  rc.currentGoroutines,
			Limit:    rc.maxGoroutines,
			Severity: 2, // Throttle
		})
	}
	
	// Check packet buffer
	bufferSize := atomic.LoadInt32(&rc.packetBufferSize)
	if int(bufferSize) > rc.maxPacketBuffer {
		violations = append(violations, Violation{
			Type:     "packet_buffer",
			Current:  bufferSize,
			Limit:    rc.maxPacketBuffer,
			Severity: 2, // Throttle
		})
	}
	
	return violations
}

// handleViolations handles resource violations
func (rc *Controller) handleViolations(violations []Violation) {
	maxSeverity := 0
	reasons := []string{}
	
	for _, v := range violations {
		if v.Severity > maxSeverity {
			maxSeverity = v.Severity
		}
		reasons = append(reasons, fmt.Sprintf("%s: %v/%v", v.Type, v.Current, v.Limit))
	}
	
	reason := fmt.Sprintf("Resource limits exceeded: %v", reasons)
	
	switch maxSeverity {
	case 3: // Emergency
		if !rc.IsInEmergencyMode() {
			atomic.StoreInt32(&rc.emergencyMode, 1)
			rc.onEmergency(reason)
		}
	case 2: // Throttle
		if !rc.IsThrottled() {
			atomic.StoreInt32(&rc.throttleActive, 1)
			rc.onThrottle(reason)
		}
	}
}

// canRecover checks if resource usage has recovered
func (rc *Controller) canRecover() bool {
	memPercent := float64(rc.currentMemoryMB) / float64(rc.maxMemoryMB) * 100
	return memPercent < 70 && 
		rc.currentCPU < rc.maxCPUPercent*0.8 &&
		int(rc.currentGoroutines) < rc.maxGoroutines*8/10
}

// recover recovers from throttled/emergency mode
func (rc *Controller) recover() {
	wasThrottled := rc.IsThrottled()
	wasEmergency := rc.IsInEmergencyMode()
	
	atomic.StoreInt32(&rc.throttleActive, 0)
	atomic.StoreInt32(&rc.emergencyMode, 0)
	
	if wasThrottled || wasEmergency {
		rc.onRecover()
	}
}

// IsThrottled returns whether throttling is active
func (rc *Controller) IsThrottled() bool {
	return atomic.LoadInt32(&rc.throttleActive) > 0
}

// IsInEmergencyMode returns whether emergency mode is active
func (rc *Controller) IsInEmergencyMode() bool {
	return atomic.LoadInt32(&rc.emergencyMode) > 0
}

// GetUsage returns current resource usage
func (rc *Controller) GetUsage() Usage {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	
	return Usage{
		MemoryMB:       rc.currentMemoryMB,
		MemoryPercent:  float64(rc.currentMemoryMB) / float64(rc.maxMemoryMB) * 100,
		CPUPercent:     rc.currentCPU,
		Goroutines:     int(rc.currentGoroutines),
		PacketBuffer:   int(atomic.LoadInt32(&rc.packetBufferSize)),
		Throttled:      rc.IsThrottled(),
		EmergencyMode:  rc.IsInEmergencyMode(),
	}
}

// Usage represents current resource usage
type Usage struct {
	MemoryMB       int64
	MemoryPercent  float64
	CPUPercent     float64
	Goroutines     int
	PacketBuffer   int
	Throttled      bool
	EmergencyMode  bool
}

// SetPacketBufferSize updates the packet buffer size
func (rc *Controller) SetPacketBufferSize(size int) {
	atomic.StoreInt32(&rc.packetBufferSize, int32(size))
}

// SetCallbacks sets callback functions
func (rc *Controller) SetCallbacks(onThrottle, onEmergency, onRecover func(string)) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	
	if onThrottle != nil {
		rc.onThrottle = onThrottle
	}
	if onEmergency != nil {
		rc.onEmergency = onEmergency
	}
	if onRecover != nil {
		rc.onRecover = func() { onRecover("") }
	}
}

// MemoryPool provides pooled memory allocation
type MemoryPool struct {
	pools map[int]*sync.Pool
	mu    sync.RWMutex
}

// NewMemoryPool creates a new memory pool
func NewMemoryPool() *MemoryPool {
	mp := &MemoryPool{
		pools: make(map[int]*sync.Pool),
	}
	
	// Pre-create pools for common sizes
	sizes := []int{64, 256, 1024, 4096, 16384, 65536}
	for _, size := range sizes {
		s := size // Capture loop variable
		mp.pools[size] = &sync.Pool{
			New: func() interface{} {
				return make([]byte, s)
			},
		}
	}
	
	return mp
}

// Get retrieves a buffer from the pool
func (mp *MemoryPool) Get(size int) []byte {
	mp.mu.RLock()
	pool, exists := mp.pools[size]
	mp.mu.RUnlock()
	
	if exists {
		return pool.Get().([]byte)
	}
	
	// Find next larger size
	mp.mu.RLock()
	defer mp.mu.RUnlock()
	
	for poolSize, pool := range mp.pools {
		if poolSize >= size {
			buf := pool.Get().([]byte)
			return buf[:size]
		}
	}
	
	// No suitable pool, allocate new
	return make([]byte, size)
}

// Put returns a buffer to the pool
func (mp *MemoryPool) Put(buf []byte) {
	size := cap(buf)
	
	mp.mu.RLock()
	pool, exists := mp.pools[size]
	mp.mu.RUnlock()
	
	if exists {
		// Clear buffer before returning to pool
		for i := range buf {
			buf[i] = 0
		}
		pool.Put(buf)
	}
}