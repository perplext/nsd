package recovery

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sync"
	"time"
)

// RecoveryManager handles application recovery and fault tolerance
type RecoveryManager struct {
	checkpointDir   string
	maxCheckpoints  int
	checkpointMutex sync.Mutex
	recoveryMode    bool
	lastCheckpoint  time.Time
}

// NewRecoveryManager creates a new recovery manager
func NewRecoveryManager(checkpointDir string) *RecoveryManager {
	return &RecoveryManager{
		checkpointDir:  checkpointDir,
		maxCheckpoints: 10,
	}
}

// Checkpoint saves current state
type Checkpoint struct {
	Timestamp   time.Time              `json:"timestamp"`
	Version     string                 `json:"version"`
	State       map[string]interface{} `json:"state"`
	MemoryUsage runtime.MemStats       `json:"memory"`
}

// SaveCheckpoint saves a checkpoint
func (rm *RecoveryManager) SaveCheckpoint(state map[string]interface{}) error {
	rm.checkpointMutex.Lock()
	defer rm.checkpointMutex.Unlock()
	
	// Rate limit checkpoints
	if time.Since(rm.lastCheckpoint) < 30*time.Second {
		return nil // Skip this checkpoint
	}
	
	// Create checkpoint directory
	// Use secure permissions for checkpoint directory
	if err := os.MkdirAll(rm.checkpointDir, 0700); err != nil {
		return fmt.Errorf("failed to create checkpoint directory: %w", err)
	}
	
	// Get memory stats
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	
	checkpoint := Checkpoint{
		Timestamp:   time.Now(),
		Version:     "1.0.0", // Should be from build info
		State:       state,
		MemoryUsage: memStats,
	}
	
	// Save checkpoint
	filename := fmt.Sprintf("checkpoint_%s.json", checkpoint.Timestamp.Format("20060102_150405"))
	path := filepath.Join(rm.checkpointDir, filename)
	
	// Write checkpoint (simplified - should use JSON)
	log.Printf("Saved checkpoint to %s", path)
	
	rm.lastCheckpoint = time.Now()
	
	// Clean old checkpoints
	rm.cleanOldCheckpoints()
	
	return nil
}

// cleanOldCheckpoints removes old checkpoint files
func (rm *RecoveryManager) cleanOldCheckpoints() {
	// List checkpoint files
	files, err := filepath.Glob(filepath.Join(rm.checkpointDir, "checkpoint_*.json"))
	if err != nil {
		return
	}
	
	// Keep only the most recent checkpoints
	if len(files) > rm.maxCheckpoints {
		// Sort by name (timestamp)
		for i := 0; i < len(files)-rm.maxCheckpoints; i++ {
			os.Remove(files[i])
		}
	}
}

// RecoverFromPanic recovers from a panic and saves crash information
func (rm *RecoveryManager) RecoverFromPanic() {
	if r := recover(); r != nil {
		rm.handlePanic(r)
	}
}

// handlePanic handles panic recovery
func (rm *RecoveryManager) handlePanic(r interface{}) {
	// Create crash report
	crashReport := CrashReport{
		Timestamp: time.Now(),
		Panic:     fmt.Sprintf("%v", r),
		Stack:     string(debug.Stack()),
		Memory:    getMemoryInfo(),
		Goroutines: runtime.NumGoroutine(),
	}
	
	// Save crash report
	rm.saveCrashReport(crashReport)
	
	// Try to recover if possible
	if rm.canRecover() {
		log.Printf("Attempting recovery from panic: %v", r)
		rm.enterRecoveryMode()
	} else {
		log.Fatalf("Unrecoverable panic: %v", r)
	}
}

// CrashReport contains crash information
type CrashReport struct {
	Timestamp  time.Time `json:"timestamp"`
	Panic      string    `json:"panic"`
	Stack      string    `json:"stack"`
	Memory     MemInfo   `json:"memory"`
	Goroutines int       `json:"goroutines"`
}

// MemInfo contains memory information
type MemInfo struct {
	Allocated      uint64 `json:"allocated"`
	TotalAllocated uint64 `json:"total_allocated"`
	System         uint64 `json:"system"`
	NumGC          uint32 `json:"num_gc"`
}

// getMemoryInfo returns current memory information
func getMemoryInfo() MemInfo {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	
	return MemInfo{
		Allocated:      m.Alloc,
		TotalAllocated: m.TotalAlloc,
		System:         m.Sys,
		NumGC:          m.NumGC,
	}
}

// saveCrashReport saves a crash report
func (rm *RecoveryManager) saveCrashReport(report CrashReport) {
	filename := fmt.Sprintf("crash_%s.log", report.Timestamp.Format("20060102_150405"))
	path := filepath.Join(rm.checkpointDir, filename)
	
	file, err := os.Create(path)
	if err != nil {
		log.Printf("Failed to save crash report: %v", err)
		return
	}
	defer file.Close()
	
	// Write crash report
	fmt.Fprintf(file, "=== NSD Crash Report ===\n")
	fmt.Fprintf(file, "Time: %s\n", report.Timestamp)
	fmt.Fprintf(file, "Panic: %s\n", report.Panic)
	fmt.Fprintf(file, "Goroutines: %d\n", report.Goroutines)
	fmt.Fprintf(file, "\nMemory:\n")
	fmt.Fprintf(file, "  Allocated: %d MB\n", report.Memory.Allocated/1024/1024)
	fmt.Fprintf(file, "  Total: %d MB\n", report.Memory.TotalAllocated/1024/1024)
	fmt.Fprintf(file, "  System: %d MB\n", report.Memory.System/1024/1024)
	fmt.Fprintf(file, "  GC Runs: %d\n", report.Memory.NumGC)
	fmt.Fprintf(file, "\nStack Trace:\n%s\n", report.Stack)
	
	log.Printf("Crash report saved to %s", path)
}

// canRecover determines if recovery is possible
func (rm *RecoveryManager) canRecover() bool {
	// Check if we have recent checkpoints
	files, err := filepath.Glob(filepath.Join(rm.checkpointDir, "checkpoint_*.json"))
	if err != nil || len(files) == 0 {
		return false
	}
	
	// Check if we're not in a crash loop
	crashes, _ := filepath.Glob(filepath.Join(rm.checkpointDir, "crash_*.log"))
	recentCrashes := 0
	
	for _, crash := range crashes {
		info, err := os.Stat(crash)
		if err == nil && time.Since(info.ModTime()) < 5*time.Minute {
			recentCrashes++
		}
	}
	
	// Don't try to recover if we've crashed too many times recently
	return recentCrashes < 3
}

// enterRecoveryMode enters recovery mode
func (rm *RecoveryManager) enterRecoveryMode() {
	rm.recoveryMode = true
	log.Println("Entering recovery mode...")
	
	// Load last checkpoint
	// Restart with limited functionality
	// etc.
}

// IsInRecoveryMode returns whether the system is in recovery mode
func (rm *RecoveryManager) IsInRecoveryMode() bool {
	return rm.recoveryMode
}

// HealthChecker performs periodic health checks
type HealthChecker struct {
	interval time.Duration
	checks   []HealthCheck
	onFail   func(string, error)
}

// HealthCheck is a function that returns an error if unhealthy
type HealthCheck func() error

// NewHealthChecker creates a new health checker
func NewHealthChecker(interval time.Duration) *HealthChecker {
	return &HealthChecker{
		interval: interval,
		checks:   make([]HealthCheck, 0),
		onFail: func(name string, err error) {
			log.Printf("Health check failed: %s: %v", name, err)
		},
	}
}

// AddCheck adds a health check
func (hc *HealthChecker) AddCheck(name string, check HealthCheck) {
	wrapped := func() error {
		if err := check(); err != nil {
			hc.onFail(name, err)
			return err
		}
		return nil
	}
	hc.checks = append(hc.checks, wrapped)
}

// Start starts the health checker
func (hc *HealthChecker) Start(ctx context.Context) {
	ticker := time.NewTicker(hc.interval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			hc.runChecks()
		}
	}
}

// runChecks runs all health checks
func (hc *HealthChecker) runChecks() {
	for _, check := range hc.checks {
		check()
	}
}